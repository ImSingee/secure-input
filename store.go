package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
)

// RequestTTL is how long a request — and later its result — lives in memory.
// Results are deleted on first pull regardless.
const RequestTTL = 30 * time.Minute

const (
	StatusPending   = "pending"
	StatusSubmitted = "submitted"
	StatusDeclined  = "declined"
)

const (
	MaxVariables         = 20
	MaxReasonLength      = 2000
	MaxDescriptionLength = 1000
	MaxValueLength       = 64 * 1024
)

type VariableSpec struct {
	Key         string `json:"key"`
	Description string `json:"description"`
	// Private is the default "keep private" state shown to the user;
	// they make the final choice per variable.
	Private bool `json:"private"`
}

// UnmarshalJSON defaults Private to true when the field is absent, so an
// omitted classification can never silently expose a value.
func (v *VariableSpec) UnmarshalJSON(data []byte) error {
	type alias VariableSpec
	a := alias{Private: true}
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	*v = VariableSpec(a)
	return nil
}

type Entry struct {
	Key     string `json:"key"`
	Value   string `json:"value"`
	Private bool   `json:"private"`
}

type Request struct {
	ID        string         `json:"id"`
	Reason    string         `json:"reason"`
	Variables []VariableSpec `json:"-"`
	CreatedAt time.Time      `json:"-"`
	ExpiresAt time.Time      `json:"expiresAt"`
	Status    string         `json:"status"`
	Entries   []Entry        `json:"entries,omitempty"`
}

func newID() string {
	buf := make([]byte, 18)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

var envKeyRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)

var reservedEnvKeys = map[string]bool{
	"BASHOPTS": true, "BASH_ENV": true, "CDPATH": true, "COREPACK_HOME": true,
	"DENO_DIR": true, "DENO_INSTALL_ROOT": true, "ENV": true, "GIT_ASKPASS": true,
	"GLOBIGNORE": true, "HOME": true, "IFS": true, "LANG": true, "LC_ALL": true,
	"LC_CTYPE": true, "LOGNAME": true, "NODE_EXTRA_CA_CERTS": true,
	"NODE_OPTIONS": true, "NODE_PATH": true, "OLDPWD": true, "PATH": true,
	"PNPM_HOME": true, "PROMPT_COMMAND": true, "PS4": true, "PWD": true,
	"SHELL": true, "SHELLOPTS": true, "SSH_ASKPASS": true, "TEMP": true,
	"TERM": true, "TMP": true, "TMPDIR": true, "USER": true, "USERPROFILE": true,
	"ZDOTDIR": true,
}

var reservedEnvPrefixes = []string{"DYLD_", "GIT_CONFIG_", "LD_", "XDG_"}

func validateEnvKey(key string) error {
	if !envKeyRE.MatchString(key) {
		return fmt.Errorf("invalid environment key %q: use 1-64 letters, digits, or underscores and do not start with a digit", key)
	}
	upper := strings.ToUpper(key)
	if reservedEnvKeys[upper] {
		return fmt.Errorf("environment key %q is reserved by the command runtime", key)
	}
	for _, prefix := range reservedEnvPrefixes {
		if strings.HasPrefix(upper, prefix) {
			return fmt.Errorf("environment key %q is reserved by the command runtime", key)
		}
	}
	return nil
}

// Spec is the JSON body accepted by POST /api/requests and --spec.
type Spec struct {
	Reason    string         `json:"reason"`
	Variables []VariableSpec `json:"variables"`
}

func validateSpec(spec *Spec) error {
	if spec == nil {
		return fmt.Errorf("missing request spec")
	}
	if spec.Reason == "" || len(spec.Reason) > MaxReasonLength {
		return fmt.Errorf("reason must be 1-%d characters", MaxReasonLength)
	}
	if len(spec.Variables) == 0 || len(spec.Variables) > MaxVariables {
		return fmt.Errorf("variables must contain 1-%d items", MaxVariables)
	}
	seen := map[string]bool{}
	for i := range spec.Variables {
		v := &spec.Variables[i]
		if err := validateEnvKey(v.Key); err != nil {
			return err
		}
		if seen[v.Key] {
			return fmt.Errorf("duplicate environment key %q", v.Key)
		}
		seen[v.Key] = true
		if len(v.Description) > MaxDescriptionLength {
			return fmt.Errorf("description for %q must be at most %d characters", v.Key, MaxDescriptionLength)
		}
	}
	return nil
}

// submittedEntry is the wire shape for a user submission; Private is a
// pointer so an omitted field falls back to the requested default instead of
// accidentally sharing the value with the AI.
type submittedEntry struct {
	Key     string `json:"key"`
	Value   string `json:"value"`
	Private *bool  `json:"private"`
}

func validateEntries(variables []VariableSpec, entries []submittedEntry) ([]Entry, error) {
	allowed := map[string]VariableSpec{}
	for _, v := range variables {
		allowed[v.Key] = v
	}
	byKey := map[string]Entry{}
	for _, e := range entries {
		spec, ok := allowed[e.Key]
		if !ok {
			return nil, fmt.Errorf("entry key %q was not requested", e.Key)
		}
		if _, dup := byKey[e.Key]; dup {
			return nil, fmt.Errorf("duplicate entry for %q", e.Key)
		}
		if len(e.Value) > MaxValueLength {
			return nil, fmt.Errorf("value for %q exceeds %d bytes", e.Key, MaxValueLength)
		}
		private := spec.Private
		if e.Private != nil {
			private = *e.Private
		}
		byKey[e.Key] = Entry{Key: e.Key, Value: e.Value, Private: private}
	}
	// Variables the user did not submit are stored as empty values.
	out := make([]Entry, 0, len(variables))
	for _, v := range variables {
		if e, ok := byKey[v.Key]; ok {
			out = append(out, e)
		} else {
			out = append(out, Entry{Key: v.Key, Value: "", Private: v.Private})
		}
	}
	return out, nil
}

// Store keeps requests in memory. Get lazily drops expired records; the server
// also runs a periodic sweep so idle records are freed.
type Store struct {
	mu       sync.Mutex
	ttl      time.Duration
	requests map[string]*Request
}

func NewStore(ttl time.Duration) *Store {
	return &Store{ttl: ttl, requests: map[string]*Request{}}
}

func (s *Store) Create(spec Spec) *Request {
	now := time.Now()
	r := &Request{
		ID:        newID(),
		Reason:    spec.Reason,
		Variables: spec.Variables,
		CreatedAt: now,
		ExpiresAt: now.Add(s.ttl),
		Status:    StatusPending,
	}
	s.mu.Lock()
	s.requests[r.ID] = r
	s.mu.Unlock()
	return r
}

// Get returns the live request, or nil if missing/expired.
func (s *Store) Get(id string) *Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getLocked(id)
}

func (s *Store) getLocked(id string) *Request {
	r, ok := s.requests[id]
	if !ok {
		return nil
	}
	if !r.ExpiresAt.After(time.Now()) {
		delete(s.requests, id)
		return nil
	}
	return r
}

// Submit marks a pending request submitted and refreshes the TTL so the
// puller gets a fresh window to consume the result.
func (s *Store) Submit(id string, entries []Entry) *Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.getLocked(id)
	if r == nil || r.Status != StatusPending {
		return nil
	}
	r.Status = StatusSubmitted
	r.Entries = entries
	r.ExpiresAt = time.Now().Add(s.ttl)
	return r
}

func (s *Store) Decline(id string) *Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.getLocked(id)
	if r == nil || r.Status != StatusPending {
		return nil
	}
	r.Status = StatusDeclined
	r.ExpiresAt = time.Now().Add(s.ttl)
	return r
}

// Consume returns the request. Pending requests stay; terminal requests
// (submitted/declined) are deleted so a result is served exactly once.
func (s *Store) Consume(id string) *Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.getLocked(id)
	if r == nil {
		return nil
	}
	if r.Status != StatusPending {
		delete(s.requests, id)
	}
	return r
}

func (s *Store) Sweep() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for id, r := range s.requests {
		if !r.ExpiresAt.After(time.Now()) {
			delete(s.requests, id)
			removed++
		}
	}
	return removed
}

func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.requests)
}
