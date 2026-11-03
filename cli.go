package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// stringList collects repeated flag values, e.g. --var A --var B.
type stringList []string

func (l *stringList) String() string { return strings.Join(*l, ",") }
func (l *stringList) Set(v string) error {
	*l = append(*l, v)
	return nil
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	addr := fs.String("addr", ":8787", "listen address")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return serve(ctx, *addr, NewStore(RequestTTL))
}

// parseVarFlag parses "KEY" or "KEY:DESCRIPTION" (split on the first colon so
// descriptions may contain colons, e.g. URLs).
func parseVarFlag(raw string) (key, description string, err error) {
	key, description, _ = strings.Cut(raw, ":")
	if key == "" {
		return "", "", fmt.Errorf("empty key in --var %q", raw)
	}
	return key, description, nil
}

func buildSpec(reason string, varFlags, publicFlags stringList, specRaw string) (*Spec, error) {
	if specRaw != "" {
		data := []byte(specRaw)
		if strings.HasPrefix(specRaw, "@") {
			var err error
			data, err = os.ReadFile(specRaw[1:])
			if err != nil {
				return nil, fmt.Errorf("read spec file: %w", err)
			}
		}
		var spec Spec
		if err := json.Unmarshal(data, &spec); err != nil {
			return nil, fmt.Errorf("invalid --spec JSON: %w", err)
		}
		if err := validateSpec(&spec); err != nil {
			return nil, err
		}
		return &spec, nil
	}
	if reason == "" {
		return nil, fmt.Errorf("--reason is required (or use --spec)")
	}
	if len(varFlags) == 0 {
		return nil, fmt.Errorf("at least one --var is required (or use --spec)")
	}
	public := map[string]bool{}
	for _, key := range publicFlags {
		public[key] = true
	}
	variables := make([]VariableSpec, 0, len(varFlags))
	for _, raw := range varFlags {
		key, description, err := parseVarFlag(raw)
		if err != nil {
			return nil, err
		}
		variables = append(variables, VariableSpec{
			Key:         key,
			Description: description,
			Private:     !public[key],
		})
	}
	spec := &Spec{Reason: reason, Variables: variables}
	if err := validateSpec(spec); err != nil {
		return nil, err
	}
	return spec, nil
}

type createResponse struct {
	ID         string            `json:"id"`
	URL        string            `json:"url"`
	ExpiresAt  string            `json:"expiresAt"`
	Encryption *EncryptionConfig `json:"encryption,omitempty"`
}

// Plaintext JSON can expand sixfold when Go escapes <, >, &, or controls.
// Allow that expansion plus normalized/missing entries; encrypted envelopes
// are smaller. Keep an explicit bound even for an untrusted relay.
const maxResultBodyBytes = 6*maxBodyBytes + MaxVariables*256 + 1024

type resultResponse struct {
	Status    string            `json:"status"`
	Entries   []Entry           `json:"entries,omitempty"`
	Encrypted *EncryptedPayload `json:"encrypted,omitempty"`
}

func apiURL(server, path string) (string, error) {
	u, err := url.Parse(server)
	if err != nil {
		return "", fmt.Errorf("invalid --server URL: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("--server must be an absolute URL like http://localhost:8787")
	}
	return u.JoinPath(path).String(), nil
}

func createRequest(ctx context.Context, server string, spec *Spec) (*createResponse, error) {
	endpoint, err := apiURL(server, "/api/requests")
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(spec)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 20 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("create request: server returned %s: %s", res.Status, readErrorBody(res.Body))
	}
	var out createResponse
	if err := json.NewDecoder(io.LimitReader(res.Body, maxEncryptedBodyBytes+1)).Decode(&out); err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	if spec.Encryption != nil && (out.Encryption == nil || *out.Encryption != *spec.Encryption) {
		return nil, fmt.Errorf("server did not confirm the requested encryption; refusing to downgrade (upgrade the server or explicitly use --no-encryption)")
	}
	if out.ID == "" || strings.ContainsAny(out.ID, "/?#\\\x00") {
		return nil, fmt.Errorf("server returned an invalid request id")
	}
	if spec.Encryption != nil {
		link, err := url.Parse(out.URL)
		if err != nil || link.Host == "" || (link.Scheme != "https" && link.Scheme != "http") {
			return nil, fmt.Errorf("server returned an invalid form URL")
		}
		// The fragment is not sent in HTTP requests. Honest browser code checks
		// it against the server-supplied key to catch accidental substitution.
		link.Fragment = "e2ee=" + spec.Encryption.PublicKey
		link.RawFragment = url.Values{"e2ee": {spec.Encryption.PublicKey}}.Encode()
		out.URL = link.String()
	}
	return &out, nil
}

func readErrorBody(body io.Reader) string {
	data, _ := io.ReadAll(io.LimitReader(body, 4096))
	return strings.TrimSpace(string(data))
}

// pollOnce fetches the result once, waiting up to waitSecs on the server.
// Returns (result, gone, error): gone=true means the request expired or was
// already consumed.
func pollOnce(ctx context.Context, server, id string, waitSecs int) (*resultResponse, bool, error) {
	endpoint, err := apiURL(server, "/api/requests/"+id+"/result")
	if err != nil {
		return nil, false, err
	}
	if waitSecs > 0 {
		endpoint += fmt.Sprintf("?wait=%d", waitSecs)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, false, err
	}
	client := &http.Client{Timeout: time.Duration(waitSecs)*time.Second + 20*time.Second}
	res, err := client.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusGone || res.StatusCode == http.StatusNotFound {
		return nil, true, nil
	}
	if res.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("poll: server returned %s: %s", res.Status, readErrorBody(res.Body))
	}
	var out resultResponse
	if err := json.NewDecoder(io.LimitReader(res.Body, maxResultBodyBytes+1)).Decode(&out); err != nil {
		return nil, false, fmt.Errorf("poll: %w", err)
	}
	return &out, false, nil
}

// writeEnvFile writes entries to path atomically with mode 0600.
func writeEnvFile(path string, entries []Entry) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".secure-input-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.WriteString(SerializeDotenv(entries)); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// reportResult writes the .env file and prints the masked summary.
func reportResult(outPath string, result *resultResponse) error {
	abs, err := filepath.Abs(outPath)
	if err != nil {
		abs = outPath
	}
	if err := writeEnvFile(abs, result.Entries); err != nil {
		return fail(1, "write env file %s: %v", abs, err)
	}
	fmt.Printf("Saved %d environment value(s) to %s:\n", len(result.Entries), abs)
	for _, e := range result.Entries {
		if e.Private {
			fmt.Printf("  %s=********\n", e.Key)
		} else {
			fmt.Printf("  %s=%s\n", e.Key, e.Value)
		}
	}
	return nil
}

func cmdRequest(args []string) error {
	fs := flag.NewFlagSet("request", flag.ContinueOnError)
	server := fs.String("server", envOr("SECURE_INPUT_SERVER", "http://localhost:8787"), "server base URL")
	out := fs.String("out", "", "path to write the .env file to (required)")
	reason := fs.String("reason", "", "why these values are needed, shown to the user")
	var varFlags, publicFlags stringList
	fs.Var(&varFlags, "var", "variable to request: KEY or KEY:DESCRIPTION (repeatable)")
	fs.Var(&publicFlags, "public", "mark a variable as shareable with the AI (repeatable; default is private)")
	specRaw := fs.String("spec", "", "full request spec as JSON, or @file.json (overrides --reason/--var/--public)")
	noWait := fs.Bool("no-wait", false, "print the URL and request id, then exit without waiting")
	noEncryption := fs.Bool("no-encryption", false, "disable end-to-end encryption (server can read values)")
	keyFile := fs.String("key-file", "", "save private request state for a later pull (default with --no-wait: OUT.secure-input-key.json)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return fail(1, "--out is required")
	}
	spec, err := buildSpec(*reason, varFlags, publicFlags, *specRaw)
	if err != nil {
		return fail(1, "%v", err)
	}
	var privateKey *ecdh.PrivateKey
	// A JSON spec cannot turn off the CLI's default encryption or supply a key
	// for which this process does not possess the private half.
	spec.Encryption = nil
	if *noEncryption {
		if *keyFile != "" {
			return fail(1, "--key-file cannot be used with --no-encryption")
		}
		fmt.Fprintln(os.Stderr, "warning: end-to-end encryption is disabled; the server can read submitted values")
	} else {
		privateKey, err = ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return fail(1, "generate encryption key: %v", err)
		}
		spec.Encryption = &EncryptionConfig{Version: encryptionVersion, PublicKey: base64.StdEncoding.EncodeToString(privateKey.PublicKey().Bytes())}
		if *noWait && *keyFile == "" {
			*keyFile = *out + ".secure-input-key.json"
		}
		if *keyFile != "" {
			if samePath(*keyFile, *out) {
				return fail(1, "--key-file must differ from --out")
			}
			if _, err := os.Lstat(*keyFile); !os.IsNotExist(err) {
				return fail(1, "--key-file must be a new file")
			}
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	created, err := createRequest(ctx, *server, spec)
	if err != nil {
		return fail(1, "%v", err)
	}
	if *keyFile != "" {
		if err := saveRequestKey(*keyFile, *server, created.ID, spec, privateKey); err != nil {
			return fail(1, "%v", err)
		}
		fmt.Fprintln(os.Stderr, "private request key saved to:", *keyFile)
	}
	// The URL goes to stdout so the user can grab it; progress stays on stderr.
	fmt.Println(created.URL)
	if *noWait {
		fmt.Println("request id:", created.ID)
		return nil
	}
	fmt.Fprintf(os.Stderr, "waiting for the user to fill in %d variable(s) (expires %s)...\n",
		len(spec.Variables), created.ExpiresAt)

	result, err := waitForResult(ctx, *server, created.ID)
	if err != nil {
		if ce, ok := err.(*cliError); ok && ce.code == 3 {
			removeRequestKey(*keyFile)
		}
		return err
	}
	if result.Status == StatusDeclined {
		removeRequestKey(*keyFile)
		return fail(2, "the user declined the request")
	}
	if err := decodeResult(result, privateKey, created.ID, spec); err != nil {
		return fail(1, "%v", err)
	}
	if err := reportResult(*out, result); err != nil {
		return err
	}
	removeRequestKey(*keyFile)
	return nil
}

func cmdPull(args []string) error {
	fs := flag.NewFlagSet("pull", flag.ContinueOnError)
	server := fs.String("server", envOr("SECURE_INPUT_SERVER", "http://localhost:8787"), "server base URL")
	id := fs.String("id", "", "request id returned by `request --no-wait` (required)")
	out := fs.String("out", "", "path to write the .env file to (required)")
	wait := fs.Int("wait", 60, "seconds to wait for the user to submit")
	noEncryption := fs.Bool("no-encryption", false, "pull a plaintext request (encryption is required by default)")
	keyFile := fs.String("key-file", "", "private request state (default: OUT.secure-input-key.json)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id == "" || *out == "" {
		return fail(1, "--id and --out are required")
	}
	var privateKey *ecdh.PrivateKey
	var spec *Spec
	if *noEncryption {
		if *keyFile != "" {
			return fail(1, "--key-file cannot be used with --no-encryption")
		}
		fmt.Fprintln(os.Stderr, "warning: pulling without end-to-end encryption")
	} else {
		if *keyFile == "" {
			*keyFile = *out + ".secure-input-key.json"
		}
		if samePath(*keyFile, *out) {
			return fail(1, "--key-file must differ from --out")
		}
		var err error
		privateKey, spec, err = loadRequestKey(*keyFile, *server, *id)
		if err != nil {
			return fail(1, "%v", err)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	result, gone, err := pollOnce(ctx, *server, *id, *wait)
	if err != nil {
		return fail(1, "%v", err)
	}
	if gone {
		removeRequestKey(*keyFile)
		return fail(3, "request expired or already consumed")
	}
	switch result.Status {
	case StatusPending:
		return fail(3, "request is still pending after %ds", *wait)
	case StatusDeclined:
		removeRequestKey(*keyFile)
		return fail(2, "the user declined the request")
	}
	if err := decodeResult(result, privateKey, *id, spec); err != nil {
		return fail(1, "%v", err)
	}
	if err := reportResult(*out, result); err != nil {
		return err
	}
	removeRequestKey(*keyFile)
	return nil
}

// waitForResult long-polls until the request resolves. Transient network
// errors are retried; the server-side expiry is what ultimately ends the wait.
func waitForResult(ctx context.Context, server, id string) (*resultResponse, error) {
	const consecutiveErrorLimit = 6
	errors := 0
	for {
		result, gone, err := pollOnce(ctx, server, id, 25)
		if err != nil {
			if ctx.Err() != nil {
				return nil, fail(130, "interrupted")
			}
			errors++
			if errors >= consecutiveErrorLimit {
				return nil, fail(1, "poll failed %d times in a row: %v", errors, err)
			}
			select {
			case <-ctx.Done():
				return nil, fail(130, "interrupted")
			case <-time.After(2 * time.Second):
			}
			continue
		}
		errors = 0
		if gone {
			return nil, fail(3, "request expired or was already consumed")
		}
		if result.Status != StatusPending {
			return result, nil
		}
	}
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
