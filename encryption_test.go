package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func encryptedSpec(t *testing.T) (Spec, *ecdh.PrivateKey) {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spec := specForTest()
	spec.Encryption = &EncryptionConfig{Version: 1, PublicKey: base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())}
	return spec, key
}

func encryptForTest(t *testing.T, recipient *ecdh.PublicKey, id string, plaintext string) *EncryptedPayload {
	t.Helper()
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := ephemeral.ECDH(recipient)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 12)
	rand.Read(nonce)
	epk := base64.StdEncoding.EncodeToString(ephemeral.PublicKey().Bytes())
	info := encryptionContext(id, base64.StdEncoding.EncodeToString(recipient.Bytes()), epk)
	key, err := hkdf.Key(sha256.New, shared, nonce, info, 32)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	encrypted := aead.Seal(nil, nonce, []byte(plaintext), []byte(info))
	return &EncryptedPayload{Version: 1, EphemeralPublicKey: epk, Nonce: base64.StdEncoding.EncodeToString(nonce), Ciphertext: base64.StdEncoding.EncodeToString(encrypted)}
}

const samplePlaintext = `{"entries":[{"key":"TOKEN","value":"private-测试-🔒"},{"key":"REGION","value":"us-west","private":false}]}`

func TestEncryptionRoundTripAndAuthentication(t *testing.T) {
	spec, key := encryptedSpec(t)
	payload := encryptForTest(t, key.PublicKey(), "request-one", samplePlaintext)
	entries, err := decryptEntries(key, "request-one", spec.Variables, payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Value != "private-测试-🔒" || !entries[0].Private || entries[1].Private {
		t.Fatalf("unexpected entries: %+v", entries)
	}
	_, wrongKey := encryptedSpec(t)
	if _, err := decryptEntries(wrongKey, "request-one", spec.Variables, payload); err == nil {
		t.Fatal("wrong key accepted")
	}
	if _, err := decryptEntries(key, "other-request", spec.Variables, payload); err == nil {
		t.Fatal("cross-request replay accepted")
	}
	for _, field := range []string{"ciphertext", "nonce", "ephemeral"} {
		t.Run(field, func(t *testing.T) {
			changed := *payload
			switch field {
			case "ciphertext":
				data, _ := decodeBase64(changed.Ciphertext, -1)
				data[0] ^= 1
				changed.Ciphertext = base64.StdEncoding.EncodeToString(data)
			case "nonce":
				data, _ := decodeBase64(changed.Nonce, -1)
				data[0] ^= 1
				changed.Nonce = base64.StdEncoding.EncodeToString(data)
			case "ephemeral":
				changed.EphemeralPublicKey = spec.Encryption.PublicKey
			}
			if _, err := decryptEntries(key, "request-one", spec.Variables, &changed); err == nil {
				t.Fatal("tampering accepted")
			}
		})
	}
}

func TestDecryptedEntryValidation(t *testing.T) {
	spec, key := encryptedSpec(t)
	for name, plaintext := range map[string]string{
		"unknown":         `{"entries":[{"key":"OTHER","value":"x"}]}`,
		"reserved":        `{"entries":[{"key":"PATH","value":"x"}]}`,
		"duplicate":       `{"entries":[{"key":"TOKEN"},{"key":"TOKEN"}]}`,
		"invalid json":    `not json`,
		"oversized value": `{"entries":[{"key":"TOKEN","value":"` + strings.Repeat("x", MaxValueLength+1) + `"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			payload := encryptForTest(t, key.PublicKey(), "id", plaintext)
			if _, err := decryptEntries(key, "id", spec.Variables, payload); err == nil {
				t.Fatal("invalid plaintext accepted")
			}
		})
	}
}

func TestEncryptionValidation(t *testing.T) {
	spec, key := encryptedSpec(t)
	for _, config := range []*EncryptionConfig{
		{Version: 2, PublicKey: spec.Encryption.PublicKey}, {Version: 1, PublicKey: "bad"},
		{Version: 1, PublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32))},
		{Version: 1, PublicKey: spec.Encryption.PublicKey + "\n"},
	} {
		if err := validateEncryption(config); err == nil {
			t.Fatal("invalid encryption config accepted")
		}
	}
	good := encryptForTest(t, key.PublicKey(), "id", samplePlaintext)
	for _, change := range []func(*EncryptedPayload){
		func(p *EncryptedPayload) { p.Version = 2 }, func(p *EncryptedPayload) { p.Nonce = "bad" },
		func(p *EncryptedPayload) { p.Ciphertext = base64.StdEncoding.EncodeToString(make([]byte, 15)) },
		func(p *EncryptedPayload) { p.Ciphertext = strings.Repeat("A", maxEncryptedBodyBytes) },
		func(p *EncryptedPayload) { p.EphemeralPublicKey = base64.StdEncoding.EncodeToString(make([]byte, 32)) },
	} {
		bad := *good
		change(&bad)
		if err := validateEncryptedPayload(&bad); err == nil {
			t.Fatal("invalid envelope accepted")
		}
	}
}

func TestEncryptedServerLifecycle(t *testing.T) {
	srv, store := newTestServer(t)
	spec, key := encryptedSpec(t)
	created, err := createRequest(context.Background(), srv.URL, &spec)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(created.URL, "#e2ee=") {
		t.Fatal("missing pinned public key")
	}
	link, err := url.Parse(created.URL)
	if err != nil {
		t.Fatal(err)
	}
	// location.hash preserves percent escapes. Parse exactly once, as the
	// browser's URLSearchParams does; Go must not double-encode %2B/%3D.
	pin, err := url.ParseQuery(link.EscapedFragment())
	if err != nil || pin.Get("e2ee") != spec.Encryption.PublicKey {
		t.Fatalf("public-key fragment failed to round-trip: %q", created.URL)
	}
	res, err := http.Get(created.URL)
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if !strings.Contains(string(page), spec.Encryption.PublicKey) || !strings.Contains(string(page), "End-to-end encryption is enabled") {
		t.Fatal("form missing encryption config")
	}
	if res.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("secret page should not be cached")
	}
	for _, body := range []string{samplePlaintext, `{}`, `{"encrypted":{"version":2}}`} {
		res = postJSON(t, srv.URL+"/r/"+created.ID+"/submit", body)
		res.Body.Close()
		if res.StatusCode != http.StatusBadRequest {
			t.Fatalf("invalid submission: %s", res.Status)
		}
	}
	payload := encryptForTest(t, key.PublicKey(), created.ID, samplePlaintext)
	mixed, _ := json.Marshal(map[string]any{"entries": nil, "encrypted": payload})
	res = postJSON(t, srv.URL+"/r/"+created.ID+"/submit", string(mixed))
	res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatal("mixed plaintext and ciphertext accepted")
	}
	wire, _ := json.Marshal(map[string]any{"encrypted": payload})
	res = postJSON(t, srv.URL+"/r/"+created.ID+"/submit", string(wire))
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("submit: %s", res.Status)
	}
	stored := store.Get(created.ID)
	if stored.Entries != nil || stored.Encrypted == nil {
		t.Fatal("store must hold only ciphertext")
	}
	result, gone, err := pollOnce(context.Background(), srv.URL, created.ID, 0)
	if err != nil || gone {
		t.Fatalf("pull: %v, gone=%v", err, gone)
	}
	if result.Entries != nil || result.Encrypted == nil {
		t.Fatal("server returned plaintext entries")
	}
	if err := decodeResult(result, key, created.ID, &spec); err != nil {
		t.Fatal(err)
	}
	if result.Entries[0].Value != "private-测试-🔒" {
		t.Fatal("wrong decrypted value")
	}
	_, gone, err = pollOnce(context.Background(), srv.URL, created.ID, 0)
	if err != nil || !gone {
		t.Fatal("result was not consumed exactly once")
	}
}

func TestRefuseDowngrade(t *testing.T) {
	spec, key := encryptedSpec(t)
	legacy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusCreated, createResponse{ID: "id", URL: "https://example.test/r/id"})
	}))
	defer legacy.Close()
	if _, err := createRequest(context.Background(), legacy.URL, &spec); err == nil {
		t.Fatal("old server silently disabled encryption")
	}
	for _, result := range []*resultResponse{
		{Status: StatusSubmitted, Entries: []Entry{{Key: "TOKEN", Value: "leak"}}},
		{Status: StatusSubmitted}, {Status: "unexpected"},
	} {
		if err := decodeResult(result, key, "id", &spec); err == nil {
			t.Fatal("plaintext/invalid result accepted")
		}
	}
	if err := decodeResult(&resultResponse{Status: StatusSubmitted, Encrypted: &EncryptedPayload{}}, nil, "id", nil); err == nil {
		t.Fatal("ciphertext accepted in plaintext mode")
	}
}

func TestPrivateKeyFile(t *testing.T) {
	spec, key := encryptedSpec(t)
	path := filepath.Join(t.TempDir(), "key.json")
	if err := saveRequestKey(path, "https://example.test/", "id", &spec, key); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatalf("permissions: %o", info.Mode().Perm())
	}
	if err := saveRequestKey(path, "https://example.test", "id", &spec, key); err == nil {
		t.Fatal("overwrote existing key")
	}
	loaded, loadedSpec, err := loadRequestKey(path, "https://example.test", "id")
	if err != nil || !key.Equal(loaded) || loadedSpec.Variables[0].Key != "TOKEN" {
		t.Fatalf("load: %v", err)
	}
	for _, wrong := range [][2]string{{"https://other.test", "id"}, {"https://example.test", "other"}} {
		if _, _, err := loadRequestKey(path, wrong[0], wrong[1]); err == nil {
			t.Fatal("mismatched key state accepted")
		}
	}
	if runtime.GOOS != "windows" {
		os.Chmod(path, 0644)
		if _, _, err := loadRequestKey(path, "https://example.test", "id"); err == nil {
			t.Fatal("insecure key permissions accepted")
		}
	}
}

func TestCLINoWaitAndPull(t *testing.T) {
	srv, store := newTestServer(t)
	out := filepath.Join(t.TempDir(), "values.env")
	if err := cmdRequest([]string{"--server", srv.URL, "--out", out, "--reason", "test", "--var", "TOKEN", "--no-wait"}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out + ".secure-input-key.json")
	if err != nil {
		t.Fatal(err)
	}
	var state requestKey
	json.Unmarshal(data, &state)
	if state.Spec.Encryption == nil {
		t.Fatal("CLI encryption not enabled by default")
	}
	public, _ := decodeBase64(state.Spec.Encryption.PublicKey, 32)
	pub, _ := ecdh.X25519().NewPublicKey(public)
	payload := encryptForTest(t, pub, state.ID, `{"entries":[{"key":"TOKEN","value":"cli-secret"}]}`)
	if store.SubmitEncrypted(state.ID, payload) == nil {
		t.Fatal("submit failed")
	}
	// Missing/mismatched local state must fail BEFORE consuming the result.
	if err := cmdPull([]string{"--server", srv.URL, "--out", out, "--id", state.ID, "--key-file", out + ".missing"}); err == nil {
		t.Fatal("pull without key succeeded")
	}
	if store.Get(state.ID) == nil {
		t.Fatal("missing-key pull consumed result")
	}
	if err := cmdPull([]string{"--server", srv.URL, "--out", out, "--id", state.ID}); err != nil {
		t.Fatal(err)
	}
	env, err := os.ReadFile(out)
	if err != nil || !strings.Contains(string(env), "cli-secret") {
		t.Fatalf("env save: %s %v", env, err)
	}
	if _, err := os.Stat(out + ".secure-input-key.json"); !os.IsNotExist(err) {
		t.Fatal("private key file not removed")
	}
}

func TestCLIExplicitPlaintext(t *testing.T) {
	srv, store := newTestServer(t)
	out := filepath.Join(t.TempDir(), "values.env")
	if err := cmdRequest([]string{"--server", srv.URL, "--out", out, "--reason", "test", "--var", "TOKEN", "--no-wait", "--no-encryption"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(out + ".secure-input-key.json"); !os.IsNotExist(err) {
		t.Fatal("plaintext request saved a key")
	}
	var id string
	for key, req := range store.requests {
		id = key
		if req.Encryption != nil {
			t.Fatal("plaintext flag ignored")
		}
	}
	store.Submit(id, []Entry{{Key: "TOKEN", Value: "legacy-secret", Private: true}})
	if err := cmdPull([]string{"--server", srv.URL, "--out", out, "--id", id, "--no-encryption"}); err != nil {
		t.Fatal(err)
	}
}

func TestBrowserCryptoInteroperability(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		if os.Getenv("SECURE_INPUT_REQUIRE_NODE") == "1" {
			t.Fatal("Node.js required for Web Crypto interoperability tests")
		}
		t.Skip("Node.js not installed; run with Node 22+ for Web Crypto interoperability")
	}
	spec, key := encryptedSpec(t)
	input, _ := json.Marshal(map[string]any{"config": spec.Encryption, "id": "browser-test", "plaintext": samplePlaintext})
	cmd := exec.Command(node, "web/crypto_test.cjs")
	cmd.Stdin = bytes.NewReader(input)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("browser crypto: %v\n%s", err, output)
	}
	var payload EncryptedPayload
	if err := json.Unmarshal(output, &payload); err != nil {
		t.Fatalf("invalid browser result: %v\n%s", err, output)
	}
	entries, err := decryptEntries(key, "browser-test", spec.Variables, &payload)
	if err != nil || entries[0].Value != "private-测试-🔒" {
		t.Fatalf("Web Crypto / Go interoperability: %v", err)
	}
}

func TestKeyPathAliases(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix symlink test")
	}
	dir := t.TempDir()
	actual := filepath.Join(dir, "actual")
	alias := filepath.Join(dir, "alias")
	if err := os.Mkdir(actual, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(actual, alias); err != nil {
		t.Fatal(err)
	}
	if !samePath(filepath.Join(actual, "new"), filepath.Join(alias, "new")) {
		t.Fatal("parent-directory symlink alias missed")
	}
	file := filepath.Join(actual, "key")
	os.WriteFile(file, []byte("test"), 0600)
	hardlink := filepath.Join(dir, "hardlink")
	if err := os.Link(file, hardlink); err != nil {
		t.Fatal(err)
	}
	if !samePath(file, hardlink) {
		t.Fatal("same-file alias missed")
	}
}

func TestEncryptedStoreSnapshots(t *testing.T) {
	spec, key := encryptedSpec(t)
	store := NewStore(RequestTTL)
	req := store.Create(spec)
	payload := encryptForTest(t, key.PublicKey(), req.ID, samplePlaintext)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 1000; i++ {
			if snapshot := store.Get(req.ID); snapshot != nil {
				_, _ = json.Marshal(snapshot)
			}
		}
	}()
	if store.SubmitEncrypted(req.ID, payload) == nil {
		t.Fatal("submit failed")
	}
	<-done
	if req.Status != StatusPending || req.Encrypted != nil {
		t.Fatal("Create returned mutable store state")
	}
	payload.Ciphertext = "changed"
	snapshot := store.Get(req.ID)
	if snapshot.Encrypted.Ciphertext == "changed" {
		t.Fatal("store retained caller payload")
	}
	snapshot.Encrypted.Ciphertext = "changed-again"
	if store.Get(req.ID).Encrypted.Ciphertext == "changed-again" {
		t.Fatal("Get returned mutable store state")
	}
}
