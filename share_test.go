package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var sampleMeta = FileMeta{Name: "report-测试.md", Type: "text/markdown; charset=utf-8", Message: "Build summary 🔐"}

const sampleContent = "# Report\n\nprivate-测试-🔒 <script>alert(1)</script>\n"

func testKey(t *testing.T) []byte {
	t.Helper()
	key, err := newFileKey()
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestFileEncryptionRoundTripAndAuthentication(t *testing.T) {
	key := testKey(t)
	enc, err := encryptFile(key, sampleMeta, []byte(sampleContent))
	if err != nil {
		t.Fatal(err)
	}
	meta, content, err := decryptFile(key, enc)
	if err != nil || *meta != sampleMeta || string(content) != sampleContent {
		t.Fatalf("round trip: %v %+v %q", err, meta, content)
	}
	if again, _ := encryptFile(key, sampleMeta, []byte(sampleContent)); again.MetaNonce == enc.MetaNonce || again.ContentNonce == enc.ContentNonce {
		t.Fatal("nonces reused")
	}
	if _, _, err := decryptFile(testKey(t), enc); err == nil {
		t.Fatal("wrong key accepted")
	}
	tamper := func(value string) string {
		data, _ := decodeBase64(value, -1)
		data[len(data)-1] ^= 1
		return base64.StdEncoding.EncodeToString(data)
	}
	for name, change := range map[string]func(*EncryptedFile){
		"meta":          func(e *EncryptedFile) { e.Meta = tamper(e.Meta) },
		"content":       func(e *EncryptedFile) { e.Content = tamper(e.Content) },
		"meta nonce":    func(e *EncryptedFile) { e.MetaNonce = tamper(e.MetaNonce) },
		"content nonce": func(e *EncryptedFile) { e.ContentNonce = tamper(e.ContentNonce) },
		// Swapping parts must fail: each part's label is authenticated.
		"swap": func(e *EncryptedFile) {
			e.Meta, e.Content = e.Content, e.Meta
			e.MetaNonce, e.ContentNonce = e.ContentNonce, e.MetaNonce
		},
	} {
		changed := *enc
		change(&changed)
		if _, _, err := decryptFile(key, &changed); err == nil {
			t.Fatalf("%s tampering accepted", name)
		}
	}
	for _, size := range []int{0, MaxFileBytes} {
		if _, err := encryptFile(key, sampleMeta, make([]byte, size)); err != nil {
			t.Fatalf("size %d rejected: %v", size, err)
		}
	}
	if _, err := encryptFile(key, sampleMeta, make([]byte, MaxFileBytes+1)); err == nil {
		t.Fatal("oversized file encrypted")
	}
}

func TestFileValidation(t *testing.T) {
	for _, meta := range []FileMeta{
		{Name: "", Type: "text/plain"}, {Name: "a/b", Type: "text/plain"}, {Name: `a\b`, Type: "text/plain"},
		{Name: "..", Type: "text/plain"}, {Name: "a\nb", Type: "text/plain"}, {Name: "a\u0085b", Type: "text/plain"},
		{Name: strings.Repeat("x", MaxFileNameLength+1), Type: "text/plain"}, {Name: "x", Type: ""},
		{Name: "x", Type: "text/plain\n"}, {Name: "x", Type: "text/plain", Message: strings.Repeat("m", MaxReasonLength+1)},
	} {
		if err := validateFileMeta(&meta); err == nil {
			t.Errorf("invalid metadata accepted: %+v", meta)
		}
	}
	good, _ := encryptFile(testKey(t), sampleMeta, []byte(sampleContent))
	plain := &PlainFile{FileMeta: sampleMeta, Content: base64.StdEncoding.EncodeToString([]byte("x"))}
	for name, upload := range map[string]*fileUpload{
		"empty":          {},
		"both":           {File: plain, Encrypted: good},
		"version":        {Encrypted: &EncryptedFile{Version: 2, MetaNonce: good.MetaNonce, Meta: good.Meta, ContentNonce: good.ContentNonce, Content: good.Content}},
		"nonce":          {Encrypted: &EncryptedFile{Version: 1, MetaNonce: "bad", Meta: good.Meta, ContentNonce: good.ContentNonce, Content: good.Content}},
		"short":          {Encrypted: &EncryptedFile{Version: 1, MetaNonce: good.MetaNonce, Meta: good.Meta, ContentNonce: good.ContentNonce, Content: base64.StdEncoding.EncodeToString(make([]byte, 15))}},
		"large":          {Encrypted: &EncryptedFile{Version: 1, MetaNonce: good.MetaNonce, Meta: good.Meta, ContentNonce: good.ContentNonce, Content: base64.StdEncoding.EncodeToString(make([]byte, MaxFileBytes+17))}},
		"plain large":    {File: &PlainFile{FileMeta: sampleMeta, Content: base64.StdEncoding.EncodeToString(make([]byte, MaxFileBytes+1))}},
		"plain encoding": {File: &PlainFile{FileMeta: sampleMeta, Content: "eA"}},
		"plain meta":     {File: &PlainFile{FileMeta: FileMeta{Name: "a/b", Type: "text/plain"}, Content: ""}},
	} {
		if err := validateFileUpload(upload); err == nil {
			t.Errorf("%s: invalid upload accepted", name)
		}
	}
}

// runShare runs the CLI command and returns its stdout.
func runShare(t *testing.T, args ...string) (string, error) {
	t.Helper()
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = write
	cmdErr := cmdShare(args)
	os.Stdout = stdout
	write.Close()
	out, _ := io.ReadAll(read)
	return strings.TrimSpace(string(out)), cmdErr
}

func writeTestFile(t *testing.T, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func getFile(t *testing.T, link string) (*http.Response, fileUpload) {
	t.Helper()
	u, _ := url.Parse(link)
	res, err := http.Get(u.Scheme + "://" + u.Host + "/api/files/" + strings.TrimPrefix(u.Path, "/f/"))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var body fileUpload
	json.NewDecoder(res.Body).Decode(&body)
	return res, body
}

func TestShareEncryptedLifecycle(t *testing.T) {
	srv, store := newTestServer(t)
	path := writeTestFile(t, "report-测试.md", []byte(sampleContent))
	link, err := runShare(t, "--server", srv.URL, "--file", path, "--message", "Build summary 🔐")
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(link)
	if err != nil || !strings.HasPrefix(u.Path, "/f/") {
		t.Fatalf("bad link %q", link)
	}
	fragment, _ := url.ParseQuery(u.EscapedFragment())
	key, err := base64.RawURLEncoding.DecodeString(fragment.Get("key"))
	if err != nil || len(key) != 32 {
		t.Fatalf("missing key in fragment: %q", link)
	}
	id := strings.TrimPrefix(u.Path, "/f/")

	// The server holds only ciphertext: no file name, message, or content.
	stored := store.GetFile(id)
	if stored == nil || stored.Upload.File != nil || stored.Upload.Encrypted == nil || stored.ContentSize != len(sampleContent) {
		t.Fatalf("unexpected stored file %+v", stored)
	}
	wire, _ := json.Marshal(stored)
	for _, secret := range []string{"report", "Build summary", "private-", fragment.Get("key")} {
		if bytes.Contains(wire, []byte(secret)) {
			t.Fatalf("server state leaks %q", secret)
		}
	}

	page, err := http.Get(srv.URL + u.Path)
	if err != nil {
		t.Fatal(err)
	}
	html, _ := io.ReadAll(page.Body)
	page.Body.Close()
	if page.StatusCode != http.StatusOK || !strings.Contains(string(html), "End-to-end encryption is enabled") ||
		!strings.Contains(page.Header.Get("Content-Security-Policy"), "default-src 'none'") ||
		page.Header.Get("Cache-Control") != "no-store" || strings.Contains(string(html), "report") {
		t.Fatalf("file page: %s %s", page.Status, page.Header)
	}

	// Viewing is repeatable until deletion and never returns plaintext.
	for range 2 {
		res, body := getFile(t, link)
		if res.StatusCode != http.StatusOK || body.File != nil || body.Encrypted == nil {
			t.Fatalf("get file: %s", res.Status)
		}
		want := sampleMeta
		want.Type = detectFileType(want.Name, []byte(sampleContent)) // varies with the system MIME table
		meta, content, err := decryptFile(key, body.Encrypted)
		if err != nil || *meta != want || string(content) != sampleContent {
			t.Fatalf("decrypt served file: %v %+v", err, meta)
		}
	}

	del, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/files/"+id, nil)
	res, err := http.DefaultClient.Do(del)
	if err != nil || res.StatusCode != http.StatusNoContent {
		t.Fatalf("delete: %v %v", err, res.Status)
	}
	res.Body.Close()
	res, err = http.DefaultClient.Do(del)
	if err != nil || res.StatusCode != http.StatusGone {
		t.Fatalf("second delete: %v %v", err, res.Status)
	}
	res.Body.Close()
	if res, _ := getFile(t, link); res.StatusCode != http.StatusGone {
		t.Fatalf("deleted file still served: %s", res.Status)
	}
	if page, _ := http.Get(srv.URL + u.Path); page.StatusCode != http.StatusGone {
		t.Fatalf("deleted file page: %s", page.Status)
	}
	if store.fileBytes != 0 || len(store.files) != 0 {
		t.Fatal("deleted file still accounted for")
	}
}

func TestSharePlaintext(t *testing.T) {
	srv, _ := newTestServer(t)
	path := writeTestFile(t, "data.bin", []byte{0, 1, 2, 255})
	link, err := runShare(t, "--server", srv.URL, "--file", path, "--name", "custom.png", "--no-encryption")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(link, "#") {
		t.Fatalf("plaintext link has a fragment: %q", link)
	}
	res, body := getFile(t, link)
	if res.StatusCode != http.StatusOK || body.Encrypted != nil || body.File == nil ||
		body.File.Name != "custom.png" || body.File.Type != "image/png" ||
		body.File.Content != base64.StdEncoding.EncodeToString([]byte{0, 1, 2, 255}) {
		t.Fatalf("plaintext file: %+v", body.File)
	}
	page, _ := http.Get(link)
	html, _ := io.ReadAll(page.Body)
	page.Body.Close()
	if !strings.Contains(string(html), "Encryption is disabled for this file") {
		t.Fatal("plaintext page is not labelled")
	}
}

func TestShareSizeLimit(t *testing.T) {
	srv, _ := newTestServer(t)
	exact := writeTestFile(t, "exact.txt", bytes.Repeat([]byte("<"), MaxFileBytes))
	// The largest plaintext body: a full file plus a message that JSON-escapes sixfold.
	message := strings.Repeat("<", MaxReasonLength)
	for _, extra := range [][]string{nil, {"--no-encryption"}} {
		args := append([]string{"--server", srv.URL, "--file", exact, "--message", message, "--name", strings.Repeat("&", MaxFileNameLength)}, extra...)
		if _, err := runShare(t, args...); err != nil {
			t.Fatalf("512 KiB file rejected %v: %v", extra, err)
		}
	}
	tooLarge := writeTestFile(t, "big.txt", make([]byte, MaxFileBytes+1))
	if _, err := runShare(t, "--server", srv.URL, "--file", tooLarge); err == nil || !strings.Contains(err.Error(), "512 KiB") {
		t.Fatalf("oversized file accepted: %v", err)
	}
	if _, err := runShare(t, "--server", srv.URL, "--file", t.TempDir()); err == nil {
		t.Fatal("directory accepted")
	}
	// The server enforces the limit too, independently of the CLI.
	body, _ := json.Marshal(fileUpload{File: &PlainFile{FileMeta: sampleMeta, Content: base64.StdEncoding.EncodeToString(make([]byte, MaxFileBytes+1))}})
	if res := postJSON(t, srv.URL+"/api/files", string(body)); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("server accepted oversized file: %s", res.Status)
	}
}

func TestFileStoreExpiryAndCapacity(t *testing.T) {
	store := NewStore(200 * time.Millisecond)
	enc, _ := encryptFile(testKey(t), sampleMeta, make([]byte, 1000))
	upload := fileUpload{Encrypted: enc}
	store.fileCapacity = uploadSize(&upload) * 2
	first, err := store.CreateFile(upload)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.CreateFile(upload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateFile(upload); err != errFileStoreFull {
		t.Fatalf("capacity not enforced: %v", err)
	}
	if !store.DeleteFile(first.ID) || store.DeleteFile(first.ID) {
		t.Fatal("delete should succeed exactly once")
	}
	if _, err := store.CreateFile(upload); err != nil {
		t.Fatalf("deleting did not free capacity: %v", err)
	}
	// Viewing does not extend the lifetime.
	time.Sleep(100 * time.Millisecond)
	if store.GetFile(second.ID) == nil {
		t.Fatal("file expired early")
	}
	time.Sleep(150 * time.Millisecond)
	if store.GetFile(second.ID) != nil || store.DeleteFile(second.ID) {
		t.Fatal("expired file still available")
	}
	// Every file so far has expired. A full store reclaims them before refusing.
	for range 2 {
		if _, err := store.CreateFile(upload); err != nil {
			t.Fatalf("expired files not reclaimed: %v", err)
		}
	}
	if store.fileBytes != 2*uploadSize(&upload) || len(store.files) != 2 {
		t.Fatalf("accounting drifted: %d bytes, %d files", store.fileBytes, len(store.files))
	}
	time.Sleep(250 * time.Millisecond)
	if store.Sweep() != 2 || store.fileBytes != 0 || len(store.files) != 0 {
		t.Fatalf("sweep left %d bytes", store.fileBytes)
	}
}

func TestShareServerFull(t *testing.T) {
	srv, store := newTestServer(t)
	store.fileCapacity = 10
	path := writeTestFile(t, "a.txt", []byte(sampleContent))
	if _, err := runShare(t, "--server", srv.URL, "--file", path); err == nil || !strings.Contains(err.Error(), "full") {
		t.Fatalf("full server: %v", err)
	}
}

func TestBrowserFileDecryptionInteroperability(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		if os.Getenv("SECURE_INPUT_REQUIRE_NODE") == "1" {
			t.Fatal("Node.js required for Web Crypto interoperability tests")
		}
		t.Skip("Node.js not installed")
	}
	key := testKey(t)
	content := append([]byte(sampleContent), make([]byte, MaxFileBytes-len(sampleContent))...)
	for i := range content[len(sampleContent):] {
		content[len(sampleContent)+i] = byte(i)
	}
	enc, err := encryptFile(key, sampleMeta, content)
	if err != nil {
		t.Fatal(err)
	}
	plain := &PlainFile{FileMeta: sampleMeta, Content: base64.StdEncoding.EncodeToString(content)}
	input, _ := json.Marshal(map[string]any{
		"key": encodeFileKey(key), "encrypted": fileUpload{Encrypted: enc}, "plain": fileUpload{File: plain},
	})
	cmd := exec.Command(node, "web/file_crypto_test.cjs")
	cmd.Stdin = bytes.NewReader(input)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("browser file crypto: %v\n%s", err, output)
	}
	var got struct {
		Meta   FileMeta `json:"meta"`
		SHA256 string   `json:"sha256"`
	}
	if err := json.Unmarshal(output, &got); err != nil {
		t.Fatalf("invalid output: %v\n%s", err, output)
	}
	sum := sha256.Sum256(content)
	if got.Meta != sampleMeta || got.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("Web Crypto / Go mismatch: %+v", got)
	}
}
