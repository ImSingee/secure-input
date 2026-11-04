package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type createFileResponse struct {
	ID        string `json:"id"`
	URL       string `json:"url"`
	ExpiresAt string `json:"expiresAt"`
	Encrypted bool   `json:"encrypted"`
}

// readShareFile reads at most MaxFileBytes from a regular file.
func readShareFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	// Read through a limit rather than trusting Stat: the file may still be growing.
	content, err := io.ReadAll(io.LimitReader(file, MaxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(content) > MaxFileBytes {
		return nil, fmt.Errorf("%s exceeds the %d-byte (512 KiB) file limit", path, MaxFileBytes)
	}
	return content, nil
}

func detectFileType(name string, content []byte) string {
	if t := mime.TypeByExtension(strings.ToLower(filepath.Ext(name))); t != "" {
		return t
	}
	return http.DetectContentType(content)
}

func uploadFile(ctx context.Context, server string, upload *fileUpload) (*createFileResponse, error) {
	endpoint, err := apiURL(server, "/api/files")
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(upload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 60 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("upload file: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNotFound || res.StatusCode == http.StatusMethodNotAllowed {
		return nil, fmt.Errorf("upload file: the server does not support file sharing (upgrade it)")
	}
	if res.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("upload file: server returned %s: %s", res.Status, readErrorBody(res.Body))
	}
	var out createFileResponse
	if err := json.NewDecoder(io.LimitReader(res.Body, 64*1024)).Decode(&out); err != nil {
		return nil, fmt.Errorf("upload file: %w", err)
	}
	if out.Encrypted != (upload.Encrypted != nil) {
		return nil, fmt.Errorf("upload file: server misreported the encryption mode")
	}
	if out.ID == "" || strings.ContainsAny(out.ID, "/?#\\\x00") {
		return nil, fmt.Errorf("upload file: server returned an invalid file id")
	}
	link, err := url.Parse(out.URL)
	if err != nil || link.Host == "" || (link.Scheme != "https" && link.Scheme != "http") || link.Fragment != "" {
		return nil, fmt.Errorf("upload file: server returned an invalid file URL")
	}
	return &out, nil
}

func cmdShare(args []string) error {
	fs := flag.NewFlagSet("share", flag.ContinueOnError)
	server := fs.String("server", envOr("SECURE_INPUT_SERVER", "http://localhost:8787"), "server base URL")
	path := fs.String("file", "", "local file to share, at most 512 KiB (required)")
	name := fs.String("name", "", "file name shown to the person (default: the file's base name)")
	message := fs.String("message", "", "optional note shown above the file")
	noEncryption := fs.Bool("no-encryption", false, "disable end-to-end encryption (server can read the file)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *path == "" {
		return fail(1, "--file is required")
	}
	content, err := readShareFile(*path)
	if err != nil {
		return fail(1, "%v", err)
	}
	if *name == "" {
		*name = filepath.Base(*path)
	}
	meta := FileMeta{Name: *name, Type: detectFileType(*name, content), Message: *message}
	if err := validateFileMeta(&meta); err != nil {
		return fail(1, "%v", err)
	}

	upload := &fileUpload{}
	var key []byte
	if *noEncryption {
		fmt.Fprintln(os.Stderr, "warning: end-to-end encryption is disabled; the server can read the file")
		upload.File = &PlainFile{FileMeta: meta, Content: base64.StdEncoding.EncodeToString(content)}
	} else {
		if key, err = newFileKey(); err != nil {
			return fail(1, "generate encryption key: %v", err)
		}
		defer clear(key)
		if upload.Encrypted, err = encryptFile(key, meta, content); err != nil {
			return fail(1, "encrypt file: %v", err)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	created, err := uploadFile(ctx, *server, upload)
	if err != nil {
		return fail(1, "%v", err)
	}
	link := created.URL
	if key != nil {
		// The fragment is never sent to the server; only the browser sees the key.
		link += "#" + fileKeyFragment + "=" + encodeFileKey(key)
	}
	fmt.Println(link)
	mode := "end-to-end encrypted"
	if key == nil {
		mode = "NOT encrypted"
	}
	fmt.Fprintf(os.Stderr, "shared %s (%d bytes, %s); it stays in server memory until %s or until deleted.\n",
		meta.Name, len(content), mode, created.ExpiresAt)
	fmt.Fprintln(os.Stderr, "anyone with the full link can view the file and delete it from the server.")
	return nil
}
