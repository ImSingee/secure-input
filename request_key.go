package main

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// requestKey is local-only state, never a wire type. The original spec is
// retained so a later pull validates decrypted entries against the request.
type requestKey struct {
	Version    int    `json:"version"`
	ID         string `json:"id"`
	Server     string `json:"server"`
	Spec       Spec   `json:"spec"`
	PrivateKey string `json:"privateKey"`
}

func samePath(a, b string) bool {
	aa, errA := filepath.Abs(a)
	bb, errB := filepath.Abs(b)
	if errA != nil || errB != nil {
		return false
	}
	if ia, err := os.Stat(aa); err == nil {
		if ib, err := os.Stat(bb); err == nil && os.SameFile(ia, ib) {
			return true
		}
	}
	// Resolve directory aliases even before a new output file exists.
	canonical := func(path string) string {
		if resolved, err := filepath.EvalSymlinks(path); err == nil {
			return resolved
		}
		if dir, err := filepath.EvalSymlinks(filepath.Dir(path)); err == nil {
			return filepath.Join(dir, filepath.Base(path))
		}
		return path
	}
	aa, bb = canonical(aa), canonical(bb)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(aa, bb)
	}
	return aa == bb
}

func saveRequestKey(path, server, id string, spec *Spec, key *ecdh.PrivateKey) error {
	if runtime.GOOS == "windows" {
		fmt.Fprintln(os.Stderr, "warning: Windows does not enforce Unix mode 0600; store this private key only in a directory with an owner-only ACL")
	}
	state := requestKey{Version: encryptionVersion, ID: id, Server: strings.TrimRight(server, "/"), Spec: *spec, PrivateKey: base64.StdEncoding.EncodeToString(key.Bytes())}
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	defer clear(data)
	// Never overwrite a key for an outstanding request (or follow a symlink).
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("create private key file: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		os.Remove(path)
		return fmt.Errorf("write private key file: %w", err)
	}
	if err := file.Close(); err != nil {
		os.Remove(path)
		return err
	}
	return nil
}

func loadRequestKey(path, server, id string) (*ecdh.PrivateKey, *Spec, error) {
	if runtime.GOOS == "windows" {
		fmt.Fprintln(os.Stderr, "warning: verify this private key file has an owner-only Windows ACL; Unix permission checks do not apply")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read private key file %s: %w (use --key-file, or --no-encryption for a plaintext request)", path, err)
	}
	if !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0) {
		return nil, nil, fmt.Errorf("private key file must be a regular file accessible only by its owner (chmod 600)")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxBodyBytes+1))
	if err != nil || len(data) > maxBodyBytes {
		return nil, nil, fmt.Errorf("invalid private key file")
	}
	defer clear(data)
	var state requestKey
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, nil, fmt.Errorf("invalid private key file")
	}
	if state.Version != encryptionVersion || state.ID != id || state.Server != strings.TrimRight(server, "/") {
		return nil, nil, fmt.Errorf("private key file does not match this server and request")
	}
	if err := validateSpec(&state.Spec); err != nil || state.Spec.Encryption == nil {
		return nil, nil, fmt.Errorf("invalid private key file spec")
	}
	raw, err := decodeBase64(state.PrivateKey, 32)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid private key")
	}
	defer clear(raw)
	key, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil || base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()) != state.Spec.Encryption.PublicKey {
		return nil, nil, fmt.Errorf("private key does not match the request public key")
	}
	return key, &state.Spec, nil
}

func removeRequestKey(path string) {
	if path != "" {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "warning: remove private key file %s: %v\n", path, err)
		}
	}
}

func decodeResult(result *resultResponse, key *ecdh.PrivateKey, id string, spec *Spec) error {
	if result.Status != StatusSubmitted {
		return fmt.Errorf("unexpected result status %q", result.Status)
	}
	if key == nil {
		if result.Encrypted != nil {
			return fmt.Errorf("encrypted result requires its private key; refusing plaintext mode")
		}
		return nil
	}
	if result.Encrypted == nil || result.Entries != nil {
		return fmt.Errorf("expected an encrypted result; refusing plaintext downgrade")
	}
	entries, err := decryptEntries(key, id, spec.Variables, result.Encrypted)
	if err != nil {
		return err
	}
	result.Entries = entries
	return nil
}
