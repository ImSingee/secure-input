package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// File sharing sends a file from the agent's machine to a person's browser.
//
// Version 1 encryption: the CLI generates a random 256-bit AES key per share
// and puts it only in the URL fragment (#key=...), which browsers never send
// to the server. Metadata (name, type, message) and content are sealed
// separately with AES-256-GCM, each under a fresh random 96-bit nonce. The
// additional authenticated data labels each part so the two ciphertexts
// cannot be swapped.
const (
	fileEncryptionVersion = 1
	MaxFileBytes          = 512 * 1024
	MaxFileNameLength     = 255
	MaxFileTypeLength     = 255
	maxFileMetaBytes      = 16 * 1024
	// The total memory budget for shared files. Uploads beyond it are refused
	// until older shares expire or are deleted.
	MaxStoredFileBytes = 256 << 20
)

// Plaintext JSON may escape every byte of the metadata sixfold; leave room for it.
const maxFileBodyBytes = (MaxFileBytes+16+2)/3*4 + 8*maxFileMetaBytes

const fileKeyFragment = "key"

// FileMeta is the metadata the person sees. In encrypted shares it is sealed.
type FileMeta struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Message string `json:"message,omitempty"`
}

// PlainFile is the explicit no-encryption wire form. Content is base64.
type PlainFile struct {
	FileMeta
	Content string `json:"content"`
}

type EncryptedFile struct {
	Version      int    `json:"version"`
	MetaNonce    string `json:"metaNonce"`
	Meta         string `json:"meta"`
	ContentNonce string `json:"contentNonce"`
	Content      string `json:"content"`
}

// fileUpload is the body of POST /api/files and of GET /api/files/{id}.
// Exactly one of File or Encrypted is set.
type fileUpload struct {
	File      *PlainFile     `json:"file,omitempty"`
	Encrypted *EncryptedFile `json:"encrypted,omitempty"`
}

func fileAAD(part string) []byte {
	return []byte("secure-input/file/v1\x00" + part)
}

func validateFileMeta(meta *FileMeta) error {
	if meta.Name == "" || len(meta.Name) > MaxFileNameLength || !utf8.ValidString(meta.Name) {
		return fmt.Errorf("file name must be 1-%d bytes of valid UTF-8", MaxFileNameLength)
	}
	if strings.ContainsAny(meta.Name, `/\`) || meta.Name == "." || meta.Name == ".." {
		return fmt.Errorf("file name must not contain path separators")
	}
	if strings.IndexFunc(meta.Name, unicode.IsControl) >= 0 {
		return fmt.Errorf("file name must not contain control characters")
	}
	if meta.Type == "" || len(meta.Type) > MaxFileTypeLength {
		return fmt.Errorf("file type must be 1-%d characters", MaxFileTypeLength)
	}
	for _, r := range meta.Type {
		if r < 0x20 || r > 0x7e {
			return fmt.Errorf("file type must be printable ASCII")
		}
	}
	if len(meta.Message) > MaxReasonLength || !utf8.ValidString(meta.Message) {
		return fmt.Errorf("message must be at most %d bytes of valid UTF-8", MaxReasonLength)
	}
	return nil
}

// validateFileUpload checks the wire shape and limits. For encrypted shares
// the server can only check sizes; the browser authenticates the contents.
func validateFileUpload(upload *fileUpload) error {
	if upload == nil || (upload.File == nil) == (upload.Encrypted == nil) {
		return fmt.Errorf("exactly one of file or encrypted is required")
	}
	if f := upload.File; f != nil {
		if err := validateFileMeta(&f.FileMeta); err != nil {
			return err
		}
		if len(f.Content) > (MaxFileBytes+2)/3*4 {
			return fmt.Errorf("file exceeds %d bytes", MaxFileBytes)
		}
		content, err := decodeBase64(f.Content, -1)
		if err != nil {
			return fmt.Errorf("invalid file content encoding")
		}
		if len(content) > MaxFileBytes {
			return fmt.Errorf("file exceeds %d bytes", MaxFileBytes)
		}
		return nil
	}
	e := upload.Encrypted
	if e.Version != fileEncryptionVersion {
		return fmt.Errorf("unsupported file encryption version")
	}
	if _, err := decodeBase64(e.MetaNonce, 12); err != nil {
		return fmt.Errorf("invalid metadata nonce")
	}
	if _, err := decodeBase64(e.ContentNonce, 12); err != nil {
		return fmt.Errorf("invalid content nonce")
	}
	if err := checkCiphertext(e.Meta, maxFileMetaBytes); err != nil {
		return fmt.Errorf("invalid encrypted metadata: %w", err)
	}
	if err := checkCiphertext(e.Content, MaxFileBytes); err != nil {
		return fmt.Errorf("invalid encrypted content: %w", err)
	}
	return nil
}

func checkCiphertext(value string, maxPlaintext int) error {
	if len(value) > (maxPlaintext+16+2)/3*4 {
		return fmt.Errorf("too large")
	}
	data, err := decodeBase64(value, -1)
	if err != nil || len(data) < 16 {
		return fmt.Errorf("bad encoding or length")
	}
	if len(data) > maxPlaintext+16 {
		return fmt.Errorf("too large")
	}
	return nil
}

// uploadSize approximates the memory a stored upload occupies.
func uploadSize(upload *fileUpload) int {
	if f := upload.File; f != nil {
		return len(f.Name) + len(f.Type) + len(f.Message) + len(f.Content)
	}
	e := upload.Encrypted
	return len(e.MetaNonce) + len(e.Meta) + len(e.ContentNonce) + len(e.Content)
}

// contentSize returns the plaintext length of a validated upload's content.
func contentSize(upload *fileUpload) int {
	if upload.File != nil {
		return base64DecodedLen(upload.File.Content)
	}
	return base64DecodedLen(upload.Encrypted.Content) - 16 // GCM tag
}

// base64DecodedLen is the exact decoded length of canonical padded base64.
func base64DecodedLen(s string) int {
	return len(s)/4*3 - (len(s) - len(strings.TrimRight(s, "=")))
}

func newFileKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

func encodeFileKey(key []byte) string { return base64.RawURLEncoding.EncodeToString(key) }

func fileAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("file key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func sealPart(aead cipher.AEAD, part string, plaintext []byte) (nonce, ciphertext string, err error) {
	n := make([]byte, aead.NonceSize())
	if _, err := rand.Read(n); err != nil {
		return "", "", err
	}
	sealed := aead.Seal(nil, n, plaintext, fileAAD(part))
	return base64.StdEncoding.EncodeToString(n), base64.StdEncoding.EncodeToString(sealed), nil
}

func encryptFile(key []byte, meta FileMeta, content []byte) (*EncryptedFile, error) {
	if err := validateFileMeta(&meta); err != nil {
		return nil, err
	}
	if len(content) > MaxFileBytes {
		return nil, fmt.Errorf("file exceeds %d bytes", MaxFileBytes)
	}
	aead, err := fileAEAD(key)
	if err != nil {
		return nil, err
	}
	metaJSON, err := json.Marshal(meta)
	if err != nil {
		return nil, err
	}
	if len(metaJSON) > maxFileMetaBytes {
		return nil, fmt.Errorf("file metadata is too large")
	}
	out := &EncryptedFile{Version: fileEncryptionVersion}
	if out.MetaNonce, out.Meta, err = sealPart(aead, "meta", metaJSON); err != nil {
		return nil, err
	}
	if out.ContentNonce, out.Content, err = sealPart(aead, "content", content); err != nil {
		return nil, err
	}
	return out, nil
}

// decryptFile mirrors the browser's decryption. The CLI does not need it; it
// documents the protocol and lets tests check the browser against Go.
func decryptFile(key []byte, e *EncryptedFile) (*FileMeta, []byte, error) {
	if err := validateFileUpload(&fileUpload{Encrypted: e}); err != nil {
		return nil, nil, err
	}
	aead, err := fileAEAD(key)
	if err != nil {
		return nil, nil, err
	}
	open := func(part, nonce, ciphertext string) ([]byte, error) {
		n, _ := decodeBase64(nonce, 12)
		c, _ := decodeBase64(ciphertext, -1)
		plaintext, err := aead.Open(nil, n, c, fileAAD(part))
		if err != nil {
			return nil, fmt.Errorf("file %s authentication failed", part)
		}
		return plaintext, nil
	}
	metaJSON, err := open("meta", e.MetaNonce, e.Meta)
	if err != nil {
		return nil, nil, err
	}
	var meta FileMeta
	if err := json.Unmarshal(metaJSON, &meta); err != nil {
		return nil, nil, fmt.Errorf("invalid file metadata")
	}
	if err := validateFileMeta(&meta); err != nil {
		return nil, nil, err
	}
	content, err := open("content", e.ContentNonce, e.Content)
	if err != nil {
		return nil, nil, err
	}
	return &meta, content, nil
}
