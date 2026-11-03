package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// Version 1 is X25519 + HKDF-SHA-256 + AES-256-GCM (128-bit tag).
// Both endpoints use these exact parameters; there is no algorithm negotiation.
const encryptionVersion = 1
const maxEncryptedBodyBytes = (maxBodyBytes+16+2)/3*4 + 1024

type EncryptionConfig struct {
	Version   int    `json:"version"`
	PublicKey string `json:"publicKey"`
}

type EncryptedPayload struct {
	Version            int    `json:"version"`
	EphemeralPublicKey string `json:"ephemeralPublicKey"`
	Nonce              string `json:"nonce"`
	Ciphertext         string `json:"ciphertext"`
}

func decodeBase64(s string, size int) ([]byte, error) {
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || base64.StdEncoding.EncodeToString(b) != s || (size >= 0 && len(b) != size) {
		return nil, fmt.Errorf("invalid base64 or length")
	}
	return b, nil
}

func validateEncryption(config *EncryptionConfig) error {
	if config == nil {
		return nil
	} // Explicit legacy API requests remain supported.
	if config.Version != encryptionVersion {
		return fmt.Errorf("unsupported encryption version")
	}
	key, err := decodeBase64(config.PublicKey, 32)
	if err != nil {
		return fmt.Errorf("invalid X25519 public key")
	}
	// ECDH rejects low-order points. Use a fixed, non-secret validation key.
	probe, _ := ecdh.X25519().NewPrivateKey(make([]byte, 32))
	pub, err := ecdh.X25519().NewPublicKey(key)
	if err != nil {
		return fmt.Errorf("invalid X25519 public key")
	}
	if _, err := probe.ECDH(pub); err != nil {
		return fmt.Errorf("invalid X25519 public key")
	}
	return nil
}

func validateEncryptedPayload(payload *EncryptedPayload) error {
	if payload == nil || payload.Version != encryptionVersion {
		return fmt.Errorf("missing encrypted payload or unsupported encryption version")
	}
	if err := validateEncryption(&EncryptionConfig{Version: payload.Version, PublicKey: payload.EphemeralPublicKey}); err != nil {
		return fmt.Errorf("invalid ephemeral public key")
	}
	if _, err := decodeBase64(payload.Nonce, 12); err != nil {
		return fmt.Errorf("invalid encryption nonce")
	}
	if len(payload.Ciphertext) > (maxBodyBytes+16+2)/3*4 {
		return fmt.Errorf("encrypted payload is too large")
	}
	ciphertext, err := decodeBase64(payload.Ciphertext, -1)
	if err != nil || len(ciphertext) < 16 || len(ciphertext) > maxBodyBytes+16 {
		return fmt.Errorf("invalid encrypted ciphertext")
	}
	return nil
}

func encryptionContext(id, recipient, ephemeral string) string {
	return "secure-input/v1\x00" + id + "\x00" + recipient + "\x00" + ephemeral
}

func decryptEntries(privateKey *ecdh.PrivateKey, id string, variables []VariableSpec, payload *EncryptedPayload) ([]Entry, error) {
	if err := validateEncryptedPayload(payload); err != nil {
		return nil, err
	}
	pubBytes, _ := decodeBase64(payload.EphemeralPublicKey, 32)
	publicKey, _ := ecdh.X25519().NewPublicKey(pubBytes)
	shared, err := privateKey.ECDH(publicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid encryption key agreement")
	}
	defer clear(shared)
	nonce, _ := decodeBase64(payload.Nonce, 12)
	context := encryptionContext(id, base64.StdEncoding.EncodeToString(privateKey.PublicKey().Bytes()), payload.EphemeralPublicKey)
	key, err := hkdf.Key(sha256.New, shared, nonce, context, 32)
	if err != nil {
		return nil, fmt.Errorf("derive encryption key: %w", err)
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ciphertext, _ := decodeBase64(payload.Ciphertext, -1)
	plaintext, err := aead.Open(nil, nonce, ciphertext, []byte(context))
	if err != nil {
		return nil, fmt.Errorf("encrypted result authentication failed")
	}
	defer clear(plaintext)
	var body struct {
		Entries []submittedEntry `json:"entries"`
	}
	if err := json.Unmarshal(plaintext, &body); err != nil {
		return nil, fmt.Errorf("invalid decrypted result")
	}
	// Validate against the CLI's original local spec, not relay-controlled keys/defaults.
	return validateEntries(variables, body.Entries)
}
