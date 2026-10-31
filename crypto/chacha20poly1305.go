package crypto

import (
	"crypto/cipher"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/aarepuusepp/libcdoc-go/v2/internal"
)

// EncryptChaCha20Poly1305 encrypts plaintext using ChaCha20-Poly1305
// key must be 32 bytes (ChaCha20-Poly1305 key length)
// nonce must be 12 bytes (ChaCha20-Poly1305 nonce length)
// aad is additional authenticated data (can be nil)
// Returns ciphertext with authentication tag appended (16 bytes tag)
func EncryptChaCha20Poly1305(plaintext, key, nonce, aad []byte) ([]byte, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, internal.NewEncryptionError(
			"ChaCha20-Poly1305 key must be 32 bytes",
			nil,
		)
	}

	if len(nonce) != chacha20poly1305.NonceSize {
		return nil, internal.NewEncryptionError(
			"ChaCha20-Poly1305 nonce must be 12 bytes",
			nil,
		)
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, internal.NewEncryptionError("failed to create ChaCha20-Poly1305 cipher", err)
	}

	// Seal encrypts and authenticates plaintext, appending the authentication tag
	ciphertext := aead.Seal(nil, nonce, plaintext, aad)
	return ciphertext, nil
}

// DecryptChaCha20Poly1305 decrypts ciphertext using ChaCha20-Poly1305
// key must be 32 bytes
// nonce must be 12 bytes
// aad is additional authenticated data (must match encryption, can be nil)
// ciphertext includes the 16-byte authentication tag at the end
// Returns plaintext if authentication succeeds
func DecryptChaCha20Poly1305(ciphertext, key, nonce, aad []byte) ([]byte, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, internal.NewDecryptionError(
			"ChaCha20-Poly1305 key must be 32 bytes",
			nil,
		)
	}

	if len(nonce) != chacha20poly1305.NonceSize {
		return nil, internal.NewDecryptionError(
			"ChaCha20-Poly1305 nonce must be 12 bytes",
			nil,
		)
	}

	// Ciphertext must include the 16-byte authentication tag
	if len(ciphertext) < chacha20poly1305.Overhead {
		return nil, internal.NewDecryptionError(
			"ciphertext too short (must include authentication tag)",
			nil,
		)
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, internal.NewDecryptionError("failed to create ChaCha20-Poly1305 cipher", err)
	}

	// Open decrypts and authenticates ciphertext
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, internal.NewDecryptionError("ChaCha20-Poly1305 decryption failed (authentication failed)", err)
	}

	return plaintext, nil
}

// NewChaCha20Poly1305 creates a new ChaCha20-Poly1305 AEAD cipher
// This can be used for streaming encryption/decryption if needed
func NewChaCha20Poly1305(key []byte) (cipher.AEAD, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, internal.NewEncryptionError(
			"ChaCha20-Poly1305 key must be 32 bytes",
			nil,
		)
	}

	return chacha20poly1305.New(key)
}
