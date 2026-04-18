package crypto

import (
	"crypto/aes"
	"crypto/subtle"
	"encoding/binary"
	"github.com/aarepuusepp/libcdoc-go/v2/internal"
)

// AESKW256 implements AES Key Wrap (RFC 3394) for 256-bit keys
// This wraps/unwraps a 256-bit key using AES-KW with a 256-bit wrapping key

var rfc3394DefaultIV = [8]byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}

// WrapAES256 wraps a 256-bit key using AES-KW-256 (RFC 3394)
func WrapAES256(keyToWrap []byte, wrappingKey []byte) ([]byte, error) {
	if len(keyToWrap) != 32 {
		return nil, internal.NewEncryptionError("key to wrap must be 32 bytes", nil)
	}
	if len(wrappingKey) != 32 {
		return nil, internal.NewEncryptionError("wrapping key must be 32 bytes", nil)
	}

	return wrapRFC3394(wrappingKey, keyToWrap)
}

func wrapRFC3394(kek []byte, plaintext []byte) ([]byte, error) {
	if len(plaintext) < 16 || len(plaintext)%8 != 0 {
		return nil, internal.NewEncryptionError("plaintext length must be a multiple of 8 bytes and at least 16 bytes", nil)
	}
	if len(kek) != 16 && len(kek) != 24 && len(kek) != 32 {
		return nil, internal.NewEncryptionError("wrapping key must be 16, 24, or 32 bytes", nil)
	}

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, internal.NewEncryptionError("failed to create AES cipher", err)
	}

	n := len(plaintext) / 8

	// A = IV (RFC 3394 default)
	A := make([]byte, 8)
	copy(A, rfc3394DefaultIV[:])

	R := make([][]byte, n)
	for i := 0; i < n; i++ {
		R[i] = make([]byte, 8)
		copy(R[i], plaintext[i*8:(i+1)*8])
	}

	// RFC 3394: 6 rounds for n blocks
	for j := 0; j < 6; j++ {
		for i := 0; i < n; i++ {
			// t = n*j + (i+1)
			t := uint64(n*j + i + 1)

			var B [16]byte
			copy(B[:8], A)
			copy(B[8:], R[i])
			block.Encrypt(B[:], B[:])

			a := binary.BigEndian.Uint64(B[:8]) ^ t
			binary.BigEndian.PutUint64(A, a)
			copy(R[i], B[8:])
		}
	}

	// Output: C = A | R[1] | ... | R[n]  => (n+1)*8 bytes
	wrapped := make([]byte, 8+(8*n))
	copy(wrapped[:8], A)
	for i := 0; i < n; i++ {
		copy(wrapped[8+i*8:8+(i+1)*8], R[i])
	}
	return wrapped, nil
}

// UnwrapAES256 unwraps a wrapped key using AES-KW-256 (RFC 3394)
func UnwrapAES256(wrappedKey []byte, wrappingKey []byte) ([]byte, error) {
	if len(wrappedKey) != 40 {
		return nil, internal.NewDecryptionError("wrapped key must be 40 bytes", nil)
	}
	if len(wrappingKey) != 32 {
		return nil, internal.NewDecryptionError("wrapping key must be 32 bytes", nil)
	}

	plaintext, err := unwrapRFC3394(wrappingKey, wrappedKey)
	if err != nil {
		return nil, err
	}
	if len(plaintext) != 32 {
		return nil, internal.NewDecryptionError("unwrapped key must be 32 bytes", nil)
	}
	return plaintext, nil
}

func unwrapRFC3394(kek []byte, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 24 || len(ciphertext)%8 != 0 {
		return nil, internal.NewDecryptionError("wrapped key length must be a multiple of 8 bytes and at least 24 bytes", nil)
	}
	if len(kek) != 16 && len(kek) != 24 && len(kek) != 32 {
		return nil, internal.NewDecryptionError("wrapping key must be 16, 24, or 32 bytes", nil)
	}

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, internal.NewDecryptionError("failed to create AES cipher", err)
	}

	n := (len(ciphertext) / 8) - 1

	// Split wrapped key: A (8 bytes) | R[0..n-1] (each 8 bytes)
	A := make([]byte, 8)
	copy(A, ciphertext[:8])

	R := make([][]byte, n)
	for i := 0; i < n; i++ {
		R[i] = make([]byte, 8)
		copy(R[i], ciphertext[8+i*8:8+(i+1)*8])
	}

	// RFC 3394: 6 rounds in reverse
	for j := 5; j >= 0; j-- {
		for i := n - 1; i >= 0; i-- {
			// t = n*j + (i+1)
			t := uint64(n*j + i + 1)

			a := binary.BigEndian.Uint64(A) ^ t
			binary.BigEndian.PutUint64(A, a)

			var B [16]byte
			copy(B[:8], A)
			copy(B[8:], R[i])
			block.Decrypt(B[:], B[:])

			copy(A, B[:8])
			copy(R[i], B[8:])
		}
	}

	if subtle.ConstantTimeCompare(A, rfc3394DefaultIV[:]) != 1 {
		return nil, internal.NewDecryptionError("invalid initial value in wrapped key", nil)
	}

	plaintext := make([]byte, 8*n)
	for i := 0; i < n; i++ {
		copy(plaintext[i*8:(i+1)*8], R[i])
	}
	return plaintext, nil
}
