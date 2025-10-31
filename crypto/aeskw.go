package crypto

import (
	"crypto/aes"
	"github.com/aarepuusepp/libcdoc-go/v2/internal"
)

// AESKW256 implements AES Key Wrap (RFC 3394) for 256-bit keys
// This wraps/unwraps a 256-bit key using AES-KW with a 256-bit wrapping key

// WrapAES256 wraps a 256-bit key using AES-KW-256 (RFC 3394)
func WrapAES256(keyToWrap []byte, wrappingKey []byte) ([]byte, error) {
	if len(keyToWrap) != 32 {
		return nil, internal.NewEncryptionError("key to wrap must be 32 bytes", nil)
	}
	if len(wrappingKey) != 32 {
		return nil, internal.NewEncryptionError("wrapping key must be 32 bytes", nil)
	}

	block, err := aes.NewCipher(wrappingKey)
	if err != nil {
		return nil, internal.NewEncryptionError("failed to create AES cipher", err)
	}

	// RFC 3394: Wrap 32 bytes (4 blocks of 64 bits each) with AES-256
	// Split key into 4 blocks of 8 bytes each
	A := make([]byte, 8) // Initial value: AIV (Alternative Initial Value) = A65959A6 for AES-256
	A[0] = 0xA6
	A[1] = 0x59
	A[2] = 0x59
	A[3] = 0xA6
	A[4] = 0x00
	A[5] = 0x00
	A[6] = 0x00
	A[7] = 0x00

	R := make([][]byte, 4)
	R[0] = make([]byte, 8)
	R[1] = make([]byte, 8)
	R[2] = make([]byte, 8)
	R[3] = make([]byte, 8)
	copy(R[0], keyToWrap[0:8])
	copy(R[1], keyToWrap[8:16])
	copy(R[2], keyToWrap[16:24])
	copy(R[3], keyToWrap[24:32])

	// RFC 3394: 6 rounds for n=4 blocks
	for j := 0; j < 6; j++ {
		for i := 0; i < 4; i++ {
			// t = n*j + i + 1 = 4*j + i + 1
			t := uint64(4*j + i + 1)

			// B = AES(K, A | R[i])
			B := make([]byte, 16)
			copy(B[:8], A)
			copy(B[8:], R[i])

			block.Encrypt(B, B)

			// A = MSB(64, B) XOR t
			copy(A, B[:8])
			tBytes := make([]byte, 8)
			tBytes[7] = byte(t & 0xFF)
			tBytes[6] = byte((t >> 8) & 0xFF)
			tBytes[5] = byte((t >> 16) & 0xFF)
			tBytes[4] = byte((t >> 24) & 0xFF)
			tBytes[3] = byte((t >> 32) & 0xFF)
			tBytes[2] = byte((t >> 40) & 0xFF)
			tBytes[1] = byte((t >> 48) & 0xFF)
			tBytes[0] = byte((t >> 56) & 0xFF)
			for k := 0; k < 8; k++ {
				A[k] ^= tBytes[k]
			}

			// R[i] = LSB(64, B)
			copy(R[i], B[8:])
		}
	}

	// Output: A | R[0] | R[1] | R[2] | R[3] = 40 bytes
	wrapped := make([]byte, 40)
	copy(wrapped[:8], A)
	copy(wrapped[8:16], R[0])
	copy(wrapped[16:24], R[1])
	copy(wrapped[24:32], R[2])
	copy(wrapped[32:40], R[3])

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

	block, err := aes.NewCipher(wrappingKey)
	if err != nil {
		return nil, internal.NewDecryptionError("failed to create AES cipher", err)
	}

	// Split wrapped key: A (8 bytes) | R[0] | R[1] | R[2] | R[3] (each 8 bytes) = 40 bytes
	A := make([]byte, 8)
	copy(A, wrappedKey[:8])

	R := make([][]byte, 4)
	R[0] = make([]byte, 8)
	R[1] = make([]byte, 8)
	R[2] = make([]byte, 8)
	R[3] = make([]byte, 8)
	copy(R[0], wrappedKey[8:16])
	copy(R[1], wrappedKey[16:24])
	copy(R[2], wrappedKey[24:32])
	copy(R[3], wrappedKey[32:40])

	// RFC 3394: 6 rounds in reverse for n=4 blocks
	for j := 5; j >= 0; j-- {
		for i := 3; i >= 0; i-- {
			// t = n*j + i + 1 = 4*j + i + 1
			t := uint64(4*j + i + 1)

			// XOR t with A
			tBytes := make([]byte, 8)
			tBytes[7] = byte(t & 0xFF)
			tBytes[6] = byte((t >> 8) & 0xFF)
			tBytes[5] = byte((t >> 16) & 0xFF)
			tBytes[4] = byte((t >> 24) & 0xFF)
			tBytes[3] = byte((t >> 32) & 0xFF)
			tBytes[2] = byte((t >> 40) & 0xFF)
			tBytes[1] = byte((t >> 48) & 0xFF)
			tBytes[0] = byte((t >> 56) & 0xFF)
			for k := 0; k < 8; k++ {
				A[k] ^= tBytes[k]
			}

			// B = AES-1(K, A | R[i])
			B := make([]byte, 16)
			copy(B[:8], A)
			copy(B[8:], R[i])

			block.Decrypt(B, B)

			// A = MSB(64, B)
			copy(A, B[:8])

			// R[i] = LSB(64, B)
			copy(R[i], B[8:])
		}
	}

	// Verify AIV
	if A[0] != 0xA6 || A[1] != 0x59 || A[2] != 0x59 || A[3] != 0xA6 {
		return nil, internal.NewDecryptionError("invalid AIV in wrapped key", nil)
	}

	// Reconstruct unwrapped key: R[0] | R[1] | R[2] | R[3] = 32 bytes
	unwrapped := make([]byte, 32)
	copy(unwrapped[0:8], R[0])
	copy(unwrapped[8:16], R[1])
	copy(unwrapped[16:24], R[2])
	copy(unwrapped[24:32], R[3])

	return unwrapped, nil
}

