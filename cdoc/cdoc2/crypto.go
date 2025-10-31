package cdoc2

import (
	"crypto/rand"

	"github.com/aarepuusepp/libcdoc-go/v2/crypto"
	"github.com/aarepuusepp/libcdoc-go/v2/internal"
)

// GenerateFMK generates a File Master Key using random bytes and HKDF-Extract
// Returns a 32-byte FMK
func GenerateFMK() ([]byte, error) {
	// Generate 32 random bytes
	randomBytes := make([]byte, KeyLen)
	if _, err := rand.Read(randomBytes); err != nil {
		return nil, internal.NewEncryptionError("failed to generate random bytes for FMK", err)
	}

	// HKDF-Extract: Extract(random, "CDOC20salt")
	salt := []byte(SALT)
	fmk := crypto.HKDFExtract(salt, randomBytes)

	// Clear the random bytes
	for i := range randomBytes {
		randomBytes[i] = 0
	}

	return fmk, nil
}

// DeriveCEK derives the Content Encryption Key from FMK
// CEK = HKDF-Expand(FMK, "CDOC20cek", 32)
func DeriveCEK(fmk []byte) ([]byte, error) {
	if len(fmk) != KeyLen {
		return nil, internal.NewEncryptionError(
			"FMK must be 32 bytes",
			nil,
		)
	}

	info := []byte(CEK)
	cek, err := crypto.HKDFExpand(fmk, info, KeyLen)
	if err != nil {
		return nil, internal.NewEncryptionError("failed to derive CEK", err)
	}

	return cek, nil
}

// DeriveHMACKey derives the HMAC key from FMK
// HMAC key = HKDF-Expand(FMK, "CDOC20hmac", 32)
func DeriveHMACKey(fmk []byte) ([]byte, error) {
	if len(fmk) != KeyLen {
		return nil, internal.NewEncryptionError(
			"FMK must be 32 bytes",
			nil,
		)
	}

	info := []byte(HMAC)
	hmacKey, err := crypto.HKDFExpand(fmk, info, KeyLen)
	if err != nil {
		return nil, internal.NewEncryptionError("failed to derive HMAC key", err)
	}

	return hmacKey, nil
}

// XOREncrypt performs XOR encryption/decryption
// For CDOC2, FMK is encrypted with XOR using a derived KEK
func XOREncrypt(data, key []byte) []byte {
	if len(data) == 0 {
		return data
	}
	if len(key) == 0 {
		// Return data as-is if key is empty (should not happen)
		return data
	}

	result := make([]byte, len(data))
	for i := range data {
		result[i] = data[i] ^ key[i%len(key)]
	}
	return result
}

// GetSaltForExpand creates the salt string for foxesHKDF Expand operation
// Used for deriving KEK from pre-master keys
// Pattern: KEK + FMKEncryptionMethodName + label
func GetSaltForExpand(label string) string {
	return string(KEK) + "XOR" + label
}

// GetSaltForExpandWithKeyMaterial creates the salt string for HKDF Expand
// Pattern: KEK + FMKEncryptionMethodName + recipient_key + key_material
func GetSaltForExpandWithKeyMaterial(recipientKey, keyMaterial []byte) string {
	result := string(KEK) + "XOR"
	result += string(recipientKey)
	result += string(keyMaterial)
	return result
}

