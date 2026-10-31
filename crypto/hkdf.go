package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"hash"

	"github.com/aarepuusepp/libcdoc-go/v2/internal"
)

// HKDFExtract performs HKDF Extract operation (RFC 5869)
// Extract(salt, IKM) -> PRK (Pseudo-Random Key)
// If salt is empty or nil, it uses a zero-filled salt of hash length
func HKDFExtract(salt, ikm []byte) []byte {
	// Use SHA-256 as the hash function (RFC 5869 default)
	return hkdfExtractWithHash(sha256.New, salt, ikm)
}

// HKDFExtractSHA512 performs HKDF Extract with SHA-512
// Used for CDOC2 ECC key derivation
func HKDFExtractSHA512(salt, ikm []byte) []byte {
	return hkdfExtractWithHash(sha512.New, salt, ikm)
}

// hkdfExtractWithHash performs HKDF Extract with a specific hash function
func hkdfExtractWithHash(hashFn func() hash.Hash, salt, ikm []byte) []byte {
	if len(salt) == 0 {
		// Use zero-filled salt of hash length (RFC 5869 Section 2.2)
		salt = make([]byte, hashFn().Size())
	}
	h := hmac.New(hashFn, salt)
	h.Write(ikm)
	return h.Sum(nil)
}

// HKDFExpand performs HKDF Expand operation (RFC 5869)
// Expand(PRK, info, L) -> OKM (Output Keying Material)
// PRK is the pseudo-random key from Extract
// info is optional context/application-specific information
// L is the desired output length in bytes
func HKDFExpand(prk, info []byte, length int) ([]byte, error) {
	// Use SHA-256 as the hash function
	return hkdfExpandWithHash(sha256.New, prk, info, length)
}

// HKDFExpandSHA512 performs HKDF Expand with SHA-512
// Used for CDOC2 ECC key derivation
func HKDFExpandSHA512(prk, info []byte, length int) ([]byte, error) {
	return hkdfExpandWithHash(sha512.New, prk, info, length)
}

// hkdfExpandWithHash performs HKDF Expand with a specific hash function
func hkdfExpandWithHash(hashFn func() hash.Hash, prk, info []byte, length int) ([]byte, error) {
	if length < 0 {
		return nil, internal.NewEncryptionError("HKDF length must be non-negative", nil)
	}

	hashSize := hashFn().Size()
	if length > 255*hashSize {
		return nil, internal.NewEncryptionError("HKDF length exceeds maximum", nil)
	}

	n := (length + hashSize - 1) / hashSize // Number of hash iterations needed
	okm := make([]byte, 0, length)

	h := hmac.New(hashFn, prk)
	var t []byte

	for i := 1; i <= n; i++ {
		// T(i) = HMAC-Hash(PRK, T(i-1) | info | octet(i))
		h.Reset()
		if i > 1 {
			h.Write(t)
		}
		h.Write(info)
		h.Write([]byte{byte(i)})

		t = h.Sum(nil)
		okm = append(okm, t...)
	}

	// Return exactly L bytes
	return okm[:length], nil
}
