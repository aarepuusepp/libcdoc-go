package cdoc2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"

	"github.com/aarepuusepp/libcdoc-go/v2/crypto"
)

// IsLegacySPKI identifies the non-standard SPKI encoding emitted by older releases.
// It is an explicit compatibility discriminator, never a fallback after authentication fails.
func IsLegacySPKI(encoded []byte) bool {
	_, err := x509.ParsePKIXPublicKey(encoded)
	return err == nil
}

// DecodeECCPublicKey accepts standard TLS points and historical SPKI containers.
func DecodeECCPublicKey(encoded []byte) (*ecdsa.PublicKey, error) {
	if IsLegacySPKI(encoded) {
		pub, _ := x509.ParsePKIXPublicKey(encoded)
		if ec, ok := pub.(*ecdsa.PublicKey); ok {
			return ec, nil
		}
		return nil, fmt.Errorf("sender key is not ECC")
	}
	var curve elliptic.Curve
	switch len(encoded) {
	case 65:
		curve = elliptic.P256()
	case 97:
		curve = elliptic.P384()
	case 133:
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("invalid ECC point length")
	}
	return ecdsa.ParseUncompressedPublicKey(curve, encoded)
}

// DeriveInlineECCKEK implements CDOC2 HKDF-SHA256 over the exact capsule encodings.
func DeriveInlineECCKEK(shared, recipient, sender []byte) ([]byte, error) {
	info := []byte(GetSaltForExpandWithKeyMaterial(recipient, sender))
	if IsLegacySPKI(sender) {
		pm := crypto.HKDFExtractSHA512([]byte(KEKPREMASTER), shared)
		defer clear(pm)
		return crypto.HKDFExpandSHA512(pm, info, KeyLen)
	}
	pm := crypto.HKDFExtract([]byte(KEKPREMASTER), shared)
	defer clear(pm)
	return crypto.HKDFExpand(pm, info, KeyLen)
}
