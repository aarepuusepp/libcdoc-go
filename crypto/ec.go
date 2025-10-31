package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"fmt"
	"math/big"
	"github.com/aarepuusepp/libcdoc-go/v2/internal"
)

const (
	// SecP384R1OID is the OID for secp384r1 curve
	SecP384R1OID = "1.3.132.0.34"
)

var (
	// P384 is the secp384r1 curve
	P384 = elliptic.P384()
)

// GenerateECKeyPair generates an ephemeral EC key pair on the same curve as the given public key
func GenerateECKeyPair(publicKey *ecdsa.PublicKey) (*ecdsa.PrivateKey, error) {
	if publicKey.Curve != P384 {
		return nil, internal.NewEncryptionError(
			fmt.Sprintf("unsupported curve, only secp384r1 is supported, got %T", publicKey.Curve),
			nil,
		)
	}

	privKey, err := ecdsa.GenerateKey(publicKey.Curve, rand.Reader)
	if err != nil {
		return nil, internal.NewEncryptionError("failed to generate EC key pair", err)
	}

	return privKey, nil
}

// ECDHKeyAgreement performs ECDH key agreement and returns the shared secret
func ECDHKeyAgreement(privKey *ecdsa.PrivateKey, pubKey *ecdsa.PublicKey) ([]byte, error) {
	if privKey.Curve != pubKey.Curve {
		return nil, internal.NewEncryptionError(
			"private and public keys are on different curves",
			nil,
		)
	}

	// ECDH shared secret = private key * public key point
	x, _ := privKey.Curve.ScalarMult(pubKey.X, pubKey.Y, privKey.D.Bytes())

	// Convert shared point X coordinate to bytes
	sharedSecret := make([]byte, (privKey.Curve.Params().BitSize+7)/8)
	xBytes := x.Bytes()
	copy(sharedSecret[len(sharedSecret)-len(xBytes):], xBytes)

	return sharedSecret, nil
}

// ConcatKDF performs ConcatKDF key derivation using SHA-512
// Parameters are concatenated as: AlgorithmID | PartyUInfo | PartyVInfo
func ConcatKDF(sharedSecret []byte, algorithmID []byte, partyUInfo []byte, partyVInfo []byte) ([]byte, error) {
	// ConcatKDF requires SHA-512 with 32-byte output
	outputLength := 32

	// Concatenate parameters
	concatenated := make([]byte, 0, len(algorithmID)+len(partyUInfo)+len(partyVInfo))
	concatenated = append(concatenated, algorithmID...)
	concatenated = append(concatenated, partyUInfo...)
	concatenated = append(concatenated, partyVInfo...)

	// Hash shared secret with concatenated parameters
	h := sha512.New()
	h.Write(sharedSecret)
	h.Write(concatenated)
	hash := h.Sum(nil)

	// Return first 32 bytes
	if len(hash) < outputLength {
		return nil, internal.NewEncryptionError("hash output too short", nil)
	}

	return hash[:outputLength], nil
}

// ValidateECPoint validates that an EC point is on the given curve
func ValidateECPoint(x, y *big.Int, curve elliptic.Curve) bool {
	if x == nil || y == nil {
		return false
	}

	// Check point is not at infinity
	if x.Sign() == 0 && y.Sign() == 0 {
		return false
	}

	// Validate point is on the curve
	return curve.IsOnCurve(x, y)
}

// ExtractECPublicKeyFromCertificate extracts the EC public key from a certificate
func ExtractECPublicKeyFromCertificate(cert *x509.Certificate) (*ecdsa.PublicKey, error) {
	pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, internal.NewCertificateError(
			"certificate does not contain EC public key",
			nil,
		)
	}

	// Validate curve is secp384r1
	if pubKey.Curve != P384 {
		return nil, internal.NewCertificateError(
			fmt.Sprintf("unsupported curve, only secp384r1 is supported"),
			nil,
		)
	}

	return pubKey, nil
}

// ValidateECPublicKey validates an EC public key point
func ValidateECPublicKey(pubKey *ecdsa.PublicKey) error {
	if !ValidateECPoint(pubKey.X, pubKey.Y, pubKey.Curve) {
		return internal.NewCertificateError(
			"EC public key point is not valid on the curve",
			nil,
		)
	}

	// Additional validation: check coordinates are in valid range
	params := pubKey.Curve.Params()
	if pubKey.X.Cmp(params.P) >= 0 || pubKey.Y.Cmp(params.P) >= 0 {
		return internal.NewCertificateError(
			"EC public key coordinates out of range",
			nil,
		)
	}

	return nil
}
