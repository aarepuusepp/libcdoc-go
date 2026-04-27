package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"github.com/aarepuusepp/libcdoc-go/v2/internal"
	"hash"
	"math/big"
)

const (
	// SecP256R1OID is the OID for secp256r1 (aka prime256v1) curve
	SecP256R1OID = "1.2.840.10045.3.1.7"
	// SecP384R1OID is the OID for secp384r1 curve
	SecP384R1OID = "1.3.132.0.34"
	DigestSHA256URI = "http://www.w3.org/2001/04/xmlenc#sha256"
	DigestSHA384URI = "http://www.w3.org/2001/04/xmlenc#sha384"
	DigestSHA512URI = "http://www.w3.org/2001/04/xmlenc#sha512"
)

var (
	// P256 is the secp256r1 curve
	P256 = elliptic.P256()
	// P384 is the secp384r1 curve
	P384 = elliptic.P384()
)

type ecCurveInfo struct {
	namedCurveOID string
	digestURI     string
}

func curveInfo(curve elliptic.Curve) (ecCurveInfo, error) {
	switch curve {
	case P256:
		return ecCurveInfo{
			namedCurveOID: SecP256R1OID,
			digestURI:     DigestSHA256URI,
		}, nil
	case P384:
		return ecCurveInfo{
			namedCurveOID: SecP384R1OID,
			digestURI:     DigestSHA384URI,
		}, nil
	default:
		return ecCurveInfo{}, internal.NewEncryptionError(
			fmt.Sprintf("unsupported curve, only secp256r1 and secp384r1 are supported, got %T", curve),
			nil,
		)
	}
}

// ECNamedCurveOIDAndDigestURI returns the XMLENC11 NamedCurve OID and ConcatKDF digest URI for the given curve.
func ECNamedCurveOIDAndDigestURI(curve elliptic.Curve) (namedCurveOID string, digestURI string, err error) {
	info, err := curveInfo(curve)
	if err != nil {
		return "", "", err
	}
	return info.namedCurveOID, info.digestURI, nil
}

// GenerateECKeyPair generates an ephemeral EC key pair on the same curve as the given public key
func GenerateECKeyPair(publicKey *ecdsa.PublicKey) (*ecdsa.PrivateKey, error) {
	if _, err := curveInfo(publicKey.Curve); err != nil {
		return nil, err
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

// ConcatKDF performs XMLENC11 ConcatKDF using SHA-384, deriving a 32-byte KEK for AES-KW-256.
// For digest selection or non-default key lengths, use ConcatKDFWithDigest.
func ConcatKDF(sharedSecret []byte, algorithmID []byte, partyUInfo []byte, partyVInfo []byte) ([]byte, error) {
	return ConcatKDFWithDigest(sharedSecret, algorithmID, partyUInfo, partyVInfo, DigestSHA384URI, 32)
}

// ConcatKDFWithDigest performs XMLENC11 ConcatKDF with an explicit digest and output length.
// It derives keying material from:
//
//	Z (ECDH shared secret) and OtherInfo = AlgorithmID || PartyUInfo || PartyVInfo.
//
// Construction (NIST SP 800-56A):
//
//	K = H(1 || Z || OtherInfo) || H(2 || Z || OtherInfo) || ...
//
// Output is truncated to keyLen bytes.
func ConcatKDFWithDigest(sharedSecret []byte, algorithmID []byte, partyUInfo []byte, partyVInfo []byte, digestURI string, keyLen int) ([]byte, error) {
	if keyLen <= 0 {
		return nil, internal.NewEncryptionError("invalid key length", nil)
	}
	if len(sharedSecret) == 0 {
		return nil, internal.NewEncryptionError("shared secret is empty", nil)
	}

	// OtherInfo = AlgorithmID || PartyUInfo || PartyVInfo
	otherInfo := make([]byte, 0, len(algorithmID)+len(partyUInfo)+len(partyVInfo))
	otherInfo = append(otherInfo, algorithmID...)
	otherInfo = append(otherInfo, partyUInfo...)
	otherInfo = append(otherInfo, partyVInfo...)

	newHash, err := hashFromDigestURI(digestURI)
	if err != nil {
		return nil, err
	}

	hashLen := newHash().Size()
	reps := (keyLen + hashLen - 1) / hashLen
	if reps <= 0 {
		return nil, internal.NewEncryptionError("invalid KDF repetition count", nil)
	}

	out := make([]byte, 0, reps*hashLen)
	for counter := 1; counter <= reps; counter++ {
		var counterBuf [4]byte
		binary.BigEndian.PutUint32(counterBuf[:], uint32(counter))

		h := newHash()
		_, _ = h.Write(counterBuf[:])
		_, _ = h.Write(sharedSecret)
		_, _ = h.Write(otherInfo)
		out = append(out, h.Sum(nil)...)
	}

	if len(out) < keyLen {
		return nil, internal.NewEncryptionError("KDF output too short", nil)
	}

	return out[:keyLen], nil
}

func hashFromDigestURI(digestURI string) (func() hash.Hash, error) {
	switch digestURI {
	case "", DigestSHA384URI:
		return sha512.New384, nil
	case DigestSHA256URI:
		return sha256.New, nil
	case DigestSHA512URI:
		return sha512.New, nil
	default:
		return nil, internal.NewEncryptionError("unsupported digest algorithm: "+digestURI, nil)
	}
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

	if _, err := curveInfo(pubKey.Curve); err != nil {
		return nil, internal.NewCertificateError(
			"unsupported curve, only secp256r1 and secp384r1 are supported",
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
