package key

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"github.com/yourorg/cdoc1-go/internal"
)

// ParsePrivateKeyDER parses a private key from DER format (PKCS#8)
func ParsePrivateKeyDER(derData []byte) (*PrivateKey, error) {
	key, err := x509.ParsePKCS8PrivateKey(derData)
	if err != nil {
		return nil, internal.NewCertificateError("failed to parse PKCS#8 DER private key", err)
	}

	// Validate key type
	switch key.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey:
		return &PrivateKey{Key: key}, nil
	default:
		return nil, internal.NewCertificateError(
			"private key is not RSA or ECDSA",
			nil,
		)
	}
}

// ParsePrivateKey parses a private key from PEM or DER format
func ParsePrivateKey(data []byte) (*PrivateKey, error) {
	// Try PEM first
	if key, err := ParsePrivateKeyPEM(data); err == nil {
		return key, nil
	}

	// Fall back to DER
	return ParsePrivateKeyDER(data)
}
