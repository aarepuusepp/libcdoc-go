package key

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/yourorg/cdoc1-go/internal"
)

// ParsePrivateKeyPEM parses a private key from PEM format
func ParsePrivateKeyPEM(pemData []byte) (*PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		// Try DER format
		return ParsePrivateKeyDER(pemData)
	}

	var key crypto.PrivateKey
	var err error

	switch block.Type {
	case "RSA PRIVATE KEY":
		// PKCS#1 format
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, internal.NewCertificateError("failed to parse PKCS#1 private key", err)
		}
	case "PRIVATE KEY":
		// PKCS#8 format
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, internal.NewCertificateError("failed to parse PKCS#8 private key", err)
		}
	case "EC PRIVATE KEY":
		// EC private key in SEC1 format
		key, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, internal.NewCertificateError("failed to parse EC private key", err)
		}
	default:
		return nil, internal.NewCertificateError(
			fmt.Sprintf("unsupported private key type: %s", block.Type),
			nil,
		)
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
