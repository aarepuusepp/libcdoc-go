package cdoc

import (
	"io"
	"os"

	"crypto/x509"

	"github.com/aarepuusepp/libcdoc-go/v2/cert"
	"github.com/aarepuusepp/libcdoc-go/v2/internal"
	"github.com/aarepuusepp/libcdoc-go/v2/key"
)

// LoadCertificate loads a certificate from a file path
func LoadCertificate(filepath string) (*x509.Certificate, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, internal.NewCertificateError("failed to open certificate file", err)
	}
	defer func() { _ = file.Close() }()

	certData, err := io.ReadAll(file)
	if err != nil {
		return nil, internal.NewCertificateError("failed to read certificate", err)
	}

	return cert.ParseCertificate(certData)
}

// LoadPrivateKey loads a private key from a file path
// Supports both PEM and DER formats (automatically detected by key package)
func LoadPrivateKey(filepath string) (*key.PrivateKey, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, internal.NewValidationError("failed to open private key file", err)
	}
	defer func() { _ = file.Close() }()

	keyData, err := io.ReadAll(file)
	if err != nil {
		return nil, internal.NewValidationError("failed to read private key file", err)
	}

	privateKey, err := key.ParsePrivateKey(keyData)
	if err != nil {
		return nil, internal.NewValidationError("failed to parse private key", err)
	}

	return privateKey, nil
}
