package cdoc

import (
	"io"
	"os"

	"crypto/x509"

	"github.com/yourorg/cdoc1-go/cert"
	"github.com/yourorg/cdoc1-go/internal"
)

// LoadCertificate loads a certificate from a file path
func LoadCertificate(filepath string) (*x509.Certificate, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, internal.NewCertificateError("failed to open certificate file", err)
	}
	defer file.Close()

	certData, err := io.ReadAll(file)
	if err != nil {
		return nil, internal.NewCertificateError("failed to read certificate", err)
	}

	return cert.ParseCertificate(certData)
}

// LoadPrivateKey is a convenience function that will be implemented when we integrate the key package
// For now, this is a placeholder
func LoadPrivateKey(filepath string) (interface{}, error) {
	// TODO: Implement using key package
	return nil, internal.NewValidationError("LoadPrivateKey not yet implemented", nil)
}

