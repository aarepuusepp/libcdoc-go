package cert

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/yourorg/cdoc1-go/internal"
)

// ParseCertificatePEM parses an X.509 certificate from PEM format
func ParseCertificatePEM(pemData []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		// Try DER format
		return ParseCertificateDER(pemData)
	}

	if block.Type != "CERTIFICATE" {
		return nil, internal.NewCertificateError(
			fmt.Sprintf("expected CERTIFICATE block, got %s", block.Type),
			nil,
		)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, internal.NewCertificateError("failed to parse certificate", err)
	}

	return cert, nil
}

// ParseCertificateDER parses an X.509 certificate from DER format
func ParseCertificateDER(derData []byte) (*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(derData)
	if err != nil {
		return nil, internal.NewCertificateError("failed to parse DER certificate", err)
	}

	return cert, nil
}

// ParseCertificate parses an X.509 certificate from PEM or DER format
func ParseCertificate(data []byte) (*x509.Certificate, error) {
	// Try PEM first
	if cert, err := ParseCertificatePEM(data); err == nil {
		return cert, nil
	}

	// Fall back to DER
	return ParseCertificateDER(data)
}

// LoadCertificateFromFile loads and parses a certificate from a file
func LoadCertificateFromFile(filename string) (*x509.Certificate, error) {
	// This will be used by the main API
	// For now, return error indicating file I/O should be handled by caller
	return nil, fmt.Errorf("LoadCertificateFromFile not yet implemented - use ParseCertificate with file contents")
}
