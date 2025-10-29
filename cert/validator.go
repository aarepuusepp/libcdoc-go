package cert

import (
	"crypto/x509"
	"fmt"
	"github.com/yourorg/cdoc1-go/internal"
)

// ValidateKeyUsage validates that a certificate has the appropriate key usage for RSA or EC encryption
func ValidateKeyUsage(cert *x509.Certificate, forRSA bool) error {
	if forRSA {
		// RSA requires keyEncipherment key usage
		if cert.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
			return internal.NewCertificateError(
				"recipient's certificate doesn't contain 'keyEncipherment' key usage",
				nil,
			)
		}
	} else {
		// EC requires keyAgreement key usage
		if cert.KeyUsage&x509.KeyUsageKeyAgreement == 0 {
			return internal.NewCertificateError(
				"recipient's certificate doesn't contain 'keyAgreement' key usage",
				nil,
			)
		}
	}

	return nil
}

// ValidateCertificate validates a certificate for CDOC usage
func ValidateCertificate(cert *x509.Certificate) error {
	if cert == nil {
		return internal.NewCertificateError("certificate is nil", nil)
	}

	// Check if certificate is expired
	// Note: We might want to allow expired certificates for decryption of old documents
	// For encryption, we should validate the certificate

	// Validate that certificate has at least some key usage set
	if cert.KeyUsage == 0 && len(cert.ExtKeyUsage) == 0 {
		return internal.NewCertificateError(
			"certificate has no key usage specified",
			nil,
		)
	}

	return nil
}

// IsRSACertificate checks if a certificate contains an RSA public key
func IsRSACertificate(cert *x509.Certificate) bool {
	return cert.PublicKeyAlgorithm == x509.RSA
}

// IsECCertificate checks if a certificate contains an EC public key
func IsECCertificate(cert *x509.Certificate) bool {
	return cert.PublicKeyAlgorithm == x509.ECDSA
}

// ValidateRecipientCertificate validates a certificate for use as a recipient
func ValidateRecipientCertificate(cert *x509.Certificate) error {
	if err := ValidateCertificate(cert); err != nil {
		return err
	}

	isRSA := IsRSACertificate(cert)
	if !isRSA && !IsECCertificate(cert) {
		return internal.NewCertificateError(
			fmt.Sprintf("certificate contains unsupported key algorithm: %s", cert.PublicKeyAlgorithm.String()),
			nil,
		)
	}

	return ValidateKeyUsage(cert, isRSA)
}
