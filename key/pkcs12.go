package key

import (
	"crypto/x509"

	"github.com/aarepuusepp/libcdoc-go/v2/internal"
	"software.sslmate.com/src/go-pkcs12"
)

// PKCS12KeyEntry represents a private key and certificate extracted from a PKCS#12 keystore
type PKCS12KeyEntry struct {
	PrivateKey  *PrivateKey
	Certificate *x509.Certificate
}

// ParsePKCS12 parses a PKCS#12 keystore file and extracts the private key and certificate
// password is the keystore password
// alias is optional - if not provided, the first valid key entry will be used
func ParsePKCS12(p12Data []byte, password string, alias ...string) (*PKCS12KeyEntry, error) {
	if len(p12Data) == 0 {
		return nil, internal.NewCertificateError("PKCS#12 data is empty", nil)
	}

	// Parse PKCS#12 data using software.sslmate.com/src/go-pkcs12.
	// Use DecodeChain to support keystores that include a CA chain in addition to
	// the leaf certificate and private key.
	privateKey, certificate, _, err := pkcs12.DecodeChain(p12Data, password)
	if err != nil {
		return nil, internal.NewCertificateError("failed to decode PKCS#12 keystore", err)
	}

	// Note: For alias support, we'd need to decode all entries and find by alias
	// The software.sslmate.com/src/go-pkcs12.DecodeChain extracts the first private key and the leaf certificate
	// If alias is provided, we should find matching entry, but for MVP we support auto-select
	// This matches cdoc4j's pattern where it auto-selects first valid key if no alias given

	if privateKey == nil {
		return nil, internal.NewCertificateError("no private key found in PKCS#12 keystore", nil)
	}

	if certificate == nil {
		return nil, internal.NewCertificateError("no certificate found in PKCS#12 keystore", nil)
	}

	return &PKCS12KeyEntry{
		PrivateKey:  &PrivateKey{Key: privateKey},
		Certificate: certificate,
	}, nil
}

