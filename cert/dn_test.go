package cert

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
)

func TestExtractCN(t *testing.T) {
	// Create a test certificate with CN
	subject := pkix.Name{
		CommonName:   "TEST USER",
		Country:      []string{"EE"},
		Organization: []string{"TEST ORG"},
	}

	cert := &x509.Certificate{
		Subject: subject,
	}

	cn := ExtractCN(cert)
	if cn != "TEST USER" {
		t.Errorf("ExtractCN() = %v, want TEST USER", cn)
	}
}

func TestExtractCN_NoCN(t *testing.T) {
	subject := pkix.Name{
		Country:      []string{"EE"},
		Organization: []string{"TEST ORG"},
	}

	cert := &x509.Certificate{
		Subject: subject,
	}

	cn := ExtractCN(cert)
	if cn != "" {
		t.Errorf("ExtractCN() with no CN = %v, want empty string", cn)
	}
}

func TestFormatDN(t *testing.T) {
	subject := pkix.Name{
		CommonName:   "TEST USER",
		Country:      []string{"EE"},
		Organization: []string{"TEST ORG"},
	}

	formatted := FormatDN(subject)
	if formatted == "" {
		t.Error("FormatDN() should return non-empty string")
	}

	// Should contain CN
	if len(formatted) < 10 {
		t.Error("FormatDN() result seems too short")
	}
}
