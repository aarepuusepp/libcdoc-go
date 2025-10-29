package cert

import (
	"os"
	"testing"
)

func TestParseCertificatePEM(t *testing.T) {
	// This test will need actual certificate files from cdoc4j test resources
	// For now, we'll create a basic test structure

	// Test with invalid PEM data
	_, err := ParseCertificatePEM([]byte("invalid PEM data"))
	if err == nil {
		t.Error("ParseCertificatePEM() with invalid data should fail")
	}

	// Test with empty data
	_, err = ParseCertificatePEM([]byte{})
	if err == nil {
		t.Error("ParseCertificatePEM() with empty data should fail")
	}
}

func TestParseCertificate_InvalidData(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"invalid text", []byte("not a certificate")},
		{"random bytes", []byte{1, 2, 3, 4, 5}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseCertificate(tt.data)
			if err == nil {
				t.Errorf("ParseCertificate() with %s should fail", tt.name)
			}
		})
	}
}

// Helper function to check if certificate test file exists and load it
func loadTestCert(path string) ([]byte, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, err
	}
	return os.ReadFile(path)
}

