package key

import (
	"encoding/pem"
	"testing"
)

func TestParsePrivateKeyPEM_Invalid(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"invalid PEM", []byte("not a PEM block")},
		{"wrong block type", pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: []byte{1, 2, 3},
		})},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParsePrivateKeyPEM(tt.data)
			if err == nil {
				t.Errorf("ParsePrivateKeyPEM() with %s should fail", tt.name)
			}
		})
	}
}

func TestParsePrivateKey_Invalid(t *testing.T) {
	_, err := ParsePrivateKey([]byte("invalid key data"))
	if err == nil {
		t.Error("ParsePrivateKey() with invalid data should fail")
	}
}

// Note: Full key parsing tests would require actual test keys from cdoc4j resources
// These are basic validation tests. Integration tests will use real key files.
