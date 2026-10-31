package crypto

import (
	"testing"
)

func TestGenerateDataEncryptionKey(t *testing.T) {
	tests := []struct {
		name      string
		keyLength int
	}{
		{"16 bytes", 16},
		{"32 bytes", 32},
		{"24 bytes", 24},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key1, err := GenerateDataEncryptionKey(tt.keyLength)
			if err != nil {
				t.Fatalf("GenerateDataEncryptionKey() error = %v", err)
			}
			if len(key1) != tt.keyLength {
				t.Errorf("GenerateDataEncryptionKey() length = %v, want %v", len(key1), tt.keyLength)
			}

			// Generate second key and verify they're different (randomness)
			key2, err := GenerateDataEncryptionKey(tt.keyLength)
			if err != nil {
				t.Fatalf("GenerateDataEncryptionKey() error = %v", err)
			}
			if len(key2) != tt.keyLength {
				t.Errorf("GenerateDataEncryptionKey() length = %v, want %v", len(key2), tt.keyLength)
			}

			// Keys should be different (very unlikely to be same with good RNG)
			if string(key1) == string(key2) {
				t.Error("GenerateDataEncryptionKey() generated identical keys (unlikely with good RNG)")
			}
		})
	}
}

func TestGenerateIV(t *testing.T) {
	tests := []struct {
		name     string
		ivLength int
	}{
		{"12 bytes (GCM)", 12},
		{"16 bytes (CBC)", 16},
		{"8 bytes", 8},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iv1, err := GenerateIV(tt.ivLength)
			if err != nil {
				t.Fatalf("GenerateIV() error = %v", err)
			}
			if len(iv1) != tt.ivLength {
				t.Errorf("GenerateIV() length = %v, want %v", len(iv1), tt.ivLength)
			}

			// Generate second IV and verify they're different (randomness)
			iv2, err := GenerateIV(tt.ivLength)
			if err != nil {
				t.Fatalf("GenerateIV() error = %v", err)
			}
			if len(iv2) != tt.ivLength {
				t.Errorf("GenerateIV() length = %v, want %v", len(iv2), tt.ivLength)
			}

			// IVs should be different (very unlikely to be same with good RNG)
			if string(iv1) == string(iv2) {
				t.Error("GenerateIV() generated identical IVs (unlikely with good RNG)")
			}
		})
	}
}
