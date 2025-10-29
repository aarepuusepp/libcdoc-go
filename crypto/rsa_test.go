package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// createTestRSACertificate creates a minimal RSA certificate for testing
func createTestRSACertificate(t *testing.T) *x509.Certificate {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test User",
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment,
		PublicKey:    privKey.Public(),
	}

	// Self-sign for testing
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}

func TestEncryptDecryptRSA(t *testing.T) {
	plaintext := []byte("Hello, World! This is a test message for RSA encryption.")

	// Generate RSA key pair
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Create certificate
	cert := createTestRSACertificate(t)
	cert.PublicKey = privKey.Public()

	// Encrypt
	ciphertext, err := EncryptRSA(plaintext, cert)
	if err != nil {
		t.Fatalf("EncryptRSA() error = %v", err)
	}

	if len(ciphertext) != 256 { // 2048-bit RSA = 256 bytes
		t.Errorf("EncryptRSA() ciphertext length = %v, want 256", len(ciphertext))
	}

	// Decrypt
	decrypted, err := DecryptRSA(ciphertext, privKey)
	if err != nil {
		t.Fatalf("DecryptRSA() error = %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("DecryptRSA() = %v, want %v", string(decrypted), string(plaintext))
	}
}

func TestEncryptRSA_LargePlaintext(t *testing.T) {
	// RSA PKCS#1 v1.5 can encrypt up to keySize - 11 bytes
	// For 2048-bit key, max is 245 bytes
	cert := createTestRSACertificate(t)

	tests := []struct {
		name      string
		plaintext []byte
		wantErr   bool
	}{
		{"max size (245 bytes)", make([]byte, 245), false},
		{"too large (246 bytes)", make([]byte, 246), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := EncryptRSA(tt.plaintext, cert)
			if (err != nil) != tt.wantErr {
				t.Errorf("EncryptRSA() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDecryptRSA_InvalidCiphertext(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	tests := []struct {
		name       string
		ciphertext []byte
		wantErr    bool
	}{
		{"empty", []byte{}, true},
		{"too short", []byte{1, 2, 3}, true},
		{"wrong length", make([]byte, 128), true}, // Should be 256 for 2048-bit key
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecryptRSA(tt.ciphertext, privKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecryptRSA() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

