package cdoc

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"os"
	"strings"
	"testing"

	"github.com/yourorg/cdoc1-go/crypto"
	"github.com/yourorg/cdoc1-go/key"
	"software.sslmate.com/src/go-pkcs12"
)

// createTestPKCS12Keystore creates a test PKCS#12 keystore
func createTestPKCS12Keystore(t *testing.T, privKey *rsa.PrivateKey, cert *x509.Certificate, password string) []byte {
	p12Data, err := pkcs12.Encode(rand.Reader, privKey, cert, nil, password)
	if err != nil {
		t.Fatalf("Failed to create PKCS#12 keystore: %v", err)
	}
	return p12Data
}

func TestPKCS12Token_GetCertificate(t *testing.T) {
	privKey, cert := createTestRSACertWithKey(t)
	password := "test-password"
	p12Data := createTestPKCS12Keystore(t, privKey, cert, password)

	keyEntry, err := key.ParsePKCS12(p12Data, password)
	if err != nil {
		t.Fatalf("Failed to parse PKCS#12: %v", err)
	}

	token := NewPKCS12Token(keyEntry)
	retrievedCert, err := token.GetCertificate()
	if err != nil {
		t.Fatalf("GetCertificate() failed: %v", err)
	}

	if retrievedCert.Subject.CommonName != cert.Subject.CommonName {
		t.Errorf("Expected CN %s, got %s", cert.Subject.CommonName, retrievedCert.Subject.CommonName)
	}
}

func TestPKCS12Token_DecryptRSA(t *testing.T) {
	privKey, cert := createTestRSACertWithKey(t)
	password := "test-password"
	p12Data := createTestPKCS12Keystore(t, privKey, cert, password)

	keyEntry, err := key.ParsePKCS12(p12Data, password)
	if err != nil {
		t.Fatalf("Failed to parse PKCS#12: %v", err)
	}

	token := NewPKCS12Token(keyEntry)

	// Encrypt some test data
	testData := []byte("test encryption data")
	encrypted, err := crypto.EncryptRSA(testData, cert)
	if err != nil {
		t.Fatalf("Failed to encrypt test data: %v", err)
	}

	// Decrypt using token
	decrypted, err := token.DecryptRSA(encrypted)
	if err != nil {
		t.Fatalf("DecryptRSA() failed: %v", err)
	}

	if !bytes.Equal(decrypted, testData) {
		t.Errorf("Decrypted data mismatch. Expected %v, got %v", testData, decrypted)
	}
}

// TestDecrypter_WithPKCS12Token_RoundTrip tests round-trip encryption/decryption with PKCS#12 token
func TestDecrypter_WithPKCS12Token_RoundTrip(t *testing.T) {
	privKey, cert := createTestRSACertWithKey(t)
	password := "test-password-123"

	// Create PKCS#12 keystore
	p12Data := createTestPKCS12Keystore(t, privKey, cert, password)

	// Write PKCS#12 to temp file
	tmpFile, err := os.CreateTemp("", "test-pkcs12-*.p12")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	if _, err := tmpFile.Write(p12Data); err != nil {
		t.Fatalf("Failed to write PKCS#12 data: %v", err)
	}
	tmpFile.Close()

	// Encrypt a test file
	testContent := "test file content for PKCS#12 decryption"
	builder := NewBuilder()
	builder.Version(Version11)
	builder.WithDataFile("test.txt", strings.NewReader(testContent), int64(len(testContent)))
	builder.WithRecipientCertificate(cert)

	var encrypted bytes.Buffer
	if err := builder.BuildToWriter(&encrypted); err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// Decrypt using PKCS#12 token
	decrypter := NewDecrypter()
	decrypter.WithCDOC(bytes.NewReader(encrypted.Bytes()))
	if err := decrypter.WithPKCS12Token(tmpFile.Name(), password); err != nil {
		t.Fatalf("Failed to set PKCS#12 token: %v", err)
	}

	decryptedFiles, err := decrypter.Decrypt()
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	if len(decryptedFiles) != 1 {
		t.Fatalf("Expected 1 decrypted file, got %d", len(decryptedFiles))
	}

	if string(decryptedFiles[0].Content) != testContent {
		t.Errorf("Content mismatch. Expected %s, got %s", testContent, string(decryptedFiles[0].Content))
	}
}

