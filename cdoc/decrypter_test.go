package cdoc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/aarepuusepp/libcdoc-go/v2/key"
)

// createTestRSAPrivateKey creates a minimal RSA private key for testing
func createTestRSAPrivateKey(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test RSA User",
		},
		NotBefore:          time.Now(),
		NotAfter:           time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:           x509.KeyUsageKeyEncipherment,
		PublicKey:          privKey.Public(),
		PublicKeyAlgorithm: x509.RSA,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return privKey, cert
}

// createTestECPrivateKey creates a minimal EC private key for testing
func createTestECPrivateKey(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate) {
	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate EC key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test EC User",
		},
		NotBefore:          time.Now(),
		NotAfter:           time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:           x509.KeyUsageKeyAgreement,
		PublicKey:          privKey.Public(),
		PublicKeyAlgorithm: x509.ECDSA,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return privKey, cert
}

func TestNewDecrypter(t *testing.T) {
	decrypter := NewDecrypter()
	if decrypter == nil {
		t.Fatal("NewDecrypter() returned nil")
	}
}

func TestDecrypter_validateParameters_NoCDOC(t *testing.T) {
	decrypter := NewDecrypter()
	privKey, _ := createTestRSAPrivateKey(t)
	decrypter.WithPrivateKey(&key.PrivateKey{Key: privKey})

	_, err := decrypter.Decrypt()
	if err == nil {
		t.Error("Decrypt() should fail when CDOC is not set")
	}
}

func TestDecrypter_validateParameters_NoPrivateKey(t *testing.T) {
	decrypter := NewDecrypter()
	decrypter.WithCDOC(strings.NewReader("<xml>test</xml>"))

	_, err := decrypter.Decrypt()
	if err == nil {
		t.Error("Decrypt() should fail when private key is not set")
	}
}

func TestDecrypter_EncryptDecryptRoundTrip_RSA(t *testing.T) {
	// Generate test key pair
	privKey, cert := createTestRSAPrivateKey(t)

	// Encrypt
	testContent := "Hello, World! This is a test message for round-trip encryption."
	testFileName := "test.txt"

	builder := NewBuilder()
	builder.Version(Version11)
	builder.WithDataFile(testFileName, strings.NewReader(testContent), int64(len(testContent)))

	if err := builder.WithRecipientCertificate(cert); err != nil {
		t.Fatalf("Failed to add recipient: %v", err)
	}

	var encryptedOutput bytes.Buffer
	if err := builder.BuildToWriter(&encryptedOutput); err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// Decrypt
	decrypter := NewDecrypter()
	decrypter.WithCDOC(bytes.NewReader(encryptedOutput.Bytes()))
	decrypter.WithPrivateKey(&key.PrivateKey{Key: privKey})

	decryptedFiles, err := decrypter.Decrypt()
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	if len(decryptedFiles) != 1 {
		t.Fatalf("Expected 1 decrypted file, got %d", len(decryptedFiles))
	}

	if decryptedFiles[0].Name != testFileName {
		t.Errorf("Expected filename %s, got %s", testFileName, decryptedFiles[0].Name)
	}

	decryptedContent := string(decryptedFiles[0].Content)
	if decryptedContent != testContent {
		t.Errorf("Decrypted content mismatch.\nExpected: %s\nGot: %s", testContent, decryptedContent)
	}
}

func TestDecrypter_EncryptDecryptRoundTrip_EC(t *testing.T) {
	// Generate test key pair
	privKey, cert := createTestECPrivateKey(t)

	// Encrypt
	testContent := "Hello, World! This is a test message for EC round-trip encryption."
	testFileName := "test_ec.txt"

	builder := NewBuilder()
	builder.Version(Version11)
	builder.WithDataFile(testFileName, strings.NewReader(testContent), int64(len(testContent)))

	if err := builder.WithRecipientCertificate(cert); err != nil {
		t.Fatalf("Failed to add EC recipient: %v", err)
	}

	var encryptedOutput bytes.Buffer
	if err := builder.BuildToWriter(&encryptedOutput); err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// Decrypt
	decrypter := NewDecrypter()
	decrypter.WithCDOC(bytes.NewReader(encryptedOutput.Bytes()))
	decrypter.WithPrivateKey(&key.PrivateKey{Key: privKey})

	decryptedFiles, err := decrypter.Decrypt()
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	if len(decryptedFiles) != 1 {
		t.Fatalf("Expected 1 decrypted file, got %d", len(decryptedFiles))
	}

	decryptedContent := string(decryptedFiles[0].Content)
	if decryptedContent != testContent {
		t.Errorf("Decrypted content mismatch.\nExpected: %s\nGot: %s", testContent, decryptedContent)
	}
}

func TestDecrypter_EncryptDecryptRoundTrip_CDOC10(t *testing.T) {
	// Generate test key pair
	privKey, cert := createTestRSAPrivateKey(t)

	// Encrypt
	testContent := "Hello, World! CDOC 1.0 test."
	testFileName := "test10.txt"

	builder := NewBuilder()
	builder.Version(Version10)
	builder.WithDataFile(testFileName, strings.NewReader(testContent), int64(len(testContent)))

	if err := builder.WithRecipientCertificate(cert); err != nil {
		t.Fatalf("Failed to add recipient: %v", err)
	}

	var encryptedOutput bytes.Buffer
	if err := builder.BuildToWriter(&encryptedOutput); err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// Decrypt
	decrypter := NewDecrypter()
	decrypter.WithCDOC(bytes.NewReader(encryptedOutput.Bytes()))
	decrypter.WithPrivateKey(&key.PrivateKey{Key: privKey})
	decrypter.WithCertificate(cert)

	decryptedFiles, err := decrypter.Decrypt()
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	if len(decryptedFiles) != 1 {
		t.Fatalf("Expected 1 decrypted file, got %d", len(decryptedFiles))
	}

	decryptedContent := string(decryptedFiles[0].Content)
	if decryptedContent != testContent {
		t.Errorf("Decrypted content mismatch.\nExpected: %s\nGot: %s", testContent, decryptedContent)
	}
}

func TestDecrypter_MultipleRecipients(t *testing.T) {
	// Create two certificates
	privKey1, cert1 := createTestRSAPrivateKey(t)
	privKey2, cert2 := createTestRSAPrivateKey(t)

	testContent := "Multiple recipients test"
	testFileName := "multi_test.txt"

	// Encrypt with both recipients
	builder := NewBuilder()
	builder.Version(Version11)
	builder.WithDataFile(testFileName, strings.NewReader(testContent), int64(len(testContent)))

	if err := builder.WithRecipientCertificate(cert1); err != nil {
		t.Fatalf("WithRecipientCertificate(cert1) failed: %v", err)
	}
	if err := builder.WithRecipientCertificate(cert2); err != nil {
		t.Fatalf("WithRecipientCertificate(cert2) failed: %v", err)
	}

	var encryptedOutput bytes.Buffer
	if err := builder.BuildToWriter(&encryptedOutput); err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// Decrypt with first recipient's key
	decrypter1 := NewDecrypter()
	decrypter1.WithCDOC(bytes.NewReader(encryptedOutput.Bytes()))
	decrypter1.WithPrivateKey(&key.PrivateKey{Key: privKey1})
	decrypter1.WithCertificate(cert1) // Specify certificate for selection

	decryptedFiles1, err := decrypter1.Decrypt()
	if err != nil {
		t.Fatalf("Failed to decrypt with first recipient: %v", err)
	}

	if string(decryptedFiles1[0].Content) != testContent {
		t.Error("Decryption with first recipient failed")
	}

	// Decrypt with second recipient's key
	decrypter2 := NewDecrypter()
	decrypter2.WithCDOC(bytes.NewReader(encryptedOutput.Bytes()))
	decrypter2.WithPrivateKey(&key.PrivateKey{Key: privKey2})
	decrypter2.WithCertificate(cert2) // Specify certificate for selection

	decryptedFiles2, err := decrypter2.Decrypt()
	if err != nil {
		t.Fatalf("Failed to decrypt with second recipient: %v", err)
	}

	if string(decryptedFiles2[0].Content) != testContent {
		t.Error("Decryption with second recipient failed")
	}
}

func TestDecrypter_EmptyContent(t *testing.T) {
	privKey, cert := createTestRSAPrivateKey(t)

	testContent := ""
	testFileName := "empty.txt"

	builder := NewBuilder()
	builder.Version(Version11)
	builder.WithDataFile(testFileName, strings.NewReader(testContent), 0)

	if err := builder.WithRecipientCertificate(cert); err != nil {
		t.Fatalf("Failed to add recipient: %v", err)
	}

	var encryptedOutput bytes.Buffer
	if err := builder.BuildToWriter(&encryptedOutput); err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	decrypter := NewDecrypter()
	decrypter.WithCDOC(bytes.NewReader(encryptedOutput.Bytes()))
	decrypter.WithPrivateKey(&key.PrivateKey{Key: privKey})

	decryptedFiles, err := decrypter.Decrypt()
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	if len(decryptedFiles) != 1 {
		t.Fatalf("Expected 1 decrypted file, got %d", len(decryptedFiles))
	}

	if len(decryptedFiles[0].Content) != 0 {
		t.Error("Decrypted empty file should have empty content")
	}
}

func TestDecrypter_LargeContent(t *testing.T) {
	privKey, cert := createTestRSAPrivateKey(t)

	// Create a larger test content (10KB)
	testContent := strings.Repeat("A", 10240)
	testFileName := "large.txt"

	builder := NewBuilder()
	builder.Version(Version11)
	builder.WithDataFile(testFileName, strings.NewReader(testContent), int64(len(testContent)))

	if err := builder.WithRecipientCertificate(cert); err != nil {
		t.Fatalf("Failed to add recipient: %v", err)
	}

	var encryptedOutput bytes.Buffer
	if err := builder.BuildToWriter(&encryptedOutput); err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	decrypter := NewDecrypter()
	decrypter.WithCDOC(bytes.NewReader(encryptedOutput.Bytes()))
	decrypter.WithPrivateKey(&key.PrivateKey{Key: privKey})

	decryptedFiles, err := decrypter.Decrypt()
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	if len(decryptedFiles) != 1 {
		t.Fatalf("Expected 1 decrypted file, got %d", len(decryptedFiles))
	}

	if string(decryptedFiles[0].Content) != testContent {
		t.Error("Large content decryption failed")
	}
}
