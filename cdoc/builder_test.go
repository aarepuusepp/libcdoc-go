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
			CommonName: "Test RSA User",
		},
		NotBefore:          time.Now(),
		NotAfter:           time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:           x509.KeyUsageKeyEncipherment,
		PublicKey:          privKey.Public(),
		PublicKeyAlgorithm: x509.RSA,
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

// createTestECCertificate creates a minimal EC certificate for testing (secp384r1)
func createTestECCertificate(t *testing.T) *x509.Certificate {
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

func TestNewBuilder(t *testing.T) {
	builder := NewBuilder()
	if builder == nil {
		t.Fatal("NewBuilder() returned nil")
	}
	if builder.version != Version11 {
		t.Errorf("Expected default version 1.1, got %v", builder.version)
	}
}

func TestBuilder_Version(t *testing.T) {
	builder := NewBuilder()
	builder.Version(Version10)
	if builder.version != Version10 {
		t.Errorf("Expected version 1.0, got %v", builder.version)
	}

	builder.Version(Version11)
	if builder.version != Version11 {
		t.Errorf("Expected version 1.1, got %v", builder.version)
	}
}

func TestBuilder_WithDataFile(t *testing.T) {
	builder := NewBuilder()
	testContent := "test content"
	reader := strings.NewReader(testContent)

	builder.WithDataFile("test.txt", reader, int64(len(testContent)))

	if len(builder.dataFiles) != 1 {
		t.Errorf("Expected 1 data file, got %d", len(builder.dataFiles))
	}

	if builder.dataFiles[0].Name != "test.txt" {
		t.Errorf("Expected file name 'test.txt', got '%s'", builder.dataFiles[0].Name)
	}

	if builder.dataFiles[0].Size != int64(len(testContent)) {
		t.Errorf("Expected file size %d, got %d", len(testContent), builder.dataFiles[0].Size)
	}
}

func TestBuilder_WithRecipientCertificate(t *testing.T) {
	builder := NewBuilder()
	cert := createTestRSACertificate(t)

	err := builder.WithRecipientCertificate(cert)
	if err != nil {
		t.Fatalf("WithRecipientCertificate() error = %v", err)
	}

	if len(builder.recipients) != 1 {
		t.Errorf("Expected 1 recipient, got %d", len(builder.recipients))
	}
}

func TestBuilder_WithRecipientCertificate_InvalidKeyUsage(t *testing.T) {
	builder := NewBuilder()

	// Create certificate without keyEncipherment
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := x509.Certificate{
		SerialNumber:       big.NewInt(1),
		Subject:            pkix.Name{CommonName: "Test"},
		NotBefore:          time.Now(),
		NotAfter:           time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:           x509.KeyUsageDigitalSignature, // Missing keyEncipherment
		PublicKey:          privKey.Public(),
		PublicKeyAlgorithm: x509.RSA,
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	cert, _ := x509.ParseCertificate(certDER)

	err := builder.WithRecipientCertificate(cert)
	if err == nil {
		t.Error("WithRecipientCertificate() should fail for certificate without keyEncipherment")
	}
}

func TestBuilder_validateParameters_NoDataFile(t *testing.T) {
	builder := NewBuilder()
	cert := createTestRSACertificate(t)
	if err := builder.WithRecipientCertificate(cert); err != nil {
		t.Fatalf("WithRecipientCertificate() failed: %v", err)
	}

	err := builder.validateParameters()
	if err == nil {
		t.Error("validateParameters() should fail when no data files are set")
	}
}

func TestBuilder_validateParameters_NoRecipient(t *testing.T) {
	builder := NewBuilder()
	builder.WithDataFile("test.txt", strings.NewReader("content"), 7)

	err := builder.validateParameters()
	if err == nil {
		t.Error("validateParameters() should fail when no recipients are set")
	}
}

func TestBuilder_BuildToWriter(t *testing.T) {
	builder := NewBuilder()
	builder.Version(Version11)
	builder.WithDataFile("test.txt", strings.NewReader("Hello, World!"), 13)

	cert := createTestRSACertificate(t)
	if err := builder.WithRecipientCertificate(cert); err != nil {
		t.Fatalf("Failed to add recipient: %v", err)
	}

	var output bytes.Buffer
	err := builder.BuildToWriter(&output)
	if err != nil {
		t.Fatalf("BuildToWriter() error = %v", err)
	}

	if output.Len() == 0 {
		t.Error("BuildToWriter() produced no output")
	}

	// Verify it's valid XML
	outputBytes := output.Bytes()
	if len(outputBytes) == 0 {
		t.Error("BuildToWriter() produced no output")
	}

	// Verify it contains EncryptedData
	if !bytes.Contains(outputBytes, []byte("EncryptedData")) {
		t.Error("BuildToWriter() output should contain EncryptedData element")
	}
}

func TestBuilder_BuildToWriter_CDOC10(t *testing.T) {
	builder := NewBuilder()
	builder.Version(Version10)
	builder.WithDataFile("test.txt", strings.NewReader("Hello, World!"), 13)

	cert := createTestRSACertificate(t)
	if err := builder.WithRecipientCertificate(cert); err != nil {
		t.Fatalf("Failed to add recipient: %v", err)
	}

	var output bytes.Buffer
	err := builder.BuildToWriter(&output)
	if err != nil {
		t.Fatalf("BuildToWriter() error = %v", err)
	}

	// Verify it's valid XML
	outputBytes := output.Bytes()
	if len(outputBytes) == 0 {
		t.Error("BuildToWriter() produced no output")
	}

	// Verify it contains EncryptedData
	if !bytes.Contains(outputBytes, []byte("EncryptedData")) {
		t.Error("BuildToWriter() output should contain EncryptedData element")
	}

	// Verify it uses AES-128-CBC (CDOC 1.0)
	if !bytes.Contains(outputBytes, []byte("aes128-cbc")) {
		t.Error("CDOC 1.0 should use aes128-cbc algorithm")
	}
}

func TestBuilder_BuildToWriter_ECRecipient(t *testing.T) {
	builder := NewBuilder()
	builder.Version(Version11)
	builder.WithDataFile("test.txt", strings.NewReader("Hello, World!"), 13)

	cert := createTestECCertificate(t)
	if err := builder.WithRecipientCertificate(cert); err != nil {
		t.Fatalf("Failed to add EC recipient: %v", err)
	}

	var output bytes.Buffer
	err := builder.BuildToWriter(&output)
	if err != nil {
		t.Fatalf("BuildToWriter() error = %v", err)
	}

	if output.Len() == 0 {
		t.Error("BuildToWriter() produced no output")
	}
}

func TestBuilder_BuildToWriter_MultipleRecipients(t *testing.T) {
	builder := NewBuilder()
	builder.Version(Version11)
	builder.WithDataFile("test.txt", strings.NewReader("Hello, World!"), 13)

	rsaCert := createTestRSACertificate(t)
	ecCert := createTestECCertificate(t)

	if err := builder.WithRecipientCertificate(rsaCert); err != nil {
		t.Fatalf("Failed to add RSA recipient: %v", err)
	}
	if err := builder.WithRecipientCertificate(ecCert); err != nil {
		t.Fatalf("Failed to add EC recipient: %v", err)
	}

	var output bytes.Buffer
	err := builder.BuildToWriter(&output)
	if err != nil {
		t.Fatalf("BuildToWriter() error = %v", err)
	}

	// Parse back to verify
	parser := NewParser()
	if err := parser.Parse(bytes.NewReader(output.Bytes())); err != nil {
		t.Fatalf("Failed to parse generated CDOC: %v", err)
	}

	recipients, err := parser.GetRecipients()
	if err != nil {
		t.Fatalf("Failed to get recipients: %v", err)
	}

	if len(recipients) != 2 {
		t.Errorf("Expected 2 recipients, got %d", len(recipients))
	}
}
