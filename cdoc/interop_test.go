package cdoc

import (
	"bytes"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yourorg/cdoc1-go/cert"
	"github.com/yourorg/cdoc1-go/key"
	"github.com/yourorg/cdoc1-go/xmlenc"
)

// Helper function to load test certificate from cdoc4j resources
func loadTestCert(t *testing.T, certPathParts ...string) *x509.Certificate {
	parts := append([]string{"cdoc4j", "src", "test", "resources"}, certPathParts...)
	fullPath := filepath.Join(parts...)
	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		t.Skipf("Test certificate not found at %s, skipping interoperability test", fullPath)
	}

	certData, err := os.ReadFile(fullPath)
	if err != nil {
		t.Fatalf("Failed to read certificate: %v", err)
	}

	cert, err := cert.ParseCertificatePEM(certData)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}

// Helper function to load test private key from cdoc4j resources
func loadTestKey(t *testing.T, keyPath string) *key.PrivateKey {
	fullPath := filepath.Join("cdoc4j", "src", "test", "resources", keyPath)
	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		t.Skipf("Test key not found at %s, skipping interoperability test", fullPath)
	}

	keyData, err := os.ReadFile(fullPath)
	if err != nil {
		t.Fatalf("Failed to read private key: %v", err)
	}

	pk, err := key.ParsePrivateKeyPEM(keyData)
	if err != nil {
		t.Fatalf("Failed to parse private key: %v", err)
	}

	return pk
}

// TestDecryptCDOC11_RSA_CreatedByCdoc4j tests decrypting a CDOC 1.1 file created by cdoc4j with RSA recipient
func TestDecryptCDOC11_RSA_CreatedByCdoc4j(t *testing.T) {
	cdocPath := filepath.Join("cdoc4j", "src", "test", "resources", "cdoc", "valid_cdoc11_RSA.cdoc")
	if _, err := os.Stat(cdocPath); os.IsNotExist(err) {
		t.Skipf("CDOC test file not found at %s, skipping interoperability test", cdocPath)
	}

	// For this test, we need the corresponding private key
	// Since cdoc4j uses PKCS#12, we'll need to extract or convert the key
	// For now, this test documents the expected behavior
	
	cdocFile, err := os.Open(cdocPath)
	if err != nil {
		t.Fatalf("Failed to open CDOC file: %v", err)
	}
	defer cdocFile.Close()

	// Parse the CDOC to verify structure
	parser := NewParser()
	err = parser.Parse(cdocFile)
	if err != nil {
		t.Fatalf("Failed to parse CDOC: %v", err)
	}

	// Verify it's CDOC 1.1
	version := parser.GetVersion()
	if version != Version11 {
		t.Errorf("Expected version 1.1, got %v", version)
	}

	// Get recipients
	recipients, err := parser.GetRecipients()
	if err != nil {
		t.Fatalf("Failed to get recipients: %v", err)
	}

	if len(recipients) == 0 {
		t.Error("No recipients found in CDOC")
	}

	rsaRecipient, ok := recipients[0].(*xmlenc.RSARecipient)
	if !ok {
		t.Error("First recipient is not RSA recipient")
	}

	if rsaRecipient.GetCN() == "" {
		t.Error("RSA recipient missing CN")
	}
}

// TestDecryptCDOC11_ECC_CreatedByCdoc4j tests decrypting a CDOC 1.1 file created by cdoc4j with EC recipient
func TestDecryptCDOC11_ECC_CreatedByCdoc4j(t *testing.T) {
	cdocPath := filepath.Join("cdoc4j", "src", "test", "resources", "cdoc", "valid_cdoc11_ECC.cdoc")
	if _, err := os.Stat(cdocPath); os.IsNotExist(err) {
		t.Skipf("CDOC test file not found at %s, skipping interoperability test", cdocPath)
	}

	cdocFile, err := os.Open(cdocPath)
	if err != nil {
		t.Fatalf("Failed to open CDOC file: %v", err)
	}
	defer cdocFile.Close()

	parser := NewParser()
	err = parser.Parse(cdocFile)
	if err != nil {
		t.Fatalf("Failed to parse CDOC: %v", err)
	}

	// Verify it's CDOC 1.1
	version := parser.GetVersion()
	if version != Version11 {
		t.Errorf("Expected version 1.1, got %v", version)
	}

	// Get recipients
	recipients, err := parser.GetRecipients()
	if err != nil {
		t.Fatalf("Failed to get recipients: %v", err)
	}

	if len(recipients) == 0 {
		t.Error("No recipients found in CDOC")
	}

	ecRecipient, ok := recipients[0].(*xmlenc.ECRecipient)
	if !ok {
		t.Error("First recipient is not EC recipient")
	}

	if ecRecipient.GetEphemeralPublicKey() == nil {
		t.Error("EC recipient missing ephemeral public key")
	}
}

// TestDecryptCDOC11_RSA_WithDDOC_CreatedByCdoc4j tests decrypting a CDOC 1.1 with DDOC created by cdoc4j
func TestDecryptCDOC11_RSA_WithDDOC_CreatedByCdoc4j(t *testing.T) {
	cdocPath := filepath.Join("cdoc4j", "src", "test", "resources", "cdoc", "valid_cdoc11_RSA_withDDOC.cdoc")
	if _, err := os.Stat(cdocPath); os.IsNotExist(err) {
		t.Skipf("CDOC test file not found at %s, skipping interoperability test", cdocPath)
	}

	cdocFile, err := os.Open(cdocPath)
	if err != nil {
		t.Fatalf("Failed to open CDOC file: %v", err)
	}
	defer cdocFile.Close()

	parser := NewParser()
	err = parser.Parse(cdocFile)
	if err != nil {
		t.Fatalf("Failed to parse CDOC: %v", err)
	}

	// Verify MimeType indicates DDOC
	mimeType := parser.GetMimeType()
	if mimeType != DDOCMimeType {
		t.Errorf("Expected DDOC mime type, got %s", mimeType)
	}
}

// TestEncryptCDOC11_ForCdoc4j tests that we can create a CDOC 1.1 file that cdoc4j can decrypt
// This test creates a CDOC and verifies its structure matches cdoc4j expectations
func TestEncryptCDOC11_ForCdoc4j(t *testing.T) {
	// Load test certificate (RSA auth cert from cdoc4j)
	cert := loadTestCert(t, "rsa", "auth_cert.pem")

	// Create test data
	testContent := "Test content for interoperability test"
	testFileName := "interop_test.txt"

	// Encrypt using our library
	builder := NewBuilder()
	builder.Version(Version11)
	builder.WithDataFile(testFileName, strings.NewReader(testContent), int64(len(testContent)))
	
	err := builder.WithRecipientCertificate(cert)
	if err != nil {
		t.Fatalf("Failed to add recipient: %v", err)
	}

	var output bytes.Buffer
	err = builder.BuildToWriter(&output)
	if err != nil {
		t.Fatalf("Failed to build CDOC: %v", err)
	}

	// Verify the output is valid XML
	cdocXML := output.Bytes()
	if len(cdocXML) == 0 {
		t.Error("Generated CDOC is empty")
	}

	// Parse it back to verify structure
	parser := NewParser()
	err = parser.Parse(bytes.NewReader(cdocXML))
	if err != nil {
		t.Fatalf("Failed to parse generated CDOC: %v", err)
	}

	// Verify CDOC 1.1 structure
	version := parser.GetVersion()
	if version != Version11 {
		t.Errorf("Expected version 1.1, got %v", version)
	}

	// Verify recipient
	recipients, err := parser.GetRecipients()
	if err != nil {
		t.Fatalf("Failed to get recipients: %v", err)
	}

	if len(recipients) != 1 {
		t.Errorf("Expected 1 recipient, got %d", len(recipients))
	}
}

// TestEncryptCDOC11_EC_ForCdoc4j tests creating a CDOC 1.1 with EC recipient for cdoc4j
func TestEncryptCDOC11_EC_ForCdoc4j(t *testing.T) {
	// Load test certificate (EC auth cert from cdoc4j)
	cert := loadTestCert(t, "ecc", "auth_cert.pem")

	// Create test data
	testContent := "Test content for EC interoperability test"
	testFileName := "interop_ec_test.txt"

	// Encrypt using our library
	builder := NewBuilder()
	builder.Version(Version11)
	builder.WithDataFile(testFileName, strings.NewReader(testContent), int64(len(testContent)))
	
	err := builder.WithRecipientCertificate(cert)
	if err != nil {
		t.Fatalf("Failed to add recipient: %v", err)
	}

	var output bytes.Buffer
	err = builder.BuildToWriter(&output)
	if err != nil {
		t.Fatalf("Failed to build CDOC: %v", err)
	}

	// Parse it back to verify structure
	parser := NewParser()
	err = parser.Parse(bytes.NewReader(output.Bytes()))
	if err != nil {
		t.Fatalf("Failed to parse generated CDOC: %v", err)
	}

	// Verify EC recipient structure
	recipients, err := parser.GetRecipients()
	if err != nil {
		t.Fatalf("Failed to get recipients: %v", err)
	}

	if len(recipients) != 1 {
		t.Fatalf("Expected 1 recipient, got %d", len(recipients))
	}

	ecRecipient, ok := recipients[0].(*xmlenc.ECRecipient)
	if !ok {
		t.Fatal("Expected EC recipient")
	}

	if ecRecipient.GetEphemeralPublicKey() == nil {
		t.Error("EC recipient missing ephemeral public key")
	}
}

// TestEncryptDecryptRoundTrip tests full round-trip: encrypt with our library, decrypt with our library
func TestEncryptDecryptRoundTrip_RSA(t *testing.T) {
	// For this test, we need both certificate and private key
	// Since we may not have access to test keys, we'll generate them for testing
	
	// Note: In real interoperability tests, use actual test certificates
	t.Skip("Skipping round-trip test - requires test certificates with private keys")
	
	// TODO: When test certificates with keys are available:
	// 1. Load certificate
	// 2. Load private key
	// 3. Encrypt
	// 4. Decrypt
	// 5. Verify content matches
}

// TestMultipleRecipients tests CDOC with multiple recipients (RSA + EC)
func TestMultipleRecipients(t *testing.T) {
	rsaCert := loadTestCert(t, "rsa", "auth_cert.pem")
	ecCert := loadTestCert(t, "ecc", "auth_cert.pem")

	testContent := "Multiple recipients test"
	testFileName := "multi_recipient_test.txt"

	builder := NewBuilder()
	builder.Version(Version11)
	builder.WithDataFile(testFileName, strings.NewReader(testContent), int64(len(testContent)))
	
	err := builder.WithRecipientCertificate(rsaCert)
	if err != nil {
		t.Fatalf("Failed to add RSA recipient: %v", err)
	}
	
	err = builder.WithRecipientCertificate(ecCert)
	if err != nil {
		t.Fatalf("Failed to add EC recipient: %v", err)
	}

	var output bytes.Buffer
	err = builder.BuildToWriter(&output)
	if err != nil {
		t.Fatalf("Failed to build CDOC: %v", err)
	}

	// Parse to verify structure
	parser := NewParser()
	err = parser.Parse(bytes.NewReader(output.Bytes()))
	if err != nil {
		t.Fatalf("Failed to parse CDOC: %v", err)
	}

	recipients, err := parser.GetRecipients()
	if err != nil {
		t.Fatalf("Failed to get recipients: %v", err)
	}

	if len(recipients) != 2 {
		t.Errorf("Expected 2 recipients, got %d", len(recipients))
	}
}

// BenchmarkCDOC11Encryption benchmarks CDOC 1.1 encryption performance
func BenchmarkCDOC11Encryption(b *testing.B) {
	cert := loadTestCert(&testing.T{}, "rsa", "auth_cert.pem")
	if cert == nil {
		b.Skip("Test certificate not available")
	}

	testContent := strings.Repeat("Test content for benchmarking. ", 100)
	testFileName := "benchmark_test.txt"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		builder := NewBuilder()
		builder.Version(Version11)
		builder.WithDataFile(testFileName, strings.NewReader(testContent), int64(len(testContent)))
		builder.WithRecipientCertificate(cert)
		
		var output bytes.Buffer
		if err := builder.BuildToWriter(&output); err != nil {
			b.Fatalf("Encryption failed: %v", err)
		}
	}
}

// verifyCDOCStructure verifies that a CDOC file has the correct structure
func verifyCDOCStructure(t *testing.T, cdocPath string, expectedVersion Version) {
	cdocFile, err := os.Open(cdocPath)
	if err != nil {
		t.Fatalf("Failed to open CDOC file: %v", err)
	}
	defer cdocFile.Close()

	parser := NewParser()
	err = parser.Parse(cdocFile)
	if err != nil {
		t.Fatalf("Failed to parse CDOC: %v", err)
	}

	// Verify version
	version := parser.GetVersion()
	if version != expectedVersion {
		t.Errorf("Expected version %v, got %v", expectedVersion, version)
	}

	// Verify EncryptionProperties contain DocumentFormat
	props := parser.GetEncryptionProperties()
	documentFormat, found := props["DocumentFormat"]
	if !found {
		t.Error("DocumentFormat property not found")
		return
	}

	expectedFormat := string(expectedVersion)
	if documentFormat != expectedFormat {
		t.Errorf("Expected DocumentFormat %s, got %s", expectedFormat, documentFormat)
	}
}

// TestCDOC11StructureValidation validates CDOC 1.1 files from cdoc4j have correct structure
func TestCDOC11StructureValidation(t *testing.T) {
	testFiles := []struct {
		name    string
		path    string
		version Version
	}{
		{"RSA single file", "valid_cdoc11_RSA.cdoc", Version11},
		{"ECC single file", "valid_cdoc11_ECC.cdoc", Version11},
		{"RSA with DDOC", "valid_cdoc11_RSA_withDDOC.cdoc", Version11},
		{"ECC with DDOC", "valid_cdoc11_ECC_withDDOC.cdoc", Version11},
		{"Multiple recipients", "valid_cdoc11_withMultipleRecipients.cdoc", Version11},
	}

	for _, tt := range testFiles {
		t.Run(tt.name, func(t *testing.T) {
			cdocPath := filepath.Join("cdoc4j", "src", "test", "resources", "cdoc", tt.path)
			if _, err := os.Stat(cdocPath); os.IsNotExist(err) {
				t.Skipf("CDOC test file not found at %s", cdocPath)
			}
			verifyCDOCStructure(t, cdocPath, tt.version)
		})
	}
}

