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

// TestDataFile is a helper struct for test data files
type TestDataFile struct {
	Name    string
	Content []byte
	Size    int64
}

// createTestRSACertWithKey creates RSA certificate and private key pair for testing
func createTestRSACertWithKey(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test RSA User",
		},
		NotBefore:         time.Now(),
		NotAfter:          time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:          x509.KeyUsageKeyEncipherment,
		PublicKey:         privKey.Public(),
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

// createTestECCertWithKey creates EC certificate and private key pair for testing
func createTestECCertWithKey(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate) {
	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate EC key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test EC User",
		},
		NotBefore:         time.Now(),
		NotAfter:          time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:          x509.KeyUsageKeyAgreement,
		PublicKey:         privKey.Public(),
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

// buildAndDecryptToMemory is similar to cdoc4j's pattern: encrypt with builder, decrypt immediately
// This tests the full round-trip: encryption → decryption
func buildAndDecryptToMemory(t *testing.T, version Version, cert *x509.Certificate, privKey interface{}, dataFiles ...TestDataFile) []DecryptedFile {
	builder := NewBuilder()
	builder.Version(version)

	// Add data files
	for _, df := range dataFiles {
		builder.WithDataFile(df.Name, bytes.NewReader(df.Content), df.Size)
	}

	// Add recipient
	if err := builder.WithRecipientCertificate(cert); err != nil {
		t.Fatalf("Failed to add recipient: %v", err)
	}

	// Encrypt
	var encryptedOutput bytes.Buffer
	if err := builder.BuildToWriter(&encryptedOutput); err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// Decrypt
	decrypter := NewDecrypter()
	decrypter.WithCDOC(bytes.NewReader(encryptedOutput.Bytes()))

	// Set private key
	var pk *key.PrivateKey
	switch k := privKey.(type) {
	case *rsa.PrivateKey:
		pk = &key.PrivateKey{Key: k}
	case *ecdsa.PrivateKey:
		pk = &key.PrivateKey{Key: k}
	default:
		t.Fatalf("Unsupported private key type: %T", privKey)
	}
	decrypter.WithPrivateKey(pk)
	decrypter.WithCertificate(cert) // For recipient selection

	decryptedFiles, err := decrypter.Decrypt()
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	return decryptedFiles
}

// TestGeneration_CDOC11_RSA_SingleFile tests CDOC 1.1 generation with RSA (similar to cdoc4j CDOC11BuilderTest)
func TestGeneration_CDOC11_RSA_SingleFile(t *testing.T) {
	privKey, cert := createTestRSACertWithKey(t)

	testContent := "test data content"
	testFileName := "test.txt"

	dataFile := TestDataFile{
		Name:    testFileName,
		Content: []byte(testContent),
		Size:    int64(len(testContent)),
	}

	decryptedFiles := buildAndDecryptToMemory(t, Version11, cert, privKey, dataFile)

	if len(decryptedFiles) != 1 {
		t.Fatalf("Expected 1 decrypted file, got %d", len(decryptedFiles))
	}

	if decryptedFiles[0].Name != testFileName {
		t.Errorf("Expected filename %s, got %s", testFileName, decryptedFiles[0].Name)
	}

	decryptedContent := string(decryptedFiles[0].Content)
	if decryptedContent != testContent {
		t.Errorf("Content mismatch.\nExpected: %s\nGot: %s", testContent, decryptedContent)
	}
}

// TestGeneration_CDOC11_EC_SingleFile tests CDOC 1.1 generation with EC (similar to cdoc4j CDOC11BuilderTest)
func TestGeneration_CDOC11_EC_SingleFile(t *testing.T) {
	privKey, cert := createTestECCertWithKey(t)

	testContent := "test data content"
	testFileName := "test.txt"

	dataFile := TestDataFile{
		Name:    testFileName,
		Content: []byte(testContent),
		Size:    int64(len(testContent)),
	}

	decryptedFiles := buildAndDecryptToMemory(t, Version11, cert, privKey, dataFile)

	if len(decryptedFiles) != 1 {
		t.Fatalf("Expected 1 decrypted file, got %d", len(decryptedFiles))
	}

	if decryptedFiles[0].Name != testFileName {
		t.Errorf("Expected filename %s, got %s", testFileName, decryptedFiles[0].Name)
	}

	decryptedContent := string(decryptedFiles[0].Content)
	if decryptedContent != testContent {
		t.Errorf("Content mismatch.\nExpected: %s\nGot: %s", testContent, decryptedContent)
	}
}

// TestGeneration_CDOC11_RSA_WithDDOC tests CDOC 1.1 generation with multiple files (DDOC pattern)
func TestGeneration_CDOC11_RSA_WithDDOC(t *testing.T) {
	privKey, cert := createTestRSACertWithKey(t)

	dataFiles := []TestDataFile{
		{
			Name:    "test.txt",
			Content: []byte("some test content"),
			Size:    int64(len("some test content")),
		},
		{
			Name:    "test.txt",
			Content: []byte("other test content"),
			Size:    int64(len("other test content")),
		},
	}

	decryptedFiles := buildAndDecryptToMemory(t, Version11, cert, privKey, dataFiles...)

	// With DDOC support, all files should be extracted
	if len(decryptedFiles) != len(dataFiles) {
		t.Fatalf("Expected %d decrypted files, got %d", len(dataFiles), len(decryptedFiles))
	}

	// Verify all files content matches
	for i := range dataFiles {
		if i < len(decryptedFiles) {
			decryptedContent := string(decryptedFiles[i].Content)
			expectedContent := string(dataFiles[i].Content)
			if decryptedContent != expectedContent {
				t.Errorf("File %d content mismatch.\nExpected: %s\nGot: %s", i, expectedContent, decryptedContent)
			}
			if decryptedFiles[i].Name != dataFiles[i].Name {
				t.Errorf("File %d name mismatch. Expected: %s, Got: %s", i, dataFiles[i].Name, decryptedFiles[i].Name)
			}
		}
	}
}

// TestGeneration_CDOC11_MultipleRecipients tests generation with multiple recipients
func TestGeneration_CDOC11_MultipleRecipients(t *testing.T) {
	privKey1, cert1 := createTestRSACertWithKey(t)
	privKey2, cert2 := createTestRSACertWithKey(t)

	testContent := "multiple recipients test"
	testFileName := "test.txt"

	// Encrypt with both recipients
	builder := NewBuilder()
	builder.Version(Version11)
	builder.WithDataFile(testFileName, strings.NewReader(testContent), int64(len(testContent)))

	if err := builder.WithRecipientCertificate(cert1); err != nil {
		t.Fatalf("Failed to add first recipient: %v", err)
	}
	if err := builder.WithRecipientCertificate(cert2); err != nil {
		t.Fatalf("Failed to add second recipient: %v", err)
	}

	var encryptedOutput bytes.Buffer
	if err := builder.BuildToWriter(&encryptedOutput); err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// Decrypt with first recipient
	decrypter1 := NewDecrypter()
	decrypter1.WithCDOC(bytes.NewReader(encryptedOutput.Bytes()))
	decrypter1.WithPrivateKey(&key.PrivateKey{Key: privKey1})
	decrypter1.WithCertificate(cert1)

	decryptedFiles1, err := decrypter1.Decrypt()
	if err != nil {
		t.Fatalf("Failed to decrypt with first recipient: %v", err)
	}

	if len(decryptedFiles1) != 1 {
		t.Fatalf("Expected 1 decrypted file, got %d", len(decryptedFiles1))
	}

	if string(decryptedFiles1[0].Content) != testContent {
		t.Error("Decryption with first recipient failed")
	}

	// Decrypt with second recipient
	decrypter2 := NewDecrypter()
	decrypter2.WithCDOC(bytes.NewReader(encryptedOutput.Bytes()))
	decrypter2.WithPrivateKey(&key.PrivateKey{Key: privKey2})
	decrypter2.WithCertificate(cert2)

	decryptedFiles2, err := decrypter2.Decrypt()
	if err != nil {
		t.Fatalf("Failed to decrypt with second recipient: %v", err)
	}

	if string(decryptedFiles2[0].Content) != testContent {
		t.Error("Decryption with second recipient failed")
	}
}

// TestGeneration_CDOC10_RSA_SingleFile tests CDOC 1.0 generation with RSA
func TestGeneration_CDOC10_RSA_SingleFile(t *testing.T) {
	privKey, cert := createTestRSACertWithKey(t)

	testContent := "test data content"
	testFileName := "test.txt"

	dataFile := TestDataFile{
		Name:    testFileName,
		Content: []byte(testContent),
		Size:    int64(len(testContent)),
	}

	decryptedFiles := buildAndDecryptToMemory(t, Version10, cert, privKey, dataFile)

	if len(decryptedFiles) != 1 {
		t.Fatalf("Expected 1 decrypted file, got %d", len(decryptedFiles))
	}

	if decryptedFiles[0].Name != testFileName {
		t.Errorf("Expected filename %s, got %s", testFileName, decryptedFiles[0].Name)
	}

	decryptedContent := string(decryptedFiles[0].Content)
	if decryptedContent != testContent {
		t.Errorf("Content mismatch.\nExpected: %s\nGot: %s", testContent, decryptedContent)
	}
}

// TestGeneration_CDOC11_EmptyFile tests encryption of empty file (similar to cdoc4j CDOC10BuilderTest.emptyFile)
func TestGeneration_CDOC11_EmptyFile(t *testing.T) {
	privKey, cert := createTestRSACertWithKey(t)

	dataFile := TestDataFile{
		Name:    "empty.txt",
		Content: []byte{},
		Size:    0,
	}

	decryptedFiles := buildAndDecryptToMemory(t, Version11, cert, privKey, dataFile)

	if len(decryptedFiles) != 1 {
		t.Fatalf("Expected 1 decrypted file, got %d", len(decryptedFiles))
	}

	if len(decryptedFiles[0].Content) != 0 {
		t.Error("Empty file should decrypt to empty content")
	}
}

// TestGeneration_BuilderValidation tests builder validation (similar to cdoc4j CDOC11BuilderTest validation tests)
func TestGeneration_BuilderValidation(t *testing.T) {
	t.Run("without recipient should fail", func(t *testing.T) {
		builder := NewBuilder()
		builder.Version(Version11)
		builder.WithDataFile("test.txt", strings.NewReader("content"), 7)

		var output bytes.Buffer
		err := builder.BuildToWriter(&output)
		if err == nil {
			t.Error("BuildToWriter() should fail when no recipients are set")
		}
	})

	t.Run("without data file should fail", func(t *testing.T) {
		_, cert := createTestRSACertWithKey(t)
		builder := NewBuilder()
		builder.Version(Version11)
		builder.WithRecipientCertificate(cert)

		var output bytes.Buffer
		err := builder.BuildToWriter(&output)
		if err == nil {
			t.Error("BuildToWriter() should fail when no data files are set")
		}
	})
}

// TestGeneration_OutputSize tests that output size is reasonable (similar to cdoc4j size assertions)
func TestGeneration_OutputSize(t *testing.T) {
	_, cert := createTestRSACertWithKey(t)

	testContent := "test data content"
	testFileName := "test.txt"

	builder := NewBuilder()
	builder.Version(Version11)
	builder.WithDataFile(testFileName, strings.NewReader(testContent), int64(len(testContent)))

	if err := builder.WithRecipientCertificate(cert); err != nil {
		t.Fatalf("Failed to add recipient: %v", err)
	}

	var output bytes.Buffer
	if err := builder.BuildToWriter(&output); err != nil {
		t.Fatalf("Failed to build: %v", err)
	}

	outputSize := output.Len()
	
	// Output should be larger than input (XML structure, encryption overhead, etc.)
	// CDOC format includes: XML structure, encrypted keys, IV, ciphertext, metadata
	// Typical overhead: 2-10x for small files (due to XML structure)
	// For 17 bytes of content, 2000-4000 bytes is reasonable
	if outputSize < len(testContent) {
		t.Errorf("Output size %d should be larger than input size %d", outputSize, len(testContent))
	}

	// More lenient check - allow up to 500x for very small files (XML overhead is proportionally larger)
	if outputSize > len(testContent)*500 {
		t.Errorf("Output size %d seems unreasonably large for input size %d (max expected: %d)", 
			outputSize, len(testContent), len(testContent)*500)
	}

	t.Logf("CDOC output size: %d bytes for %d bytes of content (overhead: %.1fx)", 
		outputSize, len(testContent), float64(outputSize)/float64(len(testContent)))
}

