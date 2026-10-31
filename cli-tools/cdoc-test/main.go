package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/aarepuusepp/libcdoc-go/v2/cdoc"
	"github.com/aarepuusepp/libcdoc-go/v2/cert"
)

const (
	rsaCertPath  = "../../testdata/rsa/auth_cert.pem"
	eccCertPath  = "../../testdata/ecc/auth_cert.pem"
	rsaP12Path   = "../../testdata/rsa/rsa.p12"
	eccP12Path   = "../../testdata/ecc/ecc.p12"
	p12Password  = "test"
	testPDFPath  = "../../testdata/samples/TEST-öäüõÖÄÜÕžšŽŠ-01.pdf"
	testDOCXPath = "../../testdata/samples/TEST-öäüõÖÄÜÕžšŽŠ-01.docx"
)

func main() {
	fmt.Println("=== libcdoc-go Test Application ===")
	fmt.Println("Testing CDOC 1.1 and 2.0 encryption and decryption with test data\n")

	// Verify test files exist
	if err := verifyTestFiles(); err != nil {
		log.Fatalf("✗ Test file verification failed: %v\n", err)
	}

	// Test 1: Encrypt with RSA certificate
	fmt.Println("=" + repeatChar("=", 60))
	fmt.Println("Test 1: Encrypt PDF with RSA certificate (CDOC 1.1)")
	fmt.Println("=" + repeatChar("=", 60))
	rsaCDOCPath, err := encryptWithRSA()
	if err != nil {
		log.Fatalf("✗ RSA encryption failed: %v\n", err)
	}
	fmt.Printf("✓ RSA encryption successful: %s\n\n", rsaCDOCPath)

	// Test 2: Decrypt RSA CDOC
	fmt.Println("=" + repeatChar("=", 60))
	fmt.Println("Test 2: Decrypt RSA CDOC with PKCS12 keystore")
	fmt.Println("=" + repeatChar("=", 60))
	rsaOutputDir := getDecryptFolderName(rsaCDOCPath)
	if err := decryptWithPKCS12(rsaCDOCPath, rsaP12Path, rsaOutputDir); err != nil {
		log.Fatalf("✗ RSA decryption failed: %v\n", err)
	}
	fmt.Printf("✓ RSA decryption successful: %s\n\n", rsaOutputDir)

	// Test 3: Encrypt with ECC certificate
	fmt.Println("=" + repeatChar("=", 60))
	fmt.Println("Test 3: Encrypt PDF with ECC certificate (CDOC 1.1)")
	fmt.Println("=" + repeatChar("=", 60))
	eccCDOCPath, err := encryptWithECC()
	if err != nil {
		log.Fatalf("✗ ECC encryption failed: %v\n", err)
	}
	fmt.Printf("✓ ECC encryption successful: %s\n\n", eccCDOCPath)

	// Test 4: Decrypt ECC CDOC
	fmt.Println("=" + repeatChar("=", 60))
	fmt.Println("Test 4: Decrypt ECC CDOC with PKCS12 keystore")
	fmt.Println("=" + repeatChar("=", 60))
	eccOutputDir := getDecryptFolderName(eccCDOCPath)
	if err := decryptWithPKCS12(eccCDOCPath, eccP12Path, eccOutputDir); err != nil {
		log.Fatalf("✗ ECC decryption failed: %v\n", err)
	}
	fmt.Printf("✓ ECC decryption successful: %s\n\n", eccOutputDir)

	// Test 5: Encrypt with multiple recipients (RSA + ECC) - single file
	fmt.Println("=" + repeatChar("=", 60))
	fmt.Println("Test 5: Encrypt PDF with multiple recipients (RSA + ECC)")
	fmt.Println("=" + repeatChar("=", 60))
	multiCDOCPath, err := encryptWithMultipleRecipients()
	if err != nil {
		log.Fatalf("✗ Multiple recipients encryption failed: %v\n", err)
	}
	fmt.Printf("✓ Multiple recipients encryption successful: %s\n\n", multiCDOCPath)

	// Test 5b: Decrypt multiple recipients CDOC with RSA keystore
	fmt.Println("=" + repeatChar("=", 60))
	fmt.Println("Test 5b: Decrypt multiple recipients CDOC with RSA PKCS12 keystore")
	fmt.Println("=" + repeatChar("=", 60))
	multiRSADecryptDir := getDecryptFolderNameWithSuffix(multiCDOCPath, "_RSA")
	if err := decryptWithPKCS12(multiCDOCPath, rsaP12Path, multiRSADecryptDir); err != nil {
		log.Fatalf("✗ Multiple recipients decryption with RSA failed: %v\n", err)
	}
	fmt.Printf("✓ Multiple recipients decryption with RSA successful: %s\n\n", multiRSADecryptDir)

	// Test 5c: Decrypt multiple recipients CDOC with ECC keystore
	fmt.Println("=" + repeatChar("=", 60))
	fmt.Println("Test 5c: Decrypt multiple recipients CDOC with ECC PKCS12 keystore")
	fmt.Println("=" + repeatChar("=", 60))
	multiECCDecryptDir := getDecryptFolderNameWithSuffix(multiCDOCPath, "_ECC")
	if err := decryptWithPKCS12(multiCDOCPath, eccP12Path, multiECCDecryptDir); err != nil {
		log.Fatalf("✗ Multiple recipients decryption with ECC failed: %v\n", err)
	}
	fmt.Printf("✓ Multiple recipients decryption with ECC successful: %s\n\n", multiECCDecryptDir)

	// Test 6: Encrypt multiple files (PDF + DOCX) with RSA certificate
	fmt.Println("=" + repeatChar("=", 60))
	fmt.Println("Test 6: Encrypt multiple files (PDF + DOCX) with RSA certificate")
	fmt.Println("=" + repeatChar("=", 60))
	multiFileCDOCPath, err := encryptMultipleFilesWithRSA()
	if err != nil {
		log.Fatalf("✗ Multiple files encryption failed: %v\n", err)
	}
	fmt.Printf("✓ Multiple files encryption successful: %s\n\n", multiFileCDOCPath)

	// Test 7: Decrypt multiple files CDOC
	fmt.Println("=" + repeatChar("=", 60))
	fmt.Println("Test 7: Decrypt multiple files CDOC with PKCS12 keystore")
	fmt.Println("=" + repeatChar("=", 60))
	multiFileOutputDir := getDecryptFolderName(multiFileCDOCPath)
	if err := decryptWithPKCS12(multiFileCDOCPath, rsaP12Path, multiFileOutputDir); err != nil {
		log.Fatalf("✗ Multiple files decryption failed: %v\n", err)
	}
	fmt.Printf("✓ Multiple files decryption successful: %s\n\n", multiFileOutputDir)

	// Test 8: Encrypt multiple files with multiple recipients
	fmt.Println("=" + repeatChar("=", 60))
	fmt.Println("Test 8: Encrypt multiple files with multiple recipients (RSA + ECC)")
	fmt.Println("=" + repeatChar("=", 60))
	multiFileMultiRecipientCDOCPath, err := encryptMultipleFilesWithMultipleRecipients()
	if err != nil {
		log.Fatalf("✗ Multiple files with multiple recipients encryption failed: %v\n", err)
	}
	fmt.Printf("✓ Multiple files with multiple recipients encryption successful: %s\n\n", multiFileMultiRecipientCDOCPath)

	// Test 8b: Decrypt multiple files with multiple recipients CDOC with RSA keystore
	fmt.Println("=" + repeatChar("=", 60))
	fmt.Println("Test 8b: Decrypt multiple files with multiple recipients CDOC (RSA keystore)")
	fmt.Println("=" + repeatChar("=", 60))
	multiFileMultiRecipientRSADir := getDecryptFolderNameWithSuffix(multiFileMultiRecipientCDOCPath, "_RSA")
	if err := decryptWithPKCS12(multiFileMultiRecipientCDOCPath, rsaP12Path, multiFileMultiRecipientRSADir); err != nil {
		log.Fatalf("✗ Multiple files with multiple recipients decryption with RSA failed: %v\n", err)
	}
	fmt.Printf("✓ Multiple files with multiple recipients decryption with RSA successful: %s\n\n", multiFileMultiRecipientRSADir)

	// Test 8c: Decrypt multiple files with multiple recipients CDOC with ECC keystore
	fmt.Println("=" + repeatChar("=", 60))
	fmt.Println("Test 8c: Decrypt multiple files with multiple recipients CDOC (ECC keystore)")
	fmt.Println("=" + repeatChar("=", 60))
	multiFileMultiRecipientECCDir := getDecryptFolderNameWithSuffix(multiFileMultiRecipientCDOCPath, "_ECC")
	if err := decryptWithPKCS12(multiFileMultiRecipientCDOCPath, eccP12Path, multiFileMultiRecipientECCDir); err != nil {
		log.Fatalf("✗ Multiple files with multiple recipients decryption with ECC failed: %v\n", err)
	}
	fmt.Printf("✓ Multiple files with multiple recipients decryption with ECC successful: %s\n\n", multiFileMultiRecipientECCDir)

	// Test 9: Encrypt with RSA certificate (CDOC 2.0)
	fmt.Println("=" + repeatChar("=", 60))
	fmt.Println("Test 9: Encrypt PDF with RSA certificate (CDOC 2.0)")
	fmt.Println("=" + repeatChar("=", 60))
	rsaCDOC2Path, err := encryptWithRSA_CDOC2()
	if err != nil {
		log.Fatalf("✗ RSA CDOC 2.0 encryption failed: %v\n", err)
	}
	fmt.Printf("✓ RSA CDOC 2.0 encryption successful: %s\n\n", rsaCDOC2Path)

	// Test 10: Decrypt RSA CDOC 2.0
	fmt.Println("=" + repeatChar("=", 60))
	fmt.Println("Test 10: Decrypt RSA CDOC 2.0 with PKCS12 keystore")
	fmt.Println("=" + repeatChar("=", 60))
	rsaCDOC2OutputDir := getDecryptFolderName(rsaCDOC2Path)
	if err := decryptWithPKCS12(rsaCDOC2Path, rsaP12Path, rsaCDOC2OutputDir); err != nil {
		log.Fatalf("✗ RSA CDOC 2.0 decryption failed: %v\n", err)
	}
	fmt.Printf("✓ RSA CDOC 2.0 decryption successful: %s\n\n", rsaCDOC2OutputDir)

	// Test 11: Encrypt with ECC certificate (CDOC 2.0)
	fmt.Println("=" + repeatChar("=", 60))
	fmt.Println("Test 11: Encrypt PDF with ECC certificate (CDOC 2.0)")
	fmt.Println("=" + repeatChar("=", 60))
	eccCDOC2Path, err := encryptWithECC_CDOC2()
	if err != nil {
		log.Fatalf("✗ ECC CDOC 2.0 encryption failed: %v\n", err)
	}
	fmt.Printf("✓ ECC CDOC 2.0 encryption successful: %s\n\n", eccCDOC2Path)

	// Test 12: Decrypt ECC CDOC 2.0
	fmt.Println("=" + repeatChar("=", 60))
	fmt.Println("Test 12: Decrypt ECC CDOC 2.0 with PKCS12 keystore")
	fmt.Println("=" + repeatChar("=", 60))
	eccCDOC2OutputDir := getDecryptFolderName(eccCDOC2Path)
	if err := decryptWithPKCS12(eccCDOC2Path, eccP12Path, eccCDOC2OutputDir); err != nil {
		log.Fatalf("✗ ECC CDOC 2.0 decryption failed: %v\n", err)
	}
	fmt.Printf("✓ ECC CDOC 2.0 decryption successful: %s\n\n", eccCDOC2OutputDir)

	// Test 13: Encrypt with password (CDOC 2.0)
	fmt.Println("=" + repeatChar("=", 60))
	fmt.Println("Test 13: Encrypt PDF with password (CDOC 2.0)")
	fmt.Println("=" + repeatChar("=", 60))
	passwordCDOC2Path, err := encryptWithPassword_CDOC2()
	if err != nil {
		log.Fatalf("✗ Password CDOC 2.0 encryption failed: %v\n", err)
	}
	fmt.Printf("✓ Password CDOC 2.0 encryption successful: %s\n\n", passwordCDOC2Path)

	// Test 14: Decrypt password CDOC 2.0
	fmt.Println("=" + repeatChar("=", 60))
	fmt.Println("Test 14: Decrypt password CDOC 2.0")
	fmt.Println("=" + repeatChar("=", 60))
	passwordCDOC2OutputDir := getDecryptFolderName(passwordCDOC2Path)
	if err := decryptWithPassword_CDOC2(passwordCDOC2Path, passwordCDOC2OutputDir); err != nil {
		log.Fatalf("✗ Password CDOC 2.0 decryption failed: %v\n", err)
	}
	fmt.Printf("✓ Password CDOC 2.0 decryption successful: %s\n\n", passwordCDOC2OutputDir)

	// Test 15: Encrypt multiple files with RSA (CDOC 2.0)
	fmt.Println("=" + repeatChar("=", 60))
	fmt.Println("Test 15: Encrypt multiple files (PDF + DOCX) with RSA certificate (CDOC 2.0)")
	fmt.Println("=" + repeatChar("=", 60))
	multiFileRSA_CDOC2Path, err := encryptMultipleFilesWithRSA_CDOC2()
	if err != nil {
		log.Fatalf("✗ Multiple files RSA CDOC 2.0 encryption failed: %v\n", err)
	}
	fmt.Printf("✓ Multiple files RSA CDOC 2.0 encryption successful: %s\n\n", multiFileRSA_CDOC2Path)

	// Test 16: Decrypt multiple files RSA CDOC 2.0
	fmt.Println("=" + repeatChar("=", 60))
	fmt.Println("Test 16: Decrypt multiple files RSA CDOC 2.0 with PKCS12 keystore")
	fmt.Println("=" + repeatChar("=", 60))
	multiFileRSA_CDOC2OutputDir := getDecryptFolderName(multiFileRSA_CDOC2Path)
	if err := decryptWithPKCS12(multiFileRSA_CDOC2Path, rsaP12Path, multiFileRSA_CDOC2OutputDir); err != nil {
		log.Fatalf("✗ Multiple files RSA CDOC 2.0 decryption failed: %v\n", err)
	}
	fmt.Printf("✓ Multiple files RSA CDOC 2.0 decryption successful: %s\n\n", multiFileRSA_CDOC2OutputDir)

	fmt.Println("=" + repeatChar("=", 60))
	fmt.Println("=== All tests passed! Library is working correctly on Windows. ===")
	fmt.Println("=" + repeatChar("=", 60))
}

func verifyTestFiles() error {
	files := []string{rsaCertPath, eccCertPath, rsaP12Path, eccP12Path, testPDFPath, testDOCXPath}
	for _, file := range files {
		if _, err := os.Stat(file); os.IsNotExist(err) {
			return fmt.Errorf("test file not found: %s", file)
		}
	}
	fmt.Println("✓ All test files verified\n")
	return nil
}

func encryptWithRSA() (string, error) {
	// Load RSA certificate
	certData, err := os.ReadFile(rsaCertPath)
	if err != nil {
		return "", fmt.Errorf("failed to read RSA certificate: %w", err)
	}

	certificate, err := cert.ParseCertificatePEM(certData)
	if err != nil {
		return "", fmt.Errorf("failed to parse RSA certificate: %w", err)
	}
	fmt.Printf("✓ Loaded RSA certificate: %s\n", certificate.Subject.String())

	// Create builder with CDOC 1.1
	builder := cdoc.NewBuilder()
	builder.Version(cdoc.Version11)

	if err := builder.WithRecipientCertificate(certificate); err != nil {
		return "", fmt.Errorf("failed to add RSA recipient: %w", err)
	}
	fmt.Println("✓ Added RSA recipient to builder")

	// Add PDF file
	if err := addDataFile(builder, testPDFPath); err != nil {
		return "", fmt.Errorf("failed to add data file: %w", err)
	}

	// Build CDOC
	outputPath := "./TEST_RSA_encrypted.cdoc"
	if err := buildCDOC(builder, outputPath); err != nil {
		return "", err
	}

	return outputPath, nil
}

func encryptWithECC() (string, error) {
	// Load ECC certificate
	certData, err := os.ReadFile(eccCertPath)
	if err != nil {
		return "", fmt.Errorf("failed to read ECC certificate: %w", err)
	}

	certificate, err := cert.ParseCertificatePEM(certData)
	if err != nil {
		return "", fmt.Errorf("failed to parse ECC certificate: %w", err)
	}
	fmt.Printf("✓ Loaded ECC certificate: %s\n", certificate.Subject.String())

	// Create builder with CDOC 1.1
	builder := cdoc.NewBuilder()
	builder.Version(cdoc.Version11)

	if err := builder.WithRecipientCertificate(certificate); err != nil {
		return "", fmt.Errorf("failed to add ECC recipient: %w", err)
	}
	fmt.Println("✓ Added ECC recipient to builder")

	// Add PDF file
	if err := addDataFile(builder, testPDFPath); err != nil {
		return "", fmt.Errorf("failed to add data file: %w", err)
	}

	// Build CDOC
	outputPath := "./TEST_ECC_encrypted.cdoc"
	if err := buildCDOC(builder, outputPath); err != nil {
		return "", err
	}

	return outputPath, nil
}

func encryptWithMultipleRecipients() (string, error) {
	// Load RSA certificate
	rsaCertData, err := os.ReadFile(rsaCertPath)
	if err != nil {
		return "", fmt.Errorf("failed to read RSA certificate: %w", err)
	}
	rsaCert, err := cert.ParseCertificatePEM(rsaCertData)
	if err != nil {
		return "", fmt.Errorf("failed to parse RSA certificate: %w", err)
	}
	fmt.Printf("✓ Loaded RSA certificate: %s\n", rsaCert.Subject.String())

	// Load ECC certificate
	eccCertData, err := os.ReadFile(eccCertPath)
	if err != nil {
		return "", fmt.Errorf("failed to read ECC certificate: %w", err)
	}
	eccCert, err := cert.ParseCertificatePEM(eccCertData)
	if err != nil {
		return "", fmt.Errorf("failed to parse ECC certificate: %w", err)
	}
	fmt.Printf("✓ Loaded ECC certificate: %s\n", eccCert.Subject.String())

	// Create builder with CDOC 1.1
	builder := cdoc.NewBuilder()
	builder.Version(cdoc.Version11)

	// Add both recipients
	if err := builder.WithRecipientCertificate(rsaCert); err != nil {
		return "", fmt.Errorf("failed to add RSA recipient: %w", err)
	}
	fmt.Println("✓ Added RSA recipient")

	if err := builder.WithRecipientCertificate(eccCert); err != nil {
		return "", fmt.Errorf("failed to add ECC recipient: %w", err)
	}
	fmt.Println("✓ Added ECC recipient")

	// Add PDF file
	if err := addDataFile(builder, testPDFPath); err != nil {
		return "", fmt.Errorf("failed to add data file: %w", err)
	}

	// Build CDOC
	outputPath := "./TEST_MULTI_encrypted.cdoc"
	if err := buildCDOC(builder, outputPath); err != nil {
		return "", err
	}

	return outputPath, nil
}

func encryptMultipleFilesWithRSA() (string, error) {
	// Load RSA certificate
	certData, err := os.ReadFile(rsaCertPath)
	if err != nil {
		return "", fmt.Errorf("failed to read RSA certificate: %w", err)
	}

	certificate, err := cert.ParseCertificatePEM(certData)
	if err != nil {
		return "", fmt.Errorf("failed to parse RSA certificate: %w", err)
	}
	fmt.Printf("✓ Loaded RSA certificate: %s\n", certificate.Subject.String())

	// Create builder with CDOC 1.1
	builder := cdoc.NewBuilder()
	builder.Version(cdoc.Version11)

	if err := builder.WithRecipientCertificate(certificate); err != nil {
		return "", fmt.Errorf("failed to add RSA recipient: %w", err)
	}
	fmt.Println("✓ Added RSA recipient to builder")

	// Add both PDF and DOCX files
	if err := addDataFile(builder, testPDFPath); err != nil {
		return "", fmt.Errorf("failed to add PDF file: %w", err)
	}

	if err := addDataFile(builder, testDOCXPath); err != nil {
		return "", fmt.Errorf("failed to add DOCX file: %w", err)
	}

	// Build CDOC
	outputPath := "./TEST_MULTIPLE_FILES_RSA_encrypted.cdoc"
	if err := buildCDOC(builder, outputPath); err != nil {
		return "", err
	}

	return outputPath, nil
}

func encryptMultipleFilesWithMultipleRecipients() (string, error) {
	// Load RSA certificate
	rsaCertData, err := os.ReadFile(rsaCertPath)
	if err != nil {
		return "", fmt.Errorf("failed to read RSA certificate: %w", err)
	}
	rsaCert, err := cert.ParseCertificatePEM(rsaCertData)
	if err != nil {
		return "", fmt.Errorf("failed to parse RSA certificate: %w", err)
	}
	fmt.Printf("✓ Loaded RSA certificate: %s\n", rsaCert.Subject.String())

	// Load ECC certificate
	eccCertData, err := os.ReadFile(eccCertPath)
	if err != nil {
		return "", fmt.Errorf("failed to read ECC certificate: %w", err)
	}
	eccCert, err := cert.ParseCertificatePEM(eccCertData)
	if err != nil {
		return "", fmt.Errorf("failed to parse ECC certificate: %w", err)
	}
	fmt.Printf("✓ Loaded ECC certificate: %s\n", eccCert.Subject.String())

	// Create builder with CDOC 1.1
	builder := cdoc.NewBuilder()
	builder.Version(cdoc.Version11)

	// Add both recipients
	if err := builder.WithRecipientCertificate(rsaCert); err != nil {
		return "", fmt.Errorf("failed to add RSA recipient: %w", err)
	}
	fmt.Println("✓ Added RSA recipient")

	if err := builder.WithRecipientCertificate(eccCert); err != nil {
		return "", fmt.Errorf("failed to add ECC recipient: %w", err)
	}
	fmt.Println("✓ Added ECC recipient")

	// Add both PDF and DOCX files
	if err := addDataFile(builder, testPDFPath); err != nil {
		return "", fmt.Errorf("failed to add PDF file: %w", err)
	}

	if err := addDataFile(builder, testDOCXPath); err != nil {
		return "", fmt.Errorf("failed to add DOCX file: %w", err)
	}

	// Build CDOC
	outputPath := "./TEST_MULTIPLE_FILES_MULTI_encrypted.cdoc"
	if err := buildCDOC(builder, outputPath); err != nil {
		return "", err
	}

	return outputPath, nil
}

func addDataFile(builder *cdoc.Builder, filePath string) error {
	// Read file content into memory to avoid closing file before builder reads it
	fileContent, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Get file info for name and size
	info, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("failed to get file info: %w", err)
	}

	// Create a bytes.Reader from the file content (doesn't need closing)
	reader := bytes.NewReader(fileContent)
	builder.WithDataFile(info.Name(), reader, info.Size())
	fmt.Printf("✓ Added data file: %s (%d bytes)\n", info.Name(), info.Size())
	return nil
}

func buildCDOC(builder *cdoc.Builder, outputPath string) error {
	outputFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outputFile.Close()

	if err := builder.BuildToWriter(outputFile); err != nil {
		return fmt.Errorf("failed to build CDOC: %w", err)
	}

	// Get file size for verification
	if info, err := os.Stat(outputPath); err == nil {
		fmt.Printf("✓ CDOC file created: %s (%d bytes)\n", outputPath, info.Size())
	}

	return nil
}

func decryptWithPKCS12(cdocPath, p12Path, outputDir string) error {
	// Create decrypter
	decrypter := cdoc.NewDecrypter()

	// Load CDOC file
	if err := decrypter.WithCDOCFromFile(cdocPath); err != nil {
		return fmt.Errorf("failed to load CDOC file: %w", err)
	}
	fmt.Printf("✓ Loaded CDOC file: %s\n", cdocPath)

	// Load PKCS12 token
	if err := decrypter.WithPKCS12Token(p12Path, p12Password); err != nil {
		return fmt.Errorf("failed to load PKCS12 token: %w", err)
	}
	fmt.Printf("✓ Loaded PKCS12 token: %s\n", p12Path)

	// Decrypt
	decryptedFiles, err := decrypter.Decrypt()
	if err != nil {
		return fmt.Errorf("failed to decrypt: %w", err)
	}
	fmt.Printf("✓ Decrypted %d file(s)\n", len(decryptedFiles))

	// Ensure output directory exists
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Write decrypted files
	for _, decryptedFile := range decryptedFiles {
		outputPath := filepath.Join(outputDir, decryptedFile.Name)
		if err := os.WriteFile(outputPath, decryptedFile.Content, 0644); err != nil {
			return fmt.Errorf("failed to write decrypted file: %w", err)
		}
		fmt.Printf("✓ Wrote decrypted file: %s (%d bytes)\n", outputPath, len(decryptedFile.Content))
	}

	return nil
}

func getDecryptFolderName(cdocPath string) string {
	// Extract filename without extension and create folder name
	baseName := filepath.Base(cdocPath)
	ext := filepath.Ext(baseName)
	nameWithoutExt := baseName[:len(baseName)-len(ext)]

	// Add _CDOC2 suffix for CDOC 2.0 files to avoid overwriting CDOC 1.x folders
	if ext == ".cdoc2" {
		return "./decrypted_" + nameWithoutExt + "_CDOC2"
	}
	return "./decrypted_" + nameWithoutExt
}

func getDecryptFolderNameWithSuffix(cdocPath string, suffix string) string {
	// Extract filename without extension, add suffix, and create folder name
	baseName := filepath.Base(cdocPath)
	nameWithoutExt := baseName[:len(baseName)-len(filepath.Ext(baseName))]
	return "./decrypted_" + nameWithoutExt + suffix
}

func encryptWithRSA_CDOC2() (string, error) {
	// Load RSA certificate
	certData, err := os.ReadFile(rsaCertPath)
	if err != nil {
		return "", fmt.Errorf("failed to read RSA certificate: %w", err)
	}

	certificate, err := cert.ParseCertificatePEM(certData)
	if err != nil {
		return "", fmt.Errorf("failed to parse RSA certificate: %w", err)
	}
	fmt.Printf("✓ Loaded RSA certificate: %s\n", certificate.Subject.String())

	// Create builder with CDOC 2.0
	builder := cdoc.NewBuilder()
	builder.Version(cdoc.Version20)

	if err := builder.WithRecipientCertificate(certificate); err != nil {
		return "", fmt.Errorf("failed to add RSA recipient: %w", err)
	}
	fmt.Println("✓ Added RSA recipient to builder")

	// Add PDF file
	if err := addDataFile(builder, testPDFPath); err != nil {
		return "", fmt.Errorf("failed to add data file: %w", err)
	}

	// Build CDOC
	outputPath := "./TEST_RSA_encrypted.cdoc2"
	if err := buildCDOC(builder, outputPath); err != nil {
		return "", err
	}

	return outputPath, nil
}

func encryptWithECC_CDOC2() (string, error) {
	// Load ECC certificate
	certData, err := os.ReadFile(eccCertPath)
	if err != nil {
		return "", fmt.Errorf("failed to read ECC certificate: %w", err)
	}

	certificate, err := cert.ParseCertificatePEM(certData)
	if err != nil {
		return "", fmt.Errorf("failed to parse ECC certificate: %w", err)
	}
	fmt.Printf("✓ Loaded ECC certificate: %s\n", certificate.Subject.String())

	// Create builder with CDOC 2.0
	builder := cdoc.NewBuilder()
	builder.Version(cdoc.Version20)

	if err := builder.WithRecipientCertificate(certificate); err != nil {
		return "", fmt.Errorf("failed to add ECC recipient: %w", err)
	}
	fmt.Println("✓ Added ECC recipient to builder")

	// Add PDF file
	if err := addDataFile(builder, testPDFPath); err != nil {
		return "", fmt.Errorf("failed to add data file: %w", err)
	}

	// Build CDOC
	outputPath := "./TEST_ECC_encrypted.cdoc2"
	if err := buildCDOC(builder, outputPath); err != nil {
		return "", err
	}

	return outputPath, nil
}

func encryptWithPassword_CDOC2() (string, error) {
	password := "test-password-123"

	// Create builder with CDOC 2.0
	builder := cdoc.NewBuilder()
	builder.Version(cdoc.Version20)

	if err := builder.WithPassword(password); err != nil {
		return "", fmt.Errorf("failed to add password recipient: %w", err)
	}
	fmt.Println("✓ Added password recipient to builder")

	// Add PDF file
	if err := addDataFile(builder, testPDFPath); err != nil {
		return "", fmt.Errorf("failed to add data file: %w", err)
	}

	// Build CDOC
	outputPath := "./TEST_PASSWORD_encrypted.cdoc2"
	if err := buildCDOC(builder, outputPath); err != nil {
		return "", err
	}

	return outputPath, nil
}

func encryptMultipleFilesWithRSA_CDOC2() (string, error) {
	// Load RSA certificate
	certData, err := os.ReadFile(rsaCertPath)
	if err != nil {
		return "", fmt.Errorf("failed to read RSA certificate: %w", err)
	}

	certificate, err := cert.ParseCertificatePEM(certData)
	if err != nil {
		return "", fmt.Errorf("failed to parse RSA certificate: %w", err)
	}
	fmt.Printf("✓ Loaded RSA certificate: %s\n", certificate.Subject.String())

	// Create builder with CDOC 2.0
	builder := cdoc.NewBuilder()
	builder.Version(cdoc.Version20)

	if err := builder.WithRecipientCertificate(certificate); err != nil {
		return "", fmt.Errorf("failed to add RSA recipient: %w", err)
	}
	fmt.Println("✓ Added RSA recipient to builder")

	// Add both PDF and DOCX files
	if err := addDataFile(builder, testPDFPath); err != nil {
		return "", fmt.Errorf("failed to add PDF file: %w", err)
	}

	if err := addDataFile(builder, testDOCXPath); err != nil {
		return "", fmt.Errorf("failed to add DOCX file: %w", err)
	}

	// Build CDOC
	outputPath := "./TEST_MULTIPLE_FILES_RSA_encrypted.cdoc2"
	if err := buildCDOC(builder, outputPath); err != nil {
		return "", err
	}

	return outputPath, nil
}

func decryptWithPassword_CDOC2(cdocPath, outputDir string) error {
	password := "test-password-123"

	// Create decrypter
	decrypter := cdoc.NewDecrypter()

	// Load CDOC file
	if err := decrypter.WithCDOCFromFile(cdocPath); err != nil {
		return fmt.Errorf("failed to load CDOC file: %w", err)
	}
	fmt.Printf("✓ Loaded CDOC file: %s\n", cdocPath)

	// Set password
	decrypter.WithPassword(password)
	fmt.Println("✓ Set password for decryption")

	// Decrypt
	decryptedFiles, err := decrypter.Decrypt()
	if err != nil {
		return fmt.Errorf("failed to decrypt: %w", err)
	}
	fmt.Printf("✓ Decrypted %d file(s)\n", len(decryptedFiles))

	// Ensure output directory exists
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Write decrypted files
	for _, decryptedFile := range decryptedFiles {
		outputPath := filepath.Join(outputDir, decryptedFile.Name)
		if err := os.WriteFile(outputPath, decryptedFile.Content, 0644); err != nil {
			return fmt.Errorf("failed to write decrypted file: %w", err)
		}
		fmt.Printf("✓ Wrote decrypted file: %s (%d bytes)\n", outputPath, len(decryptedFile.Content))
	}

	return nil
}

func repeatChar(c string, n int) string {
	result := ""
	for i := 0; i < n; i++ {
		result += c
	}
	return result
}
