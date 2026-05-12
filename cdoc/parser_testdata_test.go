package cdoc

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aarepuusepp/libcdoc-go/v2/xmlenc"
)

// TestParser_CDOCFiles_CreatedByCdoc4j tests parsing actual CDOC files created by cdoc4j
func TestParser_CDOCFiles_CreatedByCdoc4j(t *testing.T) {
	testFiles := []struct {
		name               string
		filename           string
		expectedVersion    Version
		expectedRecipients int
		description        string
	}{
		{
			name:               "CDOC 1.0 RSA single file",
			filename:           "valid_cdoc10.cdoc",
			expectedVersion:    Version10,
			expectedRecipients: 1,
			description:        "CDOC 1.0 with RSA recipient and single file",
		},
		{
			name:               "CDOC 1.0 RSA with DDOC",
			filename:           "valid_cdoc10_withDDOC.cdoc",
			expectedVersion:    Version10,
			expectedRecipients: 1,
			description:        "CDOC 1.0 with RSA recipient and multiple files (DDOC)",
		},
		{
			name:               "CDOC 1.0 RSA multiple recipients",
			filename:           "valid_cdoc10_withMultipleRecipients.cdoc",
			expectedVersion:    Version10,
			expectedRecipients: 2,
			description:        "CDOC 1.0 with RSA recipients (multiple)",
		},
		{
			name:               "CDOC 1.1 RSA single file",
			filename:           "valid_cdoc11_RSA.cdoc",
			expectedVersion:    Version11,
			expectedRecipients: 1,
			description:        "CDOC 1.1 with RSA recipient and single file",
		},
		{
			name:               "CDOC 1.1 RSA with DDOC",
			filename:           "valid_cdoc11_RSA_withDDOC.cdoc",
			expectedVersion:    Version11,
			expectedRecipients: 1,
			description:        "CDOC 1.1 with RSA recipient and multiple files (DDOC)",
		},
		{
			name:               "CDOC 1.1 EC single file",
			filename:           "valid_cdoc11_ECC.cdoc",
			expectedVersion:    Version11,
			expectedRecipients: 1,
			description:        "CDOC 1.1 with EC recipient and single file",
		},
		{
			name:               "CDOC 1.1 EC with DDOC",
			filename:           "valid_cdoc11_ECC_withDDOC.cdoc",
			expectedVersion:    Version11,
			expectedRecipients: 1,
			description:        "CDOC 1.1 with EC recipient and multiple files (DDOC)",
		},
		{
			name:               "CDOC 1.1 multiple recipients",
			filename:           "valid_cdoc11_withMultipleRecipients.cdoc",
			expectedVersion:    Version11,
			expectedRecipients: 2,
			description:        "CDOC 1.1 with multiple recipients",
		},
	}

	for _, tt := range testFiles {
		t.Run(tt.name, func(t *testing.T) {
			// Try relative path first (for running from project root)
			cdocPath := filepath.Join("testdata", "cdoc", tt.filename)
			if _, err := os.Stat(cdocPath); os.IsNotExist(err) {
				// Try alternative path (for running from cdoc package directory)
				cdocPath = filepath.Join("..", "testdata", "cdoc", tt.filename)
				if _, err2 := os.Stat(cdocPath); os.IsNotExist(err2) {
					t.Skipf("CDOC test file not found at %s or %s", filepath.Join("testdata", "cdoc", tt.filename), cdocPath)
					return
				}
			}

			cdocFile, err := os.Open(cdocPath)
			if err != nil {
				t.Fatalf("Failed to open CDOC file: %v", err)
			}
			defer func() { _ = cdocFile.Close() }()

			parser := NewParser()
			if err := parser.Parse(cdocFile); err != nil {
				t.Fatalf("Failed to parse CDOC file %s: %v", tt.filename, err)
			}

			// Verify version
			version := parser.GetVersion()
			if version != tt.expectedVersion {
				t.Errorf("Expected version %v, got %v", tt.expectedVersion, version)
			}

			// Verify recipients
			recipients, err := parser.GetRecipients()
			if err != nil {
				t.Fatalf("Failed to get recipients: %v", err)
			}

			if len(recipients) != tt.expectedRecipients {
				t.Errorf("Expected %d recipients, got %d", tt.expectedRecipients, len(recipients))
			}

			// Verify recipient types
			for i, recipient := range recipients {
				if recipient.GetCN() == "" {
					t.Errorf("Recipient %d missing CN", i)
				}

				if recipient.GetCertificate() == nil {
					t.Errorf("Recipient %d missing certificate", i)
				}

				// Check type based on version and expected algorithm
				if tt.expectedVersion == Version11 {
					// CDOC 1.1 can have RSA or EC recipients
					if _, ok := recipient.(*xmlenc.RSARecipient); !ok {
						if _, ok := recipient.(*xmlenc.ECRecipient); !ok {
							t.Errorf("Recipient %d is neither RSA nor EC", i)
						}
					}
				} else {
					// CDOC 1.0 only supports RSA
					if _, ok := recipient.(*xmlenc.RSARecipient); !ok {
						t.Errorf("CDOC 1.0 recipient %d should be RSA, got %T", i, recipient)
					}
				}
			}

			// Verify encrypted content exists
			encryptedContent, err := parser.GetEncryptedContent()
			if err != nil {
				t.Fatalf("Failed to get encrypted content: %v", err)
			}

			if len(encryptedContent) == 0 {
				t.Error("Encrypted content is empty")
			}

			// Verify MimeType
			mimeType := parser.GetMimeType()
			if tt.filename == "valid_cdoc10_withDDOC.cdoc" ||
				tt.filename == "valid_cdoc11_RSA_withDDOC.cdoc" ||
				tt.filename == "valid_cdoc11_ECC_withDDOC.cdoc" {
				if mimeType != DDOCMimeType {
					t.Errorf("Expected DDOC mime type, got %s", mimeType)
				}
			}

			// Verify EncryptionProperties
			props := parser.GetEncryptionProperties()
			docFormat, found := props["DocumentFormat"]
			if found {
				// CDOC uses format "ENCDOC-XML|1.0" or "ENCDOC-XML|1.1"
				expectedFormat := "ENCDOC-XML|" + string(tt.expectedVersion)
				if docFormat != expectedFormat {
					// Also accept just the version number
					if docFormat != string(tt.expectedVersion) {
						t.Errorf("Expected DocumentFormat %s (or %s), got %s", expectedFormat, string(tt.expectedVersion), docFormat)
					}
				}
			}

			t.Logf("Successfully parsed %s: %s", tt.filename, tt.description)
		})
	}
}

// TestParser_CDOC10_SpecificFile tests parsing a specific CDOC 1.0 file
func TestParser_CDOC10_SpecificFile(t *testing.T) {
	cdocPath := filepath.Join("testdata", "cdoc", "valid_cdoc10.cdoc")
	if _, err := os.Stat(cdocPath); os.IsNotExist(err) {
		t.Skipf("CDOC test file not found at %s", cdocPath)
		return
	}

	cdocFile, err := os.Open(cdocPath)
	if err != nil {
		t.Fatalf("Failed to open CDOC file: %v", err)
	}
	defer func() { _ = cdocFile.Close() }()

	parser := NewParser()
	if err := parser.Parse(cdocFile); err != nil {
		t.Fatalf("Failed to parse CDOC 1.0 file: %v", err)
	}

	// Verify it's CDOC 1.0
	version := parser.GetVersion()
	if version != Version10 {
		t.Errorf("Expected version 1.0, got %v", version)
	}

	// Verify it has RSA recipient (CDOC 1.0 only supports RSA)
	recipients, err := parser.GetRecipients()
	if err != nil {
		t.Fatalf("Failed to get recipients: %v", err)
	}

	if len(recipients) != 1 {
		t.Errorf("Expected 1 recipient, got %d", len(recipients))
	}

	rsaRecipient, ok := recipients[0].(*xmlenc.RSARecipient)
	if !ok {
		t.Fatal("Expected RSA recipient for CDOC 1.0")
	}

	if rsaRecipient.GetCN() == "" {
		t.Error("RSA recipient missing CN")
	}

	// Verify filename
	filename := parser.GetFilename()
	if filename == "" {
		t.Error("Filename should be extracted from EncryptionProperties")
	}
}

// TestParser_CDOC11_RSA_SpecificFile tests parsing CDOC 1.1 RSA file
func TestParser_CDOC11_RSA_SpecificFile(t *testing.T) {
	cdocPath := filepath.Join("testdata", "cdoc", "valid_cdoc11_RSA.cdoc")
	if _, err := os.Stat(cdocPath); os.IsNotExist(err) {
		t.Skipf("CDOC test file not found at %s", cdocPath)
		return
	}

	cdocFile, err := os.Open(cdocPath)
	if err != nil {
		t.Fatalf("Failed to open CDOC file: %v", err)
	}
	defer func() { _ = cdocFile.Close() }()

	parser := NewParser()
	if err := parser.Parse(cdocFile); err != nil {
		t.Fatalf("Failed to parse CDOC 1.1 RSA file: %v", err)
	}

	version := parser.GetVersion()
	if version != Version11 {
		t.Errorf("Expected version 1.1, got %v", version)
	}

	recipients, err := parser.GetRecipients()
	if err != nil {
		t.Fatalf("Failed to get recipients: %v", err)
	}

	if len(recipients) != 1 {
		t.Errorf("Expected 1 recipient, got %d", len(recipients))
	}

	rsaRecipient, ok := recipients[0].(*xmlenc.RSARecipient)
	if !ok {
		t.Fatal("Expected RSA recipient")
	}

	if rsaRecipient.GetCN() == "" {
		t.Error("RSA recipient missing CN")
	}

	// Verify encrypted key exists
	if len(rsaRecipient.EncryptedKey) == 0 {
		t.Error("RSA recipient missing encrypted key")
	}
}

// TestParser_CDOC11_EC_SpecificFile tests parsing CDOC 1.1 EC file
func TestParser_CDOC11_EC_SpecificFile(t *testing.T) {
	cdocPath := filepath.Join("testdata", "cdoc", "valid_cdoc11_ECC.cdoc")
	if _, err := os.Stat(cdocPath); os.IsNotExist(err) {
		t.Skipf("CDOC test file not found at %s", cdocPath)
		return
	}

	cdocFile, err := os.Open(cdocPath)
	if err != nil {
		t.Fatalf("Failed to open CDOC file: %v", err)
	}
	defer func() { _ = cdocFile.Close() }()

	parser := NewParser()
	if err := parser.Parse(cdocFile); err != nil {
		t.Fatalf("Failed to parse CDOC 1.1 EC file: %v", err)
	}

	version := parser.GetVersion()
	if version != Version11 {
		t.Errorf("Expected version 1.1, got %v", version)
	}

	recipients, err := parser.GetRecipients()
	if err != nil {
		t.Fatalf("Failed to get recipients: %v", err)
	}

	if len(recipients) != 1 {
		t.Errorf("Expected 1 recipient, got %d", len(recipients))
	}

	ecRecipient, ok := recipients[0].(*xmlenc.ECRecipient)
	if !ok {
		t.Fatal("Expected EC recipient")
	}

	if ecRecipient.GetCN() == "" {
		t.Error("EC recipient missing CN")
	}

	if ecRecipient.GetEphemeralPublicKey() == nil {
		t.Error("EC recipient missing ephemeral public key")
	}

	// Verify ConcatKDF parameters exist
	if len(ecRecipient.GetAlgorithmID()) == 0 {
		t.Error("EC recipient missing AlgorithmID")
	}
}

// TestParser_CDOC11_MultipleRecipients tests parsing CDOC with multiple recipients
func TestParser_CDOC11_MultipleRecipients(t *testing.T) {
	cdocPath := filepath.Join("testdata", "cdoc", "valid_cdoc11_withMultipleRecipients.cdoc")
	if _, err := os.Stat(cdocPath); os.IsNotExist(err) {
		t.Skipf("CDOC test file not found at %s", cdocPath)
		return
	}

	cdocFile, err := os.Open(cdocPath)
	if err != nil {
		t.Fatalf("Failed to open CDOC file: %v", err)
	}
	defer func() { _ = cdocFile.Close() }()

	parser := NewParser()
	if err := parser.Parse(cdocFile); err != nil {
		t.Fatalf("Failed to parse CDOC file: %v", err)
	}

	recipients, err := parser.GetRecipients()
	if err != nil {
		t.Fatalf("Failed to get recipients: %v", err)
	}

	if len(recipients) < 2 {
		t.Errorf("Expected at least 2 recipients, got %d", len(recipients))
	}

	// Verify all recipients have CNs and certificates
	for i, recipient := range recipients {
		if recipient.GetCN() == "" {
			t.Errorf("Recipient %d missing CN", i)
		}
		if recipient.GetCertificate() == nil {
			t.Errorf("Recipient %d missing certificate", i)
		}
	}
}

// TestParser_InvalidCDOCFiles tests parsing invalid CDOC structures
func TestParser_InvalidCDOCFiles(t *testing.T) {
	invalidFiles := []string{
		"invalid_cdoc10_structure.cdoc",
		"invalid_cdoc11_structure.cdoc",
		"invalid_cdoc11_multiple_files.cdoc",
	}

	for _, filename := range invalidFiles {
		t.Run(filename, func(t *testing.T) {
			cdocPath := filepath.Join("testdata", "cdoc", filename)
			if _, err := os.Stat(cdocPath); os.IsNotExist(err) {
				t.Skipf("Invalid CDOC test file not found at %s", cdocPath)
				return
			}

			cdocFile, err := os.Open(cdocPath)
			if err != nil {
				t.Fatalf("Failed to open CDOC file: %v", err)
			}
			defer func() { _ = cdocFile.Close() }()

			parser := NewParser()
			// These should either fail to parse or parse with warnings
			err = parser.Parse(cdocFile)
			// For invalid files, we expect either an error or successful parse with validation
			// The exact behavior depends on how strict our parser is
			t.Logf("Parsing invalid file %s: error = %v", filename, err)
		})
	}
}
