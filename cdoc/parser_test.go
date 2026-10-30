package cdoc

import (
	"strings"
	"testing"
)

func TestParser_GetVersion(t *testing.T) {
	// Test CDOC 1.1 detection
	xml11 := `<?xml version="1.0" encoding="UTF-8"?>
	<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" xmlns:xenc11="http://www.w3.org/2009/xmlenc11#">
		<EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes256-gcm"/>
	</EncryptedData>`

	parser := NewParser()
	if err := parser.Parse(strings.NewReader(xml11)); err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	version := parser.GetVersion()
	if version != Version11 {
		t.Errorf("Expected version 1.1, got %v", version)
	}
}

func TestParser_GetVersion_CDOC10(t *testing.T) {
	// Test CDOC 1.0 detection
	xml10 := `<?xml version="1.0" encoding="UTF-8"?>
	<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#">
		<EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/>
	</EncryptedData>`

	parser := NewParser()
	if err := parser.Parse(strings.NewReader(xml10)); err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	version := parser.GetVersion()
	if version != Version10 {
		t.Errorf("Expected version 1.0, got %v", version)
	}
}

func TestParser_GetFilename(t *testing.T) {
	xml := `<?xml version="1.0" encoding="UTF-8"?>
	<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#">
		<EncryptionProperties>
			<EncryptionProperty Name="Filename">test.pdf</EncryptionProperty>
		</EncryptionProperties>
	</EncryptedData>`

	parser := NewParser()
	if err := parser.Parse(strings.NewReader(xml)); err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	filename := parser.GetFilename()
	if filename != "test.pdf" {
		t.Errorf("Expected filename 'test.pdf', got '%s'", filename)
	}
}

func TestParser_GetFilename_NotFound(t *testing.T) {
	xml := `<?xml version="1.0" encoding="UTF-8"?>
	<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#">
	</EncryptedData>`

	parser := NewParser()
	if err := parser.Parse(strings.NewReader(xml)); err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	filename := parser.GetFilename()
	if filename != "" {
		t.Errorf("Expected empty filename, got '%s'", filename)
	}
}

func TestParser_GetMimeType(t *testing.T) {
	xml := `<?xml version="1.0" encoding="UTF-8"?>
	<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" MimeType="application/pdf">
	</EncryptedData>`

	parser := NewParser()
	if err := parser.Parse(strings.NewReader(xml)); err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	mimeType := parser.GetMimeType()
	if mimeType != "application/pdf" {
		t.Errorf("Expected MimeType 'application/pdf', got '%s'", mimeType)
	}
}

func TestParser_GetEncryptionProperties(t *testing.T) {
	xml := `<?xml version="1.0" encoding="UTF-8"?>
	<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#">
		<EncryptionProperties>
			<EncryptionProperty Name="DocumentFormat">1.1</EncryptionProperty>
			<EncryptionProperty Name="Filename">test.txt</EncryptionProperty>
		</EncryptionProperties>
	</EncryptedData>`

	parser := NewParser()
	if err := parser.Parse(strings.NewReader(xml)); err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	props := parser.GetEncryptionProperties()
	if len(props) == 0 {
		t.Error("Expected encryption properties, got empty map")
	}

	docFormat, found := props["DocumentFormat"]
	if !found {
		t.Error("DocumentFormat property not found")
	} else if docFormat != "1.1" {
		t.Errorf("Expected DocumentFormat '1.1', got '%s'", docFormat)
	}

	filename, found := props["Filename"]
	if !found {
		t.Error("Filename property not found")
	} else if filename != "test.txt" {
		t.Errorf("Expected Filename 'test.txt', got '%s'", filename)
	}
}

func TestNewParser(t *testing.T) {
	parser := NewParser()
	if parser == nil {
		t.Fatal("NewParser() returned nil")
	}
}
