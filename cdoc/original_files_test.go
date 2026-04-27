package cdoc

import (
	"strings"
	"testing"
)

func TestParser_GetOriginalFiles_MultipleEntriesAndPipesInName(t *testing.T) {
	t.Parallel()

	xml := `<?xml version="1.0" encoding="UTF-8"?>
<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" MimeType="application/octet-stream">
  <EncryptionProperties xmlns="http://www.w3.org/2001/04/xmlenc#">
    <EncryptionProperty xmlns="http://www.w3.org/2001/04/xmlenc#" Name="orig_file">simple.txt|24|application/octet-stream|D0</EncryptionProperty>
    <EncryptionProperty xmlns="http://www.w3.org/2001/04/xmlenc#" Name="orig_file">a|b|c.txt|5|text/plain|D1</EncryptionProperty>
  </EncryptionProperties>
</EncryptedData>`

	parser := NewParser()
	if err := parser.Parse(strings.NewReader(xml)); err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	files, err := parser.GetOriginalFiles()
	if err != nil {
		t.Fatalf("GetOriginalFiles() error: %v", err)
	}
	if len(files) != 2 {
		t.Fatalf("expected 2 files, got %d", len(files))
	}

	if files[0].Name != "simple.txt" || files[0].Size != 24 || files[0].MimeType != "application/octet-stream" || files[0].DataRef != "D0" {
		t.Fatalf("unexpected file[0]: %+v", files[0])
	}
	if files[1].Name != "a|b|c.txt" || files[1].Size != 5 || files[1].MimeType != "text/plain" || files[1].DataRef != "D1" {
		t.Fatalf("unexpected file[1]: %+v", files[1])
	}
}

func TestParser_GetOriginalFiles_InvalidEntry_ReturnsPartialAndError(t *testing.T) {
	t.Parallel()

	xml := `<?xml version="1.0" encoding="UTF-8"?>
<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" MimeType="application/octet-stream">
  <EncryptionProperties xmlns="http://www.w3.org/2001/04/xmlenc#">
    <EncryptionProperty xmlns="http://www.w3.org/2001/04/xmlenc#" Name="orig_file">ok.txt|7|text/plain|D0</EncryptionProperty>
    <EncryptionProperty xmlns="http://www.w3.org/2001/04/xmlenc#" Name="orig_file">bad.txt|not-a-number|text/plain|D1</EncryptionProperty>
  </EncryptionProperties>
</EncryptedData>`

	parser := NewParser()
	if err := parser.Parse(strings.NewReader(xml)); err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	files, err := parser.GetOriginalFiles()
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if len(files) != 1 {
		t.Fatalf("expected 1 valid file, got %d", len(files))
	}
	if files[0].Name != "ok.txt" || files[0].Size != 7 || files[0].MimeType != "text/plain" || files[0].DataRef != "D0" {
		t.Fatalf("unexpected file[0]: %+v", files[0])
	}
}

func TestParser_GetOriginalFiles_NotParsed_ReturnsError(t *testing.T) {
	t.Parallel()

	parser := NewParser()
	_, err := parser.GetOriginalFiles()
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
}

