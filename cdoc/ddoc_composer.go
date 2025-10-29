package cdoc

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"

	"github.com/yourorg/cdoc1-go/internal"
)

// convertIntToString converts int to string
func convertIntToString(i int) string {
	return fmt.Sprintf("%d", i)
}

// convertInt64ToString converts int64 to string
func convertInt64ToString(i int64) string {
	return fmt.Sprintf("%d", i)
}

// createDDOCXML creates a DDOC XML structure containing all data files
func (c *Composer) createDDOCXML() ([]byte, error) {
	var buf bytes.Buffer

	// Write XML declaration
	buf.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)

	// Create encoder
	encoder := xml.NewEncoder(&buf)

	// Start SignedDoc element with namespace and attributes
	if err := encoder.EncodeToken(xml.StartElement{
		Name: xml.Name{Space: "http://www.sk.ee/DigiDoc/v1.3.0#", Local: "SignedDoc"},
		Attr: []xml.Attr{
			{Name: xml.Name{Local: "xmlns"}, Value: "http://www.sk.ee/DigiDoc/v1.3.0#"},
			{Name: xml.Name{Local: "format"}, Value: "DIGIDOC-XML"},
			{Name: xml.Name{Local: "version"}, Value: "1.3"},
		},
	}); err != nil {
		return nil, internal.NewEncryptionError("failed to write SignedDoc start element", err)
	}

	// Add each data file
	for i, dataFile := range c.dataFiles {
		content, err := io.ReadAll(dataFile.Content)
		if err != nil {
			return nil, internal.NewEncryptionError("failed to read data file: "+dataFile.Name, err)
		}

		base64Content := base64.StdEncoding.EncodeToString(content)

		// Convert index and size to strings
		idValue := "D" + convertIntToString(i)
		sizeValue := convertInt64ToString(dataFile.Size)

		// Write DataFile start element with attributes
		if err := encoder.EncodeToken(xml.StartElement{
			Name: xml.Name{Local: "DataFile"},
			Attr: []xml.Attr{
				{Name: xml.Name{Local: "Filename"}, Value: dataFile.Name},
				{Name: xml.Name{Local: "ContentType"}, Value: "EMBEDDED_BASE64"},
				{Name: xml.Name{Local: "Id"}, Value: idValue},
				{Name: xml.Name{Local: "MimeType"}, Value: "application/octet-stream"},
				{Name: xml.Name{Local: "Size"}, Value: sizeValue},
			},
		}); err != nil {
			return nil, internal.NewEncryptionError("failed to write DataFile start element", err)
		}

		// Write Base64Value element with content (content goes directly, not as nested element)
		// According to cdoc4j, Base64Value content is written directly to the stream after DataFile start
		if err := encoder.EncodeToken(xml.CharData(base64Content)); err != nil {
			return nil, internal.NewEncryptionError("failed to write Base64Value content", err)
		}

		// Close DataFile element
		if err := encoder.EncodeToken(xml.EndElement{
			Name: xml.Name{Local: "DataFile"},
		}); err != nil {
			return nil, internal.NewEncryptionError("failed to write DataFile end element", err)
		}
	}

	// Close SignedDoc element
	if err := encoder.EncodeToken(xml.EndElement{
		Name: xml.Name{Space: "http://www.sk.ee/DigiDoc/v1.3.0#", Local: "SignedDoc"},
	}); err != nil {
		return nil, internal.NewEncryptionError("failed to write SignedDoc end element", err)
	}

	// Flush encoder to write all tokens
	if err := encoder.Flush(); err != nil {
		return nil, internal.NewEncryptionError("failed to flush XML encoder", err)
	}

	return buf.Bytes(), nil
}

