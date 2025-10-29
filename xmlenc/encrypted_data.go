package xmlenc

import (
	"encoding/xml"
)

// EncryptedData represents the root EncryptedData XML element
type EncryptedData struct {
	XMLName xml.Name `xml:"http://www.w3.org/2001/04/xmlenc# EncryptedData"`
	ID      string   `xml:"Id,attr,omitempty"`
	Type    string   `xml:"Type,attr,omitempty"`
	MimeType string  `xml:"MimeType,attr"`
	
	EncryptionMethod EncryptionMethod `xml:"http://www.w3.org/2001/04/xmlenc# EncryptionMethod"`
	KeyInfo          KeyInfo          `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
	CipherData       CipherData       `xml:"http://www.w3.org/2001/04/xmlenc# CipherData"`
	EncryptionProperties *EncryptionProperties `xml:"http://www.w3.org/2001/04/xmlenc# EncryptionProperties,omitempty"`
}

// EncryptionMethod represents the EncryptionMethod element
type EncryptionMethod struct {
	XMLName   xml.Name `xml:"http://www.w3.org/2001/04/xmlenc# EncryptionMethod"`
	Algorithm string   `xml:"Algorithm,attr"`
}

// CipherData represents the CipherData element
type CipherData struct {
	XMLName    xml.Name `xml:"http://www.w3.org/2001/04/xmlenc# CipherData"`
	CipherValue string   `xml:"http://www.w3.org/2001/04/xmlenc# CipherValue"`
}

// KeyInfo represents the KeyInfo element containing recipients
type KeyInfo struct {
	XMLName      xml.Name       `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
	EncryptedKeys []EncryptedKey `xml:"http://www.w3.org/2001/04/xmlenc# EncryptedKey"`
}

// EncryptionProperties represents metadata about the encrypted document
type EncryptionProperties struct {
	XMLName    xml.Name              `xml:"http://www.w3.org/2001/04/xmlenc# EncryptionProperties"`
	ID         string                `xml:"Id,attr,omitempty"`
	Properties []EncryptionProperty  `xml:"http://www.w3.org/2001/04/xmlenc# EncryptionProperty"`
}

// EncryptionProperty represents a single metadata property
type EncryptionProperty struct {
	XMLName xml.Name `xml:"http://www.w3.org/2001/04/xmlenc# EncryptionProperty"`
	ID      string   `xml:"Id,attr,omitempty"`
	Target  string   `xml:"Target,attr,omitempty"`
	Name    string   `xml:"Name,attr"`
	Content string   `xml:",chardata"`
}
