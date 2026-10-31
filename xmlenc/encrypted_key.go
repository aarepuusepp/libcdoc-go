package xmlenc

import (
	"encoding/xml"
)

// EncryptedKey represents an EncryptedKey XML element (for RSA recipients)
type EncryptedKey struct {
	XMLName          xml.Name         `xml:"http://www.w3.org/2001/04/xmlenc# EncryptedKey"`
	ID               string           `xml:"Id,attr,omitempty"`
	Recipient        string           `xml:"Recipient,attr,omitempty"`
	EncryptionMethod EncryptionMethod `xml:"http://www.w3.org/2001/04/xmlenc# EncryptionMethod"`
	KeyInfo          KeyInfoElement   `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
	CipherData       CipherData       `xml:"http://www.w3.org/2001/04/xmlenc# CipherData"`
}

// KeyInfoElement represents a KeyInfo element within an EncryptedKey
type KeyInfoElement struct {
	XMLName         xml.Name         `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
	KeyName         *string          `xml:"http://www.w3.org/2000/09/xmldsig# KeyName,omitempty"`
	X509Data        *X509Data        `xml:"http://www.w3.org/2000/09/xmldsig# X509Data,omitempty"`
	AgreementMethod *AgreementMethod `xml:"http://www.w3.org/2001/04/xmlenc# AgreementMethod,omitempty"`
	CarriedKeyName  *string          `xml:"http://www.w3.org/2000/09/xmldsig# CarriedKeyName,omitempty"`
}

// X509Data represents X.509 certificate data
type X509Data struct {
	XMLName         xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# X509Data"`
	X509Certificate string   `xml:"http://www.w3.org/2000/09/xmldsig# X509Certificate"`
}
