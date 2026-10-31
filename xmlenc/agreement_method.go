package xmlenc

import (
	"encoding/xml"
)

// AgreementMethod represents the AgreementMethod element for ECDH-ES (EC recipients)
type AgreementMethod struct {
	XMLName             xml.Name             `xml:"http://www.w3.org/2001/04/xmlenc# AgreementMethod"`
	Algorithm           string               `xml:"Algorithm,attr"`
	KeyDerivationMethod *KeyDerivationMethod `xml:"http://www.w3.org/2009/xmlenc11# KeyDerivationMethod,omitempty"`
	OriginatorKeyInfo   *OriginatorKeyInfo   `xml:"http://www.w3.org/2001/04/xmlenc# OriginatorKeyInfo,omitempty"`
	RecipientKeyInfo    *RecipientKeyInfo    `xml:"http://www.w3.org/2001/04/xmlenc# RecipientKeyInfo,omitempty"`
}

// KeyDerivationMethod represents the KeyDerivationMethod element (ConcatKDF)
type KeyDerivationMethod struct {
	XMLName         xml.Name         `xml:"http://www.w3.org/2009/xmlenc11# KeyDerivationMethod"`
	Algorithm       string           `xml:"Algorithm,attr"`
	ConcatKDFParams *ConcatKDFParams `xml:"http://www.w3.org/2009/xmlenc11# ConcatKDFParams,omitempty"`
}

// ConcatKDFParams represents ConcatKDF parameters
type ConcatKDFParams struct {
	XMLName      xml.Name     `xml:"http://www.w3.org/2009/xmlenc11# ConcatKDFParams"`
	AlgorithmID  string       `xml:"AlgorithmID,attr"`
	PartyUInfo   string       `xml:"PartyUInfo,attr"`
	PartyVInfo   string       `xml:"PartyVInfo,attr"`
	DigestMethod DigestMethod `xml:"http://www.w3.org/2000/09/xmldsig# DigestMethod"`
}

// DigestMethod represents the digest method (SHA-384)
type DigestMethod struct {
	XMLName   xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# DigestMethod"`
	Algorithm string   `xml:"Algorithm,attr"`
}

// OriginatorKeyInfo represents the ephemeral public key info
type OriginatorKeyInfo struct {
	XMLName  xml.Name  `xml:"http://www.w3.org/2001/04/xmlenc# OriginatorKeyInfo"`
	KeyValue *KeyValue `xml:"http://www.w3.org/2000/09/xmldsig# KeyValue,omitempty"`
}

// RecipientKeyInfo represents the recipient certificate info
type RecipientKeyInfo struct {
	XMLName  xml.Name  `xml:"http://www.w3.org/2001/04/xmlenc# RecipientKeyInfo"`
	X509Data *X509Data `xml:"http://www.w3.org/2000/09/xmldsig# X509Data,omitempty"`
}

// KeyValue represents the KeyValue element containing EC key
type KeyValue struct {
	XMLName    xml.Name    `xml:"http://www.w3.org/2000/09/xmldsig# KeyValue"`
	ECKeyValue *ECKeyValue `xml:"http://www.w3.org/2009/xmldsig11# ECKeyValue,omitempty"`
}

// ECKeyValue represents an EC key value
type ECKeyValue struct {
	XMLName    xml.Name    `xml:"http://www.w3.org/2009/xmldsig11# ECKeyValue"`
	NamedCurve *NamedCurve `xml:"http://www.w3.org/2009/xmldsig11# NamedCurve,omitempty"`
	PublicKey  string      `xml:"http://www.w3.org/2009/xmldsig11# PublicKey"`
}

// NamedCurve represents the named curve specification
type NamedCurve struct {
	XMLName xml.Name `xml:"http://www.w3.org/2009/xmldsig11# NamedCurve"`
	URI     string   `xml:"URI,attr"`
}
