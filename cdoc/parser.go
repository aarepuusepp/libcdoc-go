package cdoc

import (
	"encoding/base64"
	"encoding/xml"
	"io"
	"math/big"
	"strings"

	"crypto/ecdsa"
	"crypto/elliptic"

	"github.com/aarepuusepp/libcdoc-go/v2/cert"
	"github.com/aarepuusepp/libcdoc-go/v2/internal"
	"github.com/aarepuusepp/libcdoc-go/v2/xmlenc"
)

// Parser implements XML parsing for CDOC documents
type Parser struct {
	encryptedData *xmlenc.EncryptedData
}

// NewParser creates a new Parser instance
func NewParser() *Parser {
	return &Parser{}
}

// Parse parses a CDOC document from an XML reader
func (p *Parser) Parse(r io.Reader) error {
	decoder := xml.NewDecoder(r)
	decoder.Strict = false // Allow some flexibility in parsing

	var encryptedData xmlenc.EncryptedData
	if err := decoder.Decode(&encryptedData); err != nil {
		return internal.NewParseError("failed to parse CDOC XML", err)
	}

	p.encryptedData = &encryptedData
	return nil
}

// GetVersion returns the CDOC version based on EncryptionMethod
func (p *Parser) GetVersion() Version {
	if p.encryptedData == nil {
		return Version10
	}
	return DetectVersion(p.encryptedData.EncryptionMethod.Algorithm)
}

// GetRecipients extracts all recipients from the parsed document
func (p *Parser) GetRecipients() ([]xmlenc.Recipient, error) {
	if p.encryptedData == nil {
		return nil, internal.NewParseError("document not parsed", nil)
	}

	var recipients []xmlenc.Recipient

	for _, encryptedKey := range p.encryptedData.KeyInfo.EncryptedKeys {
		recipient, err := p.parseRecipient(&encryptedKey)
		if err != nil {
			return nil, err
		}
		recipients = append(recipients, recipient)
	}

	return recipients, nil
}

// parseRecipient parses a single recipient from an EncryptedKey element
func (p *Parser) parseRecipient(encryptedKey *xmlenc.EncryptedKey) (xmlenc.Recipient, error) {
	algorithmURI := encryptedKey.EncryptionMethod.Algorithm

	switch AlgorithmURI(algorithmURI) {
	case URI_RSA15:
		return p.parseRSARecipient(encryptedKey)
	case URI_AES256KW:
		return p.parseECRecipient(encryptedKey)
	default:
		return nil, internal.NewParseError(
			"unsupported encryption method: "+algorithmURI,
			nil,
		)
	}
}

// parseRSARecipient parses an RSA recipient
func (p *Parser) parseRSARecipient(encryptedKey *xmlenc.EncryptedKey) (*xmlenc.RSARecipient, error) {
	if encryptedKey.KeyInfo.X509Data == nil {
		return nil, internal.NewParseError("X509Data missing for RSA recipient", nil)
	}

	// Parse certificate
	certData, err := internal.DecodeBase64(encryptedKey.KeyInfo.X509Data.X509Certificate)
	if err != nil {
		return nil, internal.NewParseError("failed to decode certificate", err)
	}

	certificate, err := cert.ParseCertificate(certData)
	if err != nil {
		return nil, internal.NewParseError("failed to parse certificate", err)
	}

	cn := cert.ExtractCN(certificate)

	// Decode encrypted key
	encryptedKeyBytes, err := internal.DecodeBase64(encryptedKey.CipherData.CipherValue)
	if err != nil {
		return nil, internal.NewParseError("failed to decode encrypted key", err)
	}

	return &xmlenc.RSARecipient{
		Certificate:  certificate,
		CN:           cn,
		EncryptedKey: encryptedKeyBytes,
	}, nil
}

// parseECRecipient parses an EC recipient
func (p *Parser) parseECRecipient(encryptedKey *xmlenc.EncryptedKey) (*xmlenc.ECRecipient, error) {
	if encryptedKey.KeyInfo.AgreementMethod == nil {
		return nil, internal.NewParseError("AgreementMethod missing for EC recipient", nil)
	}

	agreementMethod := encryptedKey.KeyInfo.AgreementMethod

	// Parse ConcatKDF parameters
	if agreementMethod.KeyDerivationMethod == nil || agreementMethod.KeyDerivationMethod.ConcatKDFParams == nil {
		return nil, internal.NewParseError("ConcatKDFParams missing", nil)
	}

	params := agreementMethod.KeyDerivationMethod.ConcatKDFParams

	// Decode hex-encoded parameters (they have "00" prefix that needs to be stripped)
	algorithmIDHex := params.AlgorithmID
	partyUInfoHex := params.PartyUInfo
	partyVInfoHex := params.PartyVInfo

	// Remove "00" prefix if present
	if strings.HasPrefix(algorithmIDHex, "00") {
		algorithmIDHex = algorithmIDHex[2:]
	}
	if strings.HasPrefix(partyUInfoHex, "00") {
		partyUInfoHex = partyUInfoHex[2:]
	}
	if strings.HasPrefix(partyVInfoHex, "00") {
		partyVInfoHex = partyVInfoHex[2:]
	}

	algorithmID, err := internal.DecodeHex(algorithmIDHex)
	if err != nil {
		return nil, internal.NewParseError("failed to decode AlgorithmID", err)
	}

	partyUInfo, err := internal.DecodeHex(partyUInfoHex)
	if err != nil {
		return nil, internal.NewParseError("failed to decode PartyUInfo", err)
	}

	partyVInfo, err := internal.DecodeHex(partyVInfoHex)
	if err != nil {
		return nil, internal.NewParseError("failed to decode PartyVInfo", err)
	}

	digestAlg := params.DigestMethod.Algorithm

	// Parse ephemeral public key
	if agreementMethod.OriginatorKeyInfo == nil || agreementMethod.OriginatorKeyInfo.KeyValue == nil ||
		agreementMethod.OriginatorKeyInfo.KeyValue.ECKeyValue == nil {
		return nil, internal.NewParseError("OriginatorKeyInfo missing", nil)
	}

	ecKeyValue := agreementMethod.OriginatorKeyInfo.KeyValue.ECKeyValue
	ephemeralPubKey, err := p.parseECPublicKey(ecKeyValue.PublicKey)
	if err != nil {
		return nil, err
	}

	// Parse recipient certificate
	if agreementMethod.RecipientKeyInfo == nil || agreementMethod.RecipientKeyInfo.X509Data == nil {
		return nil, internal.NewParseError("RecipientKeyInfo missing", nil)
	}

	certData, err := internal.DecodeBase64(agreementMethod.RecipientKeyInfo.X509Data.X509Certificate)
	if err != nil {
		return nil, internal.NewParseError("failed to decode certificate", err)
	}

	recipientCert, err := cert.ParseCertificate(certData)
	if err != nil {
		return nil, internal.NewParseError("failed to parse certificate", err)
	}

	cn := cert.ExtractCN(recipientCert)

	// Decode encrypted/wrapped key
	encryptedKeyBase64 := encryptedKey.CipherData.CipherValue
	encryptedKeyBytes := []byte(encryptedKeyBase64) // Store as base64 string for now

	return &xmlenc.ECRecipient{
		Certificate:        recipientCert,
		CN:                 cn,
		EphemeralPublicKey: ephemeralPubKey,
		AlgorithmID:        algorithmID,
		PartyUInfo:         partyUInfo,
		PartyVInfo:         partyVInfo,
		DigestAlgorithm:    digestAlg,
		EncryptedKey:       encryptedKeyBytes,
	}, nil
}

// parseECPublicKey parses an EC public key from base64-encoded point
func (p *Parser) parseECPublicKey(base64PublicKey string) (*ecdsa.PublicKey, error) {
	// Decode base64 public key
	publicKeyBytes, err := base64.StdEncoding.DecodeString(base64PublicKey)
	if err != nil {
		return nil, internal.NewParseError("failed to decode EC public key", err)
	}

	// secp384r1 curve
	curve := elliptic.P384()

	// Validate point length (for secp384r1, uncompressed point is 97 bytes: 1 byte prefix + 48 bytes X + 48 bytes Y)
	if len(publicKeyBytes) != 97 && len(publicKeyBytes) != 96 {
		// Try without prefix
		if len(publicKeyBytes) == 96 {
			// Uncompressed format: 96 bytes (X + Y, no prefix)
			// Split into X and Y coordinates
			xBytes := publicKeyBytes[:48]
			yBytes := publicKeyBytes[48:]

			x := new(big.Int).SetBytes(xBytes)
			y := new(big.Int).SetBytes(yBytes)

			// Validate point is on curve
			if !curve.IsOnCurve(x, y) {
				return nil, internal.NewParseError("EC point is not on curve", nil)
			}

			return &ecdsa.PublicKey{
				Curve: curve,
				X:     x,
				Y:     y,
			}, nil
		}
		return nil, internal.NewParseError("invalid EC public key length", nil)
	}

	// Handle 97-byte format (with 0x04 prefix for uncompressed)
	var offset int
	if len(publicKeyBytes) == 97 {
		if publicKeyBytes[0] != 0x04 {
			return nil, internal.NewParseError("invalid EC public key format", nil)
		}
		offset = 1
	}

	// Split into X and Y coordinates
	xBytes := publicKeyBytes[offset : offset+48]
	yBytes := publicKeyBytes[offset+48 : offset+96]

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	// Validate point is on curve
	if !curve.IsOnCurve(x, y) {
		return nil, internal.NewParseError("EC point is not on curve", nil)
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

// GetEncryptedContent returns the base64-encoded encrypted content
func (p *Parser) GetEncryptedContent() ([]byte, error) {
	if p.encryptedData == nil {
		return nil, internal.NewParseError("document not parsed", nil)
	}

	return internal.DecodeBase64(p.encryptedData.CipherData.CipherValue)
}

// GetMimeType returns the MimeType attribute
func (p *Parser) GetMimeType() string {
	if p.encryptedData == nil {
		return ""
	}
	return p.encryptedData.MimeType
}

// GetEncryptionProperties returns the metadata properties
func (p *Parser) GetEncryptionProperties() map[string]string {
	if p.encryptedData == nil || p.encryptedData.EncryptionProperties == nil {
		return make(map[string]string)
	}

	props := make(map[string]string)
	for _, prop := range p.encryptedData.EncryptionProperties.Properties {
		props[prop.Name] = prop.Content
	}

	return props
}

// GetFilename returns the original filename from EncryptionProperties
func (p *Parser) GetFilename() string {
	props := p.GetEncryptionProperties()
	return props["Filename"]
}
