package cdoc

import (
	"encoding/base64"
	"encoding/xml"
	"io"
	"strconv"
	"strings"

	"crypto/ecdsa"
	"crypto/elliptic"

	"github.com/aarepuusepp/libcdoc-go/v2/cert"
	cdoccrypto "github.com/aarepuusepp/libcdoc-go/v2/crypto"
	"github.com/aarepuusepp/libcdoc-go/v2/internal"
	"github.com/aarepuusepp/libcdoc-go/v2/xmlenc"
)

// Parser implements XML parsing for CDOC documents
type Parser struct {
	encryptedData *xmlenc.EncryptedData
}

// OriginalFile is metadata about a single original file embedded in a CDOC 1.1 container.
// It is extracted from `EncryptionProperty Name="orig_file"` entries without decrypting.
type OriginalFile struct {
	Name     string
	Size     int64
	MimeType string
	DataRef  string // e.g. D0
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
	algorithmIDHex = strings.TrimPrefix(algorithmIDHex, "00")
	partyUInfoHex = strings.TrimPrefix(partyUInfoHex, "00")
	partyVInfoHex = strings.TrimPrefix(partyVInfoHex, "00")

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
	var namedCurveURI string
	if ecKeyValue.NamedCurve != nil {
		namedCurveURI = ecKeyValue.NamedCurve.URI
	}

	ephemeralPubKey, err := p.parseECPublicKey(ecKeyValue.PublicKey, namedCurveURI)
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
	encryptedKeyBytes := []byte(encryptedKeyBase64)

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
func (p *Parser) parseECPublicKey(base64PublicKey string, namedCurveURI string) (*ecdsa.PublicKey, error) {
	// Decode base64 public key
	publicKeyBytes, err := base64.StdEncoding.DecodeString(base64PublicKey)
	if err != nil {
		return nil, internal.NewParseError("failed to decode EC public key", err)
	}

	var (
		curve    elliptic.Curve
		coordLen int
	)

	if namedCurveURI != "" {
		oid := strings.TrimPrefix(namedCurveURI, "urn:oid:")
		switch oid {
		case cdoccrypto.SecP256R1OID:
			curve = elliptic.P256()
			coordLen = 32
		case cdoccrypto.SecP384R1OID:
			curve = elliptic.P384()
			coordLen = 48
		default:
			return nil, internal.NewParseError("unsupported EC named curve", nil)
		}
	} else {
		// Backwards-compat fallback: infer curve from point length.
		switch len(publicKeyBytes) {
		case 65, 64:
			curve = elliptic.P256()
			coordLen = 32
		case 97, 96:
			curve = elliptic.P384()
			coordLen = 48
		default:
			return nil, internal.NewParseError("invalid EC public key length", nil)
		}
	}

	// Accept both uncompressed point encodings:
	// - 0x04 || X || Y (1 + 2*coordLen bytes)
	// - X || Y (2*coordLen bytes)
	var offset int
	switch len(publicKeyBytes) {
	case 1 + 2*coordLen:
		if publicKeyBytes[0] != 0x04 {
			return nil, internal.NewParseError("invalid EC public key format", nil)
		}
		offset = 1
	case 2 * coordLen:
		offset = 0
	default:
		return nil, internal.NewParseError("invalid EC public key length", nil)
	}

	encoded := append([]byte{4}, publicKeyBytes[offset:]...)
	public, err := ecdsa.ParseUncompressedPublicKey(curve, encoded)
	if err != nil {
		return nil, internal.NewParseError("EC point is not on curve", err)
	}
	return public, nil
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

// GetOriginalFiles extracts `orig_file` metadata entries.
//
// The CDOC 1.1 writer stores multiple `orig_file` properties (one per embedded file) using
// the format: `filename|size|mime_type|D#`. Filenames may contain `|`, so parsing is done
// from the end.
func (p *Parser) GetOriginalFiles() ([]OriginalFile, error) {
	if p.encryptedData == nil {
		return nil, internal.NewParseError("document not parsed", nil)
	}
	if p.encryptedData.EncryptionProperties == nil {
		return []OriginalFile{}, nil
	}

	var (
		files    []OriginalFile
		firstErr error
	)

	for _, prop := range p.encryptedData.EncryptionProperties.Properties {
		if prop.Name != "orig_file" {
			continue
		}

		originalFile, err := parseOrigFileProperty(prop.Content)
		if err != nil {
			if firstErr == nil {
				firstErr = internal.NewParseError("failed to parse orig_file metadata", err)
			}
			continue
		}
		files = append(files, originalFile)
	}

	return files, firstErr
}

func parseOrigFileProperty(content string) (OriginalFile, error) {
	// Format: filename|size|mime_type|D#
	// Filenames can contain '|', so split from the end.
	raw := strings.TrimSpace(content)

	dataRefSep := strings.LastIndex(raw, "|")
	if dataRefSep < 0 {
		return OriginalFile{}, internal.NewParseError("invalid orig_file metadata (missing dataRef separator)", nil)
	}
	dataRef := strings.TrimSpace(raw[dataRefSep+1:])
	rest := raw[:dataRefSep]

	mimeSep := strings.LastIndex(rest, "|")
	if mimeSep < 0 {
		return OriginalFile{}, internal.NewParseError("invalid orig_file metadata (missing mimeType separator)", nil)
	}
	mimeType := strings.TrimSpace(rest[mimeSep+1:])
	rest = rest[:mimeSep]

	sizeSep := strings.LastIndex(rest, "|")
	if sizeSep < 0 {
		return OriginalFile{}, internal.NewParseError("invalid orig_file metadata (missing size separator)", nil)
	}
	sizeStr := strings.TrimSpace(rest[sizeSep+1:])
	name := strings.TrimSpace(rest[:sizeSep])

	size, err := strconv.ParseInt(sizeStr, 10, 64)
	if err != nil {
		return OriginalFile{}, internal.NewParseError("invalid orig_file metadata (size)", err)
	}
	if size < 0 {
		return OriginalFile{}, internal.NewParseError("invalid orig_file metadata (negative size)", nil)
	}

	return OriginalFile{
		Name:     name,
		Size:     size,
		MimeType: mimeType,
		DataRef:  dataRef,
	}, nil
}

// GetFilename returns the original filename from EncryptionProperties
func (p *Parser) GetFilename() string {
	props := p.GetEncryptionProperties()
	return props["Filename"]
}
