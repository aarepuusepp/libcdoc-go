package cdoc

import (
	"encoding/base64"
	"encoding/xml"
	"io"

	"crypto/ecdsa"
	"crypto/x509"

	"github.com/aarepuusepp/libcdoc-go/v2/cert"
	"github.com/aarepuusepp/libcdoc-go/v2/crypto"
	"github.com/aarepuusepp/libcdoc-go/v2/internal"
	"github.com/aarepuusepp/libcdoc-go/v2/xmlenc"
)

const (
	// ENCDOCXMLVersion11 is the format version string for CDOC 1.1
	ENCDOCXMLVersion11 = "ENCDOC-XML|1.1"
	// ENCDOCXMLVersion10 is the format version string for CDOC 1.0
	ENCDOCXMLVersion10 = "ENCDOC-XML|1.0"
	// DDOCMimeType is the MIME type for DigiDoc documents
	DDOCMimeType = "http://www.sk.ee/DigiDoc/v1.3.0/digidoc.xsd"
)

// Composer implements XML composition for CDOC documents
type Composer struct {
	dataKey     []byte // AES-256 key for CDOC 1.1, AES-128 for CDOC 1.0
	recipients  []*x509.Certificate
	dataFiles   []DataFile
	version     Version
}

// DataFile represents a file to be encrypted
type DataFile struct {
	Name        string
	Content     io.Reader
	Size        int64
	MimeType    string
}

// NewComposer creates a new Composer instance
func NewComposer() *Composer {
	return &Composer{
		version: Version11, // Default to 1.1
	}
}

// SetVersion sets the CDOC version
func (c *Composer) SetVersion(version Version) {
	c.version = version
}

// SetRecipients sets the recipient certificates
func (c *Composer) SetRecipients(certs []*x509.Certificate) {
	c.recipients = certs
}

// SetDataFiles sets the data files to encrypt
func (c *Composer) SetDataFiles(files []DataFile) {
	c.dataFiles = files
}

// Compose generates the CDOC XML document
func (c *Composer) Compose(w io.Writer) error {
	// Generate encryption key
	var keySize int
	if c.version == Version11 {
		keySize = 32 // AES-256
	} else {
		keySize = 16 // AES-128
	}

	dataKey, err := crypto.GenerateDataEncryptionKey(keySize)
	if err != nil {
		return internal.NewEncryptionError("failed to generate encryption key", err)
	}
	c.dataKey = dataKey

	// Create XML structure
	if c.version == Version11 {
		return c.compose11(w)
	}
	return c.compose10(w)
}

// compose11 composes a CDOC 1.1 document
func (c *Composer) compose11(w io.Writer) error {
	// Encrypt content
	mimeType := "application/octet-stream"
	if len(c.dataFiles) > 1 {
		mimeType = DDOCMimeType
	}

	// Generate IV for GCM
	iv, err := crypto.GenerateIV(12) // 12 bytes for GCM
	if err != nil {
		return internal.NewEncryptionError("failed to generate IV", err)
	}

	// Prepare content to encrypt
	var contentToEncrypt []byte
	if len(c.dataFiles) > 1 {
		// Multiple files: create DDOC XML structure
		contentToEncrypt, err = c.createDDOCXML()
		if err != nil {
			return err
		}
	} else if len(c.dataFiles) == 1 {
		// Single file: read directly
		contentToEncrypt, err = io.ReadAll(c.dataFiles[0].Content)
		if err != nil {
			return internal.NewEncryptionError("failed to read data file", err)
		}
	}

	// Encrypt content with GCM
	ciphertext, err := crypto.EncryptAESGCM(contentToEncrypt, c.dataKey, iv)
	if err != nil {
		return internal.NewEncryptionError("failed to encrypt content", err)
	}

	// Prepend IV to encrypted content (IV || ciphertext)
	encryptedContent := append(iv, ciphertext...)

	// Build EncryptedData structure
	encryptedData := &xmlenc.EncryptedData{
		MimeType: mimeType,
		EncryptionMethod: xmlenc.EncryptionMethod{
			Algorithm: string(URI_AES256GCM),
		},
		KeyInfo: xmlenc.KeyInfo{},
		CipherData: xmlenc.CipherData{
			CipherValue: internal.EncodeBase64(encryptedContent),
		},
	}

	// Build recipients (EncryptedKey elements)
	var encryptedKeys []xmlenc.EncryptedKey
	for _, recipientCert := range c.recipients {
		encryptedKey, err := c.createRecipientEncryptedKey11(recipientCert)
		if err != nil {
			return err
		}
		encryptedKeys = append(encryptedKeys, *encryptedKey)
	}
	encryptedData.KeyInfo.EncryptedKeys = encryptedKeys

	// Add metadata
	props := c.buildEncryptionProperties()
	encryptedData.EncryptionProperties = props

	// Write XML
	encoder := xml.NewEncoder(w)
	encoder.Indent("", "  ")
	if err := encoder.Encode(encryptedData); err != nil {
		return internal.NewEncryptionError("failed to encode XML", err)
	}

	return nil
}

// compose10 composes a CDOC 1.0 document
func (c *Composer) compose10(w io.Writer) error {
	// Determine MIME type
	mimeType := "application/octet-stream"
	if len(c.dataFiles) > 1 {
		mimeType = DDOCMimeType
	}

	// Prepare content to encrypt
	var contentToEncrypt []byte
	var err error
	if len(c.dataFiles) > 1 {
		// Multiple files: create DDOC XML structure
		contentToEncrypt, err = c.createDDOCXML()
		if err != nil {
			return err
		}
	} else if len(c.dataFiles) == 1 {
		// Single file: read directly
		contentToEncrypt, err = io.ReadAll(c.dataFiles[0].Content)
		if err != nil {
			return internal.NewEncryptionError("failed to read data file", err)
		}
	}

	// Generate IV (16 bytes for CBC)
	iv, err := crypto.GenerateIV(16)
	if err != nil {
		return internal.NewEncryptionError("failed to generate IV", err)
	}

	// Encrypt with AES-128-CBC (padding is handled inside EncryptAESCBC)
	ciphertext, err := crypto.EncryptAESCBC(contentToEncrypt, c.dataKey, iv)
	if err != nil {
		return internal.NewEncryptionError("failed to encrypt content", err)
	}

	// Prepend IV to encrypted content (IV || ciphertext)
	encryptedContent := append(iv, ciphertext...)

	// Build EncryptedData structure
	encryptedData := &xmlenc.EncryptedData{
		MimeType: mimeType,
		EncryptionMethod: xmlenc.EncryptionMethod{
			Algorithm: string(URI_AES128CBC), // CDOC 1.0 uses AES-128-CBC
		},
		KeyInfo: xmlenc.KeyInfo{},
		CipherData: xmlenc.CipherData{
			CipherValue: internal.EncodeBase64(encryptedContent),
		},
	}

	// Build recipients (only RSA for CDOC 1.0)
	var encryptedKeys []xmlenc.EncryptedKey
	for _, recipientCert := range c.recipients {
		// CDOC 1.0 only supports RSA recipients
		if !cert.IsRSACertificate(recipientCert) {
			return internal.NewEncryptionError(
				"CDOC 1.0 only supports RSA recipients, certificate is not RSA",
				nil,
			)
		}

		encryptedKey, err := c.createRecipientEncryptedKey10(recipientCert)
		if err != nil {
			return err
		}
		encryptedKeys = append(encryptedKeys, *encryptedKey)
	}
	encryptedData.KeyInfo.EncryptedKeys = encryptedKeys

	// Add metadata
	props := c.buildEncryptionProperties()
	encryptedData.EncryptionProperties = props

	// Write XML
	encoder := xml.NewEncoder(w)
	encoder.Indent("", "  ")
	if err := encoder.Encode(encryptedData); err != nil {
		return internal.NewEncryptionError("failed to encode XML", err)
	}

	return nil
}

// createRecipientEncryptedKey10 creates an EncryptedKey for CDOC 1.0 (RSA only)
func (c *Composer) createRecipientEncryptedKey10(recipientCert *x509.Certificate) (*xmlenc.EncryptedKey, error) {
	cn := cert.ExtractCN(recipientCert)

	// Encrypt transport key with RSA PKCS#1 v1.5
	encryptedKeyBytes, err := crypto.EncryptRSA(c.dataKey, recipientCert)
	if err != nil {
		return nil, internal.NewEncryptionError("failed to encrypt transport key", err)
	}

	// Use the full certificate bytes
	certBytes := recipientCert.Raw
	certBase64 := internal.EncodeBase64(certBytes)

	return &xmlenc.EncryptedKey{
		Recipient: cn,
		EncryptionMethod: xmlenc.EncryptionMethod{
			Algorithm: string(URI_RSA15),
		},
		KeyInfo: xmlenc.KeyInfoElement{
			X509Data: &xmlenc.X509Data{
				X509Certificate: certBase64,
			},
		},
		CipherData: xmlenc.CipherData{
			CipherValue: internal.EncodeBase64(encryptedKeyBytes),
		},
	}, nil
}

// createRecipientEncryptedKey11 creates an EncryptedKey element for CDOC 1.1
func (c *Composer) createRecipientEncryptedKey11(recipientCert *x509.Certificate) (*xmlenc.EncryptedKey, error) {
	cn := cert.ExtractCN(recipientCert)

	if cert.IsRSACertificate(recipientCert) {
		return c.createRSAEncryptedKey(recipientCert, cn)
	} else if cert.IsECCertificate(recipientCert) {
		return c.createECEncryptedKey(recipientCert, cn)
	}

	return nil, internal.NewCertificateError(
		"unsupported certificate key type",
		nil,
	)
}

// createRSAEncryptedKey creates an RSA recipient EncryptedKey
func (c *Composer) createRSAEncryptedKey(recipientCert *x509.Certificate, cn string) (*xmlenc.EncryptedKey, error) {
	// Encrypt data key with RSA PKCS#1 v1.5
	encryptedKeyBytes, err := crypto.EncryptRSA(c.dataKey, recipientCert)
	if err != nil {
		return nil, err
	}

	// Use the full certificate bytes
	certBytes := recipientCert.Raw
	certBase64 := internal.EncodeBase64(certBytes)

	return &xmlenc.EncryptedKey{
		Recipient: cn,
		EncryptionMethod: xmlenc.EncryptionMethod{
			Algorithm: string(URI_RSA15),
		},
		KeyInfo: xmlenc.KeyInfoElement{
			X509Data: &xmlenc.X509Data{
				X509Certificate: certBase64,
			},
		},
		CipherData: xmlenc.CipherData{
			CipherValue: internal.EncodeBase64(encryptedKeyBytes),
		},
	}, nil
}

// createECEncryptedKey creates an EC recipient EncryptedKey
func (c *Composer) createECEncryptedKey(recipientCert *x509.Certificate, cn string) (*xmlenc.EncryptedKey, error) {
	// Extract EC public key
	ecPubKey, err := crypto.ExtractECPublicKeyFromCertificate(recipientCert)
	if err != nil {
		return nil, err
	}

	// Generate ephemeral key pair
	ephemeralPrivKey, err := crypto.GenerateECKeyPair(ecPubKey)
	if err != nil {
		return nil, err
	}

	// Perform ECDH key agreement
	sharedSecret, err := crypto.ECDHKeyAgreement(ephemeralPrivKey, ecPubKey)
	if err != nil {
		return nil, err
	}

	// Build ConcatKDF parameters
	algorithmID := []byte(ENCDOCXMLVersion11)
	
	// PartyUInfo: ephemeral public key bytes (from SubjectPublicKeyInfo)
	partyUInfo, err := encodeECPublicKeyBytes(ephemeralPrivKey.PublicKey)
	if err != nil {
		return nil, err
	}

	// PartyVInfo: recipient certificate bytes
	partyVInfo := recipientCert.Raw

	// Derive wrap key via ConcatKDF
	wrapKey, err := crypto.ConcatKDF(sharedSecret, algorithmID, partyUInfo, partyVInfo)
	if err != nil {
		return nil, err
	}

	// Wrap data key with AES-KW-256
	wrappedKey, err := crypto.WrapAES256(c.dataKey, wrapKey)
	if err != nil {
		return nil, err
	}

	// Encode ephemeral public key
	ephemeralPubKeyBase64 := encodeECPublicKeyBase64(ephemeralPrivKey.PublicKey)

	// Build AgreementMethod structure
	agreementMethod := &xmlenc.AgreementMethod{
		Algorithm: "http://www.w3.org/2009/xmlenc11#ECDH-ES",
		KeyDerivationMethod: &xmlenc.KeyDerivationMethod{
			Algorithm: "http://www.w3.org/2009/xmlenc11#ConcatKDF",
			ConcatKDFParams: &xmlenc.ConcatKDFParams{
				AlgorithmID: "00" + internal.EncodeHex(algorithmID),
				PartyUInfo:  "00" + internal.EncodeHex(partyUInfo),
				PartyVInfo:  "00" + internal.EncodeHex(partyVInfo),
				DigestMethod: xmlenc.DigestMethod{
					Algorithm: "http://www.w3.org/2001/04/xmlenc#sha384",
				},
			},
		},
		OriginatorKeyInfo: &xmlenc.OriginatorKeyInfo{
			KeyValue: &xmlenc.KeyValue{
				ECKeyValue: &xmlenc.ECKeyValue{
					NamedCurve: &xmlenc.NamedCurve{
						URI: "urn:oid:1.3.132.0.34", // secp384r1
					},
					PublicKey: ephemeralPubKeyBase64,
				},
			},
		},
		RecipientKeyInfo: &xmlenc.RecipientKeyInfo{
			X509Data: &xmlenc.X509Data{
				X509Certificate: internal.EncodeBase64(recipientCert.Raw),
			},
		},
	}

	return &xmlenc.EncryptedKey{
		Recipient: cn,
		EncryptionMethod: xmlenc.EncryptionMethod{
			Algorithm: string(URI_AES256KW),
		},
		KeyInfo: xmlenc.KeyInfoElement{
			AgreementMethod: agreementMethod,
		},
		CipherData: xmlenc.CipherData{
			CipherValue: internal.EncodeBase64(wrappedKey),
		},
	}, nil
}

// encodeECPublicKeyBytes encodes EC public key as raw point bytes (X + Y coordinates)
func encodeECPublicKeyBytes(pubKey ecdsa.PublicKey) ([]byte, error) {
	// Encode as uncompressed point: 48 bytes X + 48 bytes Y = 96 bytes
	xBytes := pubKey.X.Bytes()
	yBytes := pubKey.Y.Bytes()

	// Pad to 48 bytes each
	result := make([]byte, 96)
	copy(result[48-len(xBytes):48], xBytes)
	copy(result[96-len(yBytes):], yBytes)

	return result, nil
}

// encodeECPublicKeyBase64 encodes EC public key as base64 string
func encodeECPublicKeyBase64(pubKey ecdsa.PublicKey) string {
	bytes, _ := encodeECPublicKeyBytes(pubKey)
	// Add 0x04 prefix for uncompressed format
	fullBytes := append([]byte{0x04}, bytes...)
	return base64.StdEncoding.EncodeToString(fullBytes)
}

// buildEncryptionProperties builds metadata properties
func (c *Composer) buildEncryptionProperties() *xmlenc.EncryptionProperties {
	props := []xmlenc.EncryptionProperty{}

	// DocumentFormat
	var formatVersion string
	if c.version == Version11 {
		formatVersion = ENCDOCXMLVersion11
	} else {
		formatVersion = ENCDOCXMLVersion10
	}
	props = append(props, xmlenc.EncryptionProperty{
		Name:    "DocumentFormat",
		Content: formatVersion,
	})

	// LibraryVersion
	props = append(props, xmlenc.EncryptionProperty{
		Name:    "LibraryVersion",
		Content: "cdoc1-go|0.1",
	})

	// Filename (if single file)
	if len(c.dataFiles) == 1 {
		props = append(props, xmlenc.EncryptionProperty{
			Name:    "Filename",
			Content: c.dataFiles[0].Name,
		})
	}

	return &xmlenc.EncryptionProperties{
		Properties: props,
	}
}

