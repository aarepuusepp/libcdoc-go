package cdoc

import (
	"io"
	"os"

	"crypto/x509"

	"github.com/yourorg/cdoc1-go/crypto"
	"github.com/yourorg/cdoc1-go/internal"
	"github.com/yourorg/cdoc1-go/key"
	"github.com/yourorg/cdoc1-go/xmlenc"
)

// Decrypter implements decryption of CDOC documents
type Decrypter struct {
	cdocReader    io.Reader
	cdocFile      string
	privateKey    *key.PrivateKey
	token         Token              // Optional: token for decryption (PKCS#11, PKCS#12, etc.)
	certificate   *x509.Certificate // Optional: for recipient selection when multiple recipients
	outputDir     string
	outputWriter  io.Writer
}

// NewDecrypter creates a new Decrypter instance
func NewDecrypter() *Decrypter {
	return &Decrypter{}
}

// WithCDOC sets the CDOC input from a reader
func (d *Decrypter) WithCDOC(reader io.Reader) *Decrypter {
	d.cdocReader = reader
	return d
}

// WithCDOCFromFile sets the CDOC input from a file path
func (d *Decrypter) WithCDOCFromFile(filepath string) error {
	file, err := os.Open(filepath)
	if err != nil {
		return internal.NewDecryptionError("failed to open CDOC file", err)
	}
	d.cdocReader = file
	d.cdocFile = filepath
	return nil
}

// WithPrivateKey sets the private key for decryption
func (d *Decrypter) WithPrivateKey(privKey *key.PrivateKey) *Decrypter {
	d.privateKey = privKey
	return d
}

// WithPrivateKeyFromFile loads a private key from a file path
func (d *Decrypter) WithPrivateKeyFromFile(filepath string) error {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return internal.NewDecryptionError("failed to read private key file", err)
	}

	privKey, err := key.ParsePrivateKey(data)
	if err != nil {
		return internal.NewDecryptionError("failed to parse private key", err)
	}

	d.privateKey = privKey
	return nil
}

// WithCertificate sets an optional certificate for recipient selection
func (d *Decrypter) WithCertificate(cert *x509.Certificate) *Decrypter {
	d.certificate = cert
	return d
}

// WithToken sets a token (PKCS#11, PKCS#12, etc.) for decryption
func (d *Decrypter) WithToken(token Token) *Decrypter {
	d.token = token
	return d
}

// WithPKCS12Token loads a PKCS#12 keystore and creates a token for decryption
// password is the keystore password
// alias is optional - if not provided, the first valid key entry will be used
func (d *Decrypter) WithPKCS12Token(filepath string, password string, alias ...string) error {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return internal.NewDecryptionError("failed to read PKCS#12 file", err)
	}

	keyEntry, err := key.ParsePKCS12(data, password, alias...)
	if err != nil {
		return internal.NewDecryptionError("failed to parse PKCS#12 keystore", err)
	}

	token := NewPKCS12Token(keyEntry)
	d.token = token

	// Automatically set certificate from token
	cert, err := token.GetCertificate()
	if err != nil {
		return internal.NewDecryptionError("failed to get certificate from PKCS#12 token", err)
	}
	d.certificate = cert

	return nil
}

// WithPKCS11Token loads a PKCS#11 token and creates a token for decryption
func (d *Decrypter) WithPKCS11Token(config key.PKCS11Config) error {
	token, err := NewPKCS11Token(config)
	if err != nil {
		return err
	}

	d.token = token

	// Automatically set certificate from token
	cert, err := token.GetCertificate()
	if err != nil {
		token.Close()
		return internal.NewDecryptionError("failed to get certificate from PKCS#11 token", err)
	}
	d.certificate = cert

	return nil
}

// Decrypt decrypts the CDOC and returns decrypted data files
func (d *Decrypter) Decrypt() ([]DecryptedFile, error) {
	if err := d.validateParameters(); err != nil {
		return nil, err
	}

	// Parse CDOC document
	parser := NewParser()
	if err := parser.Parse(d.cdocReader); err != nil {
		return nil, err
	}

	// Get recipients
	recipients, err := parser.GetRecipients()
	if err != nil {
		return nil, err
	}

	// Select recipient
	recipient, err := d.selectRecipient(recipients)
	if err != nil {
		return nil, err
	}

	// Decrypt transport key
	dataKey, err := d.decryptTransportKey(recipient)
	if err != nil {
		return nil, err
	}

	// Decrypt content
	encryptedContent, err := parser.GetEncryptedContent()
	if err != nil {
		return nil, err
	}

	version := parser.GetVersion()
	var plaintext []byte
	if version == Version11 {
		plaintext, err = d.decryptContent11(encryptedContent, dataKey)
	} else {
		plaintext, err = d.decryptContent10(encryptedContent, dataKey)
	}
	if err != nil {
		return nil, err
	}

	// Check if this is DDOC (multiple files)
	mimeType := parser.GetMimeType()
	if mimeType == DDOCMimeType {
		// Parse DDOC XML structure to extract all files
		return ParseDDOC(plaintext)
	}

	// Single file - extract filename from metadata
	filename := parser.GetFilename()
	if filename == "" {
		filename = "decrypted_file"
	}

	return []DecryptedFile{
		{
			Name:    filename,
			Content: plaintext,
		},
	}, nil
}

// DecryptToDirectory decrypts the CDOC and writes files to a directory
func (d *Decrypter) DecryptToDirectory(dirpath string) ([]string, error) {
	if err := os.MkdirAll(dirpath, 0755); err != nil {
		return nil, internal.NewDecryptionError("failed to create output directory", err)
	}

	files, err := d.Decrypt()
	if err != nil {
		return nil, err
	}

	var filepaths []string
	for _, file := range files {
		filepath := dirpath + "/" + file.Name
		if err := os.WriteFile(filepath, file.Content, 0644); err != nil {
			return nil, internal.NewDecryptionError("failed to write decrypted file", err)
		}
		filepaths = append(filepaths, filepath)
	}

	return filepaths, nil
}

// DecryptedFile represents a decrypted file
type DecryptedFile struct {
	Name    string
	Content []byte
}

// selectRecipient selects the appropriate recipient from the list
func (d *Decrypter) selectRecipient(recipients []xmlenc.Recipient) (xmlenc.Recipient, error) {
	if len(recipients) == 0 {
		return nil, internal.NewDecryptionError("no recipients found in CDOC", nil)
	}

	if len(recipients) == 1 {
		return recipients[0], nil
	}

	// Multiple recipients: need certificate to match
	if d.certificate == nil {
		return nil, internal.NewDecryptionError(
			"CDOC contains multiple recipients, certificate needed for selection",
			nil,
		)
	}

	// Find matching recipient
	for _, recipient := range recipients {
		if recipient.GetCertificate() != nil {
			// Compare certificates
			recipientCert := recipient.GetCertificate()
			if d.certificate.Equal(recipientCert) {
				return recipient, nil
			}
		}
	}

	return nil, internal.NewDecryptionError(
		"provided certificate does not match any recipient in CDOC",
		nil,
	)
}

// decryptTransportKey decrypts the transport key using the recipient's method
func (d *Decrypter) decryptTransportKey(recipient xmlenc.Recipient) ([]byte, error) {
	// Prefer token over private key
	if d.token != nil {
		return d.decryptTransportKeyWithToken(recipient)
	}

	if d.privateKey == nil {
		return nil, internal.NewDecryptionError("private key or token not set", nil)
	}

	switch r := recipient.(type) {
	case *xmlenc.RSARecipient:
		return d.decryptRSATransportKey(r)
	case *xmlenc.ECRecipient:
		return d.decryptECTransportKey(r)
	default:
		return nil, internal.NewDecryptionError("unsupported recipient type", nil)
	}
}

// decryptTransportKeyWithToken decrypts the transport key using a token
func (d *Decrypter) decryptTransportKeyWithToken(recipient xmlenc.Recipient) ([]byte, error) {
	if d.token == nil {
		return nil, internal.NewDecryptionError("token not set", nil)
	}

	switch r := recipient.(type) {
	case *xmlenc.RSARecipient:
		return d.token.DecryptRSA(r.EncryptedKey)
	case *xmlenc.ECRecipient:
		ephemeralKey := r.GetEphemeralPublicKey()
		encryptedKey, err := r.GetEncryptedKey()
		if err != nil {
			return nil, internal.NewDecryptionError("failed to get encrypted key", err)
		}
		return d.token.DecryptEC(
			ephemeralKey,
			r.GetAlgorithmID(),
			r.GetPartyUInfo(),
			r.GetPartyVInfo(),
			encryptedKey,
		)
	default:
		return nil, internal.NewDecryptionError("unsupported recipient type", nil)
	}
}

// decryptRSATransportKey decrypts RSA transport key
func (d *Decrypter) decryptRSATransportKey(recipient *xmlenc.RSARecipient) ([]byte, error) {
	privKey, ok := d.privateKey.RSAPrivateKey()
	if !ok {
		return nil, internal.NewDecryptionError("private key is not RSA", nil)
	}

	return crypto.DecryptRSA(recipient.EncryptedKey, privKey)
}

// decryptECTransportKey decrypts EC transport key
func (d *Decrypter) decryptECTransportKey(recipient *xmlenc.ECRecipient) ([]byte, error) {
	privKey, ok := d.privateKey.ECPrivateKey()
	if !ok {
		return nil, internal.NewDecryptionError("private key is not EC", nil)
	}

	// Perform ECDH key agreement
	sharedSecret, err := crypto.ECDHKeyAgreement(privKey, recipient.GetEphemeralPublicKey())
	if err != nil {
		return nil, internal.NewDecryptionError("failed ECDH key agreement", err)
	}

	// Derive wrap key via ConcatKDF
	wrapKey, err := crypto.ConcatKDF(
		sharedSecret,
		recipient.GetAlgorithmID(),
		recipient.GetPartyUInfo(),
		recipient.GetPartyVInfo(),
	)
	if err != nil {
		return nil, internal.NewDecryptionError("failed ConcatKDF", err)
	}

	// Unwrap transport key
	encryptedKey, err := recipient.GetEncryptedKey()
	if err != nil {
		return nil, internal.NewDecryptionError("failed to decode encrypted key", err)
	}

	return crypto.UnwrapAES256(encryptedKey, wrapKey)
}

// decryptContent11 decrypts CDOC 1.1 content (AES-256-GCM)
func (d *Decrypter) decryptContent11(encryptedContent []byte, dataKey []byte) ([]byte, error) {
	if len(encryptedContent) < 12 {
		return nil, internal.NewDecryptionError("encrypted content too short", nil)
	}

	// Extract IV (first 12 bytes)
	iv := encryptedContent[:12]
	ciphertext := encryptedContent[12:]

	return crypto.DecryptAESGCM(ciphertext, dataKey, iv)
}

// decryptContent10 decrypts CDOC 1.0 content (AES-128-CBC)
func (d *Decrypter) decryptContent10(encryptedContent []byte, dataKey []byte) ([]byte, error) {
	if len(encryptedContent) < 16 {
		return nil, internal.NewDecryptionError("encrypted content too short", nil)
	}

	// Extract IV (first 16 bytes)
	iv := encryptedContent[:16]
	ciphertext := encryptedContent[16:]

	return crypto.DecryptAESCBC(ciphertext, dataKey, iv)
}

// validateParameters validates required parameters are set
func (d *Decrypter) validateParameters() error {
	if d.cdocReader == nil && d.cdocFile == "" {
		return internal.NewDecryptionError("CDOC input not set", nil)
	}

	if d.privateKey == nil && d.token == nil {
		return internal.NewDecryptionError("private key or token not set", nil)
	}

	return nil
}
