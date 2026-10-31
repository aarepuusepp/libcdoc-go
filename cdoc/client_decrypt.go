package cdoc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io"

	c2 "github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2"
	"github.com/aarepuusepp/libcdoc-go/v2/internal"
	"github.com/aarepuusepp/libcdoc-go/v2/xmlenc"
)

// ClientUnwrapChallenge contains transport-key unwrap parameters for client-side PKCS#11.
type ClientUnwrapChallenge struct {
	CdocVersion      string `json:"cdocVersion"`
	RecipientType    string `json:"recipientType"`
	RecipientCertPEM string `json:"recipientCertPem"`

	EncryptedKeyB64       string `json:"encryptedKeyB64,omitempty"`
	EphemeralPublicKeyB64 string `json:"ephemeralPublicKeyB64,omitempty"`
	AlgorithmIDB64        string `json:"algorithmIdB64,omitempty"`
	PartyUInfoB64         string `json:"partyUInfoB64,omitempty"`
	PartyVInfoB64         string `json:"partyVInfoB64,omitempty"`
	DigestAlgorithm       string `json:"digestAlgorithm,omitempty"`
	WrappedKeyB64         string `json:"wrappedKeyB64,omitempty"`
	// RecipientKeyB64 is the CDOC2 inline recipient public key bytes (required for ECC unwrap).
	RecipientKeyB64 string `json:"recipientKeyB64,omitempty"`
}

// PrepareClientUnwrap parses a CDOC 1.0/1.1/2.0 container and returns unwrap parameters for the matching recipient.
func PrepareClientUnwrap(cdocBytes []byte, recipientCert *x509.Certificate) (*ClientUnwrapChallenge, error) {
	if recipientCert == nil {
		return nil, internal.NewDecryptionError("recipient certificate is required", nil)
	}
	if len(cdocBytes) == 0 {
		return nil, internal.NewDecryptionError("CDOC data is empty", nil)
	}

	readerAt := bytes.NewReader(cdocBytes)
	ver, err := DetectFileVersion(readerAt)
	if err != nil {
		return nil, err
	}
	if ver == Version20 {
		return prepareClientUnwrapCDOC2(cdocBytes, recipientCert)
	}

	parser := NewParser()
	if err := parser.Parse(bytes.NewReader(cdocBytes)); err != nil {
		return nil, err
	}

	recipients, err := parser.GetRecipients()
	if err != nil {
		return nil, err
	}

	d := NewDecrypter().WithCertificate(recipientCert)
	recipient, err := d.selectRecipient(recipients)
	if err != nil {
		return nil, err
	}

	challenge := &ClientUnwrapChallenge{
		CdocVersion:      string(parser.GetVersion()),
		RecipientCertPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: recipientCert.Raw})),
	}

	switch r := recipient.(type) {
	case *xmlenc.RSARecipient:
		challenge.RecipientType = "RSA"
		challenge.EncryptedKeyB64 = base64.StdEncoding.EncodeToString(r.EncryptedKey)
	case *xmlenc.ECRecipient:
		challenge.RecipientType = "EC"
		challenge.DigestAlgorithm = r.GetDigestAlgorithm()
		challenge.AlgorithmIDB64 = base64.StdEncoding.EncodeToString(r.GetAlgorithmID())
		challenge.PartyUInfoB64 = base64.StdEncoding.EncodeToString(r.GetPartyUInfo())
		challenge.PartyVInfoB64 = base64.StdEncoding.EncodeToString(r.GetPartyVInfo())
		ephemeralKey := r.GetEphemeralPublicKey()
		if ephemeralKey != nil {
			point, err := ephemeralKey.Bytes()
			if err != nil {
				return nil, internal.NewDecryptionError("invalid ephemeral public key", err)
			}
			challenge.EphemeralPublicKeyB64 = base64.StdEncoding.EncodeToString(point)
		}
		wrappedKey, err := r.GetEncryptedKey()
		if err != nil {
			return nil, internal.NewDecryptionError("failed to get encrypted key", err)
		}
		challenge.WrappedKeyB64 = base64.StdEncoding.EncodeToString(wrappedKey)
	default:
		return nil, internal.NewDecryptionError("unsupported recipient type", nil)
	}

	return challenge, nil
}

// FinishClientDecrypt decrypts CDOC content using a content encryption key obtained from client-side unwrap.
func FinishClientDecrypt(cdocBytes []byte, recipientCert *x509.Certificate, cek []byte) ([]DecryptedFile, error) {
	if recipientCert == nil {
		return nil, internal.NewDecryptionError("recipient certificate is required", nil)
	}
	if len(cek) == 0 {
		return nil, internal.NewDecryptionError("content encryption key is empty", nil)
	}

	readerAt := bytes.NewReader(cdocBytes)
	ver, err := DetectFileVersion(readerAt)
	if err != nil {
		return nil, err
	}
	if ver == Version20 {
		return finishClientDecryptCDOC2(cdocBytes, recipientCert, cek)
	}

	parser := NewParser()
	if err := parser.Parse(bytes.NewReader(cdocBytes)); err != nil {
		return nil, err
	}

	recipients, err := parser.GetRecipients()
	if err != nil {
		return nil, err
	}

	d := NewDecrypter().WithCertificate(recipientCert)
	if _, err := d.selectRecipient(recipients); err != nil {
		return nil, err
	}

	encryptedContent, err := parser.GetEncryptedContent()
	if err != nil {
		return nil, err
	}

	version := parser.GetVersion()
	var plaintext []byte
	if version == Version11 {
		plaintext, err = d.decryptContent11(encryptedContent, cek)
	} else {
		plaintext, err = d.decryptContent10(encryptedContent, cek)
	}
	if err != nil {
		return nil, err
	}

	mimeType := parser.GetMimeType()
	if mimeType == DDOCMimeType {
		return ParseDDOC(plaintext)
	}

	filename := parser.GetFilename()
	if filename == "" {
		filename = "decrypted.bin"
	}
	return []DecryptedFile{{Name: filename, Content: plaintext}}, nil
}

// DecodeEphemeralPublicKey reconstructs an EC public key from uncompressed point bytes.
func DecodeEphemeralPublicKey(curve elliptic.Curve, point []byte) (*ecdsa.PublicKey, error) {
	if curve == nil {
		return nil, internal.NewDecryptionError("EC curve is required", nil)
	}
	if len(point) == 0 {
		return nil, internal.NewDecryptionError("ephemeral public key is empty", nil)
	}
	public, err := ecdsa.ParseUncompressedPublicKey(curve, point)
	if err != nil {
		return nil, internal.NewDecryptionError("invalid ephemeral public key encoding", nil)
	}
	return public, nil
}

// ChallengeEncryptedKey returns RSA encrypted key bytes from the challenge.
func (c *ClientUnwrapChallenge) ChallengeEncryptedKey() ([]byte, error) {
	return decodeChallengeB64(c.EncryptedKeyB64, "encryptedKey")
}

// ChallengeWrappedKey returns EC wrapped key bytes from the challenge.
func (c *ClientUnwrapChallenge) ChallengeWrappedKey() ([]byte, error) {
	return decodeChallengeB64(c.WrappedKeyB64, "wrappedKey")
}

func decodeChallengeB64(value, field string) ([]byte, error) {
	if value == "" {
		return nil, internal.NewDecryptionError(field+" is required", nil)
	}
	out, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, internal.NewDecryptionError("invalid base64 for "+field, err)
	}
	return out, nil
}

// ChallengeEphemeralPoint returns ephemeral EC point bytes.
func (c *ClientUnwrapChallenge) ChallengeEphemeralPoint() ([]byte, error) {
	return decodeChallengeB64(c.EphemeralPublicKeyB64, "ephemeralPublicKey")
}

func decodeOptionalB64(value string) ([]byte, error) {
	if value == "" {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(value)
}

// RecipientCertificate parses RecipientCertPEM from the challenge.
func (c *ClientUnwrapChallenge) RecipientCertificate() (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(c.RecipientCertPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, internal.NewCertificateError("invalid recipient certificate PEM", nil)
	}
	return x509.ParseCertificate(block.Bytes)
}

// ReadAllCDOCBytes reads CDOC bytes from a reader.
func ReadAllCDOCBytes(r io.Reader) ([]byte, error) {
	return io.ReadAll(r)
}

// InferCurveFromCert picks a curve for EC unwrap based on the recipient certificate.
func InferCurveFromCert(cert *x509.Certificate) elliptic.Curve {
	if cert == nil || cert.PublicKey == nil {
		return elliptic.P384()
	}
	if pub, ok := cert.PublicKey.(*ecdsa.PublicKey); ok && pub.Curve != nil {
		return pub.Curve
	}
	return elliptic.P384()
}

func prepareClientUnwrapCDOC2(cdocBytes []byte, recipientCert *x509.Certificate) (*ClientUnwrapChallenge, error) {
	reader, err := c2.NewReader(bytes.NewReader(cdocBytes))
	if err != nil {
		return nil, err
	}
	if _, err := reader.ReadHeader(); err != nil {
		return nil, err
	}
	locks, err := reader.GetLocks()
	if err != nil {
		return nil, err
	}

	var matched *c2.Lock
	for i := range locks {
		lock := locks[i]
		if lock.Type != c2.LockTypePublicKey {
			continue
		}
		ok, err := lock.MatchesCertificate(recipientCert)
		if err != nil {
			return nil, err
		}
		if ok {
			matched = &locks[i]
			break
		}
	}
	if matched == nil {
		return nil, internal.NewDecryptionError("no matching inline recipient for certificate", nil)
	}

	challenge := &ClientUnwrapChallenge{
		CdocVersion:      "2.0",
		RecipientCertPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: recipientCert.Raw})),
	}
	switch {
	case matched.IsRSA():
		challenge.RecipientType = "RSA"
		challenge.EncryptedKeyB64 = base64.StdEncoding.EncodeToString(matched.KeyMaterial)
		challenge.RecipientKeyB64 = base64.StdEncoding.EncodeToString(matched.RecipientKey)
	case matched.IsECC():
		challenge.RecipientType = "EC"
		challenge.EphemeralPublicKeyB64 = base64.StdEncoding.EncodeToString(matched.KeyMaterial)
		challenge.RecipientKeyB64 = base64.StdEncoding.EncodeToString(matched.RecipientKey)
	default:
		return nil, internal.NewDecryptionError("unsupported inline recipient type", nil)
	}
	return challenge, nil
}

func finishClientDecryptCDOC2(cdocBytes []byte, recipientCert *x509.Certificate, kek []byte) ([]DecryptedFile, error) {
	if len(kek) != c2.KeyLen {
		return nil, internal.NewDecryptionError("derived key must be 32 bytes", nil)
	}
	kekCopy := append([]byte(nil), kek...)
	defer func() {
		for i := range kekCopy {
			kekCopy[i] = 0
		}
	}()

	reader, err := c2.NewReader(bytes.NewReader(cdocBytes))
	if err != nil {
		return nil, err
	}
	if _, err := reader.ReadHeader(); err != nil {
		return nil, err
	}
	locks, err := reader.GetLocks()
	if err != nil {
		return nil, err
	}

	var matched *c2.Lock
	for i := range locks {
		lock := locks[i]
		if lock.Type != c2.LockTypePublicKey {
			continue
		}
		ok, err := lock.MatchesCertificate(recipientCert)
		if err != nil {
			return nil, err
		}
		if ok {
			matched = &locks[i]
			break
		}
	}
	if matched == nil {
		return nil, internal.NewDecryptionError("no matching inline recipient for certificate", nil)
	}

	fmk := c2.XOREncrypt(matched.EncryptedFMK, kekCopy)
	defer func() {
		for i := range fmk {
			fmk[i] = 0
		}
	}()

	if err := reader.BeginDecryption(fmk); err != nil {
		return nil, err
	}
	defer func() { _ = reader.FinishDecryption() }()

	return collectCDOC2DecryptedFiles(reader)
}

func collectCDOC2DecryptedFiles(reader *c2.Reader) ([]DecryptedFile, error) {
	var files []DecryptedFile
	for {
		name, size, err := reader.NextFile()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		// Grow only as data is read; never allocate from an untrusted TAR size.
		buf, err := io.ReadAll(io.LimitReader(reader, size))
		if err != nil {
			return nil, internal.NewDecryptionError("failed to read tar entry", err)
		}
		if int64(len(buf)) != size {
			return nil, internal.NewDecryptionError("truncated tar entry", io.ErrUnexpectedEOF)
		}
		files = append(files, DecryptedFile{Name: name, Content: buf})
	}
	return files, nil
}
