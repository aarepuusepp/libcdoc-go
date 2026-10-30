package cdoc

import (
	"crypto/ecdsa"
	"crypto/x509"

	"github.com/aarepuusepp/libcdoc-go/v2/crypto"
	"github.com/aarepuusepp/libcdoc-go/v2/internal"
	"github.com/aarepuusepp/libcdoc-go/v2/key"
)

// PKCS12Token implements the Token interface for PKCS#12 keystores
type PKCS12Token struct {
	keyEntry *key.PKCS12KeyEntry
}

// NewPKCS12Token creates a new PKCS12Token from a PKCS12KeyEntry
func NewPKCS12Token(keyEntry *key.PKCS12KeyEntry) *PKCS12Token {
	return &PKCS12Token{
		keyEntry: keyEntry,
	}
}

// GetCertificate returns the certificate from the PKCS#12 keystore
func (t *PKCS12Token) GetCertificate() (*x509.Certificate, error) {
	if t.keyEntry == nil || t.keyEntry.Certificate == nil {
		return nil, internal.NewCertificateError("no certificate in PKCS#12 token", nil)
	}
	return t.keyEntry.Certificate, nil
}

// DecryptRSA decrypts an RSA-encrypted transport key
func (t *PKCS12Token) DecryptRSA(encryptedKey []byte) ([]byte, error) {
	if t.keyEntry == nil || t.keyEntry.PrivateKey == nil {
		return nil, internal.NewDecryptionError("no private key in PKCS#12 token", nil)
	}

	privKey, ok := t.keyEntry.PrivateKey.RSAPrivateKey()
	if !ok {
		return nil, internal.NewDecryptionError("private key is not RSA", nil)
	}

	return crypto.DecryptRSA(encryptedKey, privKey)
}

// DecryptECWithDigest performs ECDH and unwrap using the specified ConcatKDF digest.
func (t *PKCS12Token) DecryptECWithDigest(ephemeralPublicKey *ecdsa.PublicKey, algorithmID []byte, partyUInfo []byte, partyVInfo []byte, encryptedKey []byte, digestURI string) ([]byte, error) {
	if t.keyEntry == nil || t.keyEntry.PrivateKey == nil {
		return nil, internal.NewDecryptionError("no private key in PKCS#12 token", nil)
	}

	privKey, ok := t.keyEntry.PrivateKey.ECPrivateKey()
	if !ok {
		return nil, internal.NewDecryptionError("private key is not EC", nil)
	}

	// Perform ECDH key agreement (same logic as decryptECTransportKey)
	sharedSecret, err := crypto.ECDHKeyAgreement(privKey, ephemeralPublicKey)
	if err != nil {
		return nil, internal.NewDecryptionError("failed ECDH key agreement", err)
	}

	defer clear(sharedSecret)
	if digestURI == "" {
		digestURI = crypto.DigestSHA384URI
	}
	wrapKey, err := crypto.ConcatKDFWithDigest(
		sharedSecret,
		algorithmID,
		partyUInfo,
		partyVInfo,
		digestURI,
		32,
	)
	if err != nil {
		return nil, internal.NewDecryptionError("failed ConcatKDF", err)
	}

	defer clear(wrapKey)
	// Unwrap transport key using AES-KW-256
	dataKey, err := crypto.UnwrapAES256(encryptedKey, wrapKey)
	if err != nil {
		return nil, internal.NewDecryptionError("failed to unwrap transport key", err)
	}

	return dataKey, nil
}

// DecryptECSharedSecret performs ECDH key agreement for CDOC2 inline ECC locks.
func (t *PKCS12Token) DecryptECSharedSecret(ephemeralPublicKey *ecdsa.PublicKey) ([]byte, error) {
	if t.keyEntry == nil || t.keyEntry.PrivateKey == nil {
		return nil, internal.NewDecryptionError("no private key in PKCS#12 token", nil)
	}
	privKey, ok := t.keyEntry.PrivateKey.ECPrivateKey()
	if !ok {
		return nil, internal.NewDecryptionError("private key is not EC", nil)
	}
	return crypto.ECDHKeyAgreement(privKey, ephemeralPublicKey)
}

func (t *PKCS12Token) DecryptEC(ephemeralPublicKey *ecdsa.PublicKey, algorithmID, partyUInfo, partyVInfo, encryptedKey []byte) ([]byte, error) {
	return t.DecryptECWithDigest(ephemeralPublicKey, algorithmID, partyUInfo, partyVInfo, encryptedKey, "")
}
