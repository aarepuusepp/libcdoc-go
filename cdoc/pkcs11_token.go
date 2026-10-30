//go:build cgo
// +build cgo

package cdoc

import (
	"crypto/ecdsa"
	"crypto/x509"

	"github.com/aarepuusepp/libcdoc-go/v2/crypto"
	"github.com/aarepuusepp/libcdoc-go/v2/internal"
	"github.com/aarepuusepp/libcdoc-go/v2/key"
	"github.com/miekg/pkcs11"
)

// PKCS11Token implements the Token interface for PKCS#11 hardware tokens
type PKCS11Token struct {
	context     *key.PKCS11Context
	keyHandle   pkcs11.ObjectHandle
	certificate *x509.Certificate
}

// NewPKCS11Token creates a new PKCS11Token from a PKCS11Config
func NewPKCS11Token(config key.PKCS11Config) (*PKCS11Token, error) {
	context, err := key.NewPKCS11Context(config)
	if err != nil {
		return nil, internal.NewDecryptionError("failed to initialize PKCS#11 context", err)
	}

	var keyHandle pkcs11.ObjectHandle
	var certificate *x509.Certificate

	if config.RecipientCert != nil {
		keyHandle, certificate, err = context.FindMatchedKeyPair(config.RecipientCert)
	} else {
		keyHandle, err = context.FindPrivateKey(config.Label, config.KeyID)
		if err != nil {
			_ = context.Close()
			return nil, internal.NewDecryptionError("failed to find private key on token", err)
		}
		certificate, err = context.FindCertificate(config.Label, config.KeyID)
	}
	if err != nil {
		_ = context.Close()
		return nil, internal.NewDecryptionError("failed to find certificate on token", err)
	}

	return &PKCS11Token{
		context:     context,
		keyHandle:   keyHandle,
		certificate: certificate,
	}, nil
}

// Close closes the PKCS#11 session
func (t *PKCS11Token) Close() error {
	if t.context != nil {
		return t.context.Close()
	}
	return nil
}

// GetCertificate returns the certificate from the PKCS#11 token
func (t *PKCS11Token) GetCertificate() (*x509.Certificate, error) {
	if t.certificate == nil {
		return nil, internal.NewCertificateError("no certificate in PKCS#11 token", nil)
	}
	return t.certificate, nil
}

// DecryptRSA decrypts an RSA-encrypted transport key using the PKCS#11 token
func (t *PKCS11Token) DecryptRSA(encryptedKey []byte) ([]byte, error) {
	if t.context == nil {
		return nil, internal.NewDecryptionError("PKCS#11 context not initialized", nil)
	}

	return t.context.DecryptRSA(t.keyHandle, encryptedKey)
}

// DecryptECWithDigest performs ECDH and unwrap using the specified ConcatKDF digest.
func (t *PKCS11Token) DecryptECWithDigest(ephemeralPublicKey *ecdsa.PublicKey, algorithmID []byte, partyUInfo []byte, partyVInfo []byte, encryptedKey []byte, digestURI string) ([]byte, error) {
	if t.context == nil {
		return nil, internal.NewDecryptionError("PKCS#11 context not initialized", nil)
	}

	sharedSecret, err := t.context.DecryptEC(t.keyHandle, ephemeralPublicKey)
	if err != nil {
		return nil, err
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

// DecryptECSharedSecret performs ECDH key agreement and returns only the shared secret
// This method is used by CDOC2 which uses HKDF instead of ConcatKDF
// Note: EC support via PKCS#11 may require token-specific implementation
func (t *PKCS11Token) DecryptECSharedSecret(ephemeralPublicKey *ecdsa.PublicKey) ([]byte, error) {
	if t.context == nil {
		return nil, internal.NewDecryptionError("PKCS#11 context not initialized", nil)
	}

	// Derive the shared secret on the token without exporting the private key.
	sharedSecret, err := t.context.DecryptEC(t.keyHandle, ephemeralPublicKey)
	if err != nil {
		return nil, err
	}

	// Return shared secret directly (CDOC2 will handle HKDF separately)
	return sharedSecret, nil
}

func (t *PKCS11Token) DecryptEC(ephemeralPublicKey *ecdsa.PublicKey, algorithmID, partyUInfo, partyVInfo, encryptedKey []byte) ([]byte, error) {
	return t.DecryptECWithDigest(ephemeralPublicKey, algorithmID, partyUInfo, partyVInfo, encryptedKey, "")
}
