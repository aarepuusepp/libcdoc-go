//go:build cgo
// +build cgo

package cdoc

import (
	"crypto/ecdsa"
	"crypto/x509"

	"github.com/miekg/pkcs11"
	"github.com/aarepuusepp/libcdoc-go/v2/crypto"
	"github.com/aarepuusepp/libcdoc-go/v2/internal"
	"github.com/aarepuusepp/libcdoc-go/v2/key"
)

// PKCS11Token implements the Token interface for PKCS#11 hardware tokens
type PKCS11Token struct {
	context     *key.PKCS11Context
	keyHandle   pkcs11.ObjectHandle
	certificate *x509.Certificate
}

// NewPKCS11Token creates a new PKCS11Token from a PKCS11Config
func NewPKCS11Token(config key.PKCS11Config) (*PKCS11Token, error) {
	// Create PKCS#11 context and initialize session
	context, err := key.NewPKCS11Context(config)
	if err != nil {
		return nil, internal.NewDecryptionError("failed to initialize PKCS#11 context", err)
	}

	// Find private key on token
	keyHandle, err := context.FindPrivateKey(config.Label, config.KeyID)
	if err != nil {
		context.Close()
		return nil, internal.NewDecryptionError("failed to find private key on token", err)
	}

	// Find certificate on token (for recipient matching)
	certificate, err := context.FindCertificate(config.Label, config.KeyID)
	if err != nil {
		context.Close()
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

// DecryptEC performs ECDH key agreement and decrypts an EC-encrypted transport key
// Note: EC decryption via PKCS#11 is currently not fully supported due to token-specific
// ECDH implementation requirements. This method will return an error indicating
// that token-specific EC support needs to be implemented.
func (t *PKCS11Token) DecryptEC(ephemeralPublicKey *ecdsa.PublicKey, algorithmID []byte, partyUInfo []byte, partyVInfo []byte, encryptedKey []byte) ([]byte, error) {
	if t.context == nil {
		return nil, internal.NewDecryptionError("PKCS#11 context not initialized", nil)
	}

	// Attempt EC key agreement via PKCS#11
	// This will currently return an error as EC support needs token-specific implementation
	sharedSecret, err := t.context.DecryptEC(t.keyHandle, ephemeralPublicKey)
	if err != nil {
		return nil, err
	}

	// If we got here, we have a shared secret (unlikely with current implementation)
	// Derive wrap key via ConcatKDF (same as software implementation)
	wrapKey, err := crypto.ConcatKDF(
		sharedSecret,
		algorithmID,
		partyUInfo,
		partyVInfo,
	)
	if err != nil {
		return nil, internal.NewDecryptionError("failed ConcatKDF", err)
	}

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

	// Attempt EC key agreement via PKCS#11
	// This will currently return an error as EC support needs token-specific implementation
	sharedSecret, err := t.context.DecryptEC(t.keyHandle, ephemeralPublicKey)
	if err != nil {
		return nil, err
	}

	// Return shared secret directly (CDOC2 will handle HKDF separately)
	return sharedSecret, nil
}

