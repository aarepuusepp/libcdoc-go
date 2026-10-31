package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"github.com/aarepuusepp/libcdoc-go/v2/internal"
)

// EncryptRSA encrypts data using RSA PKCS#1 v1.5 encryption
//
//nolint:staticcheck // CDOC 1.x compatibility requires RSA PKCS#1 v1.5 key transport.
func EncryptRSA(data []byte, cert *x509.Certificate) ([]byte, error) {
	pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, internal.NewEncryptionError(
			"certificate does not contain RSA public key",
			nil,
		)
	}

	// RSA encryption with PKCS#1 v1.5 padding
	encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, data)
	if err != nil {
		return nil, internal.NewEncryptionError("failed to encrypt with RSA", err)
	}

	return encrypted, nil
}

// DecryptRSA decrypts data using RSA PKCS#1 v1.5 decryption
//
//nolint:staticcheck // CDOC 1.x compatibility requires RSA PKCS#1 v1.5 key transport.
func DecryptRSA(encrypted []byte, privKey *rsa.PrivateKey) ([]byte, error) {
	decrypted, err := rsa.DecryptPKCS1v15(rand.Reader, privKey, encrypted)
	if err != nil {
		return nil, internal.NewDecryptionError("failed to decrypt with RSA", err)
	}

	return decrypted, nil
}

// EncryptRSAOAEP implements CDOC2 RSA-OAEP with SHA256, MGF1-SHA256 and empty label.
func EncryptRSAOAEP(data []byte, pub *rsa.PublicKey) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, data, nil)
}
func DecryptRSAOAEP(data []byte, priv *rsa.PrivateKey) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, data, nil)
}
