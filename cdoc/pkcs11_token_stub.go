//go:build !cgo
// +build !cgo

package cdoc

import (
	"crypto/ecdsa"
	"crypto/x509"

	"github.com/aarepuusepp/libcdoc-go/v2/internal"
	"github.com/aarepuusepp/libcdoc-go/v2/key"
)

// PKCS11Token is unavailable when built without CGO.
type PKCS11Token struct{}

func NewPKCS11Token(config key.PKCS11Config) (*PKCS11Token, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return nil, internal.NewDecryptionError("PKCS#11 support requires CGO-enabled build", nil)
}

func (t *PKCS11Token) Close() error { return nil }

func (t *PKCS11Token) GetCertificate() (*x509.Certificate, error) {
	return nil, internal.NewCertificateError("PKCS#11 support requires CGO-enabled build", nil)
}

func (t *PKCS11Token) DecryptRSA(encryptedKey []byte) ([]byte, error) {
	return nil, internal.NewDecryptionError("PKCS#11 support requires CGO-enabled build", nil)
}

func (t *PKCS11Token) DecryptEC(ephemeralPublicKey *ecdsa.PublicKey, algorithmID []byte, partyUInfo []byte, partyVInfo []byte, encryptedKey []byte) ([]byte, error) {
	return nil, internal.NewDecryptionError("PKCS#11 support requires CGO-enabled build", nil)
}

func (t *PKCS11Token) DecryptECSharedSecret(ephemeralPublicKey *ecdsa.PublicKey) ([]byte, error) {
	return nil, internal.NewDecryptionError("PKCS#11 support requires CGO-enabled build", nil)
}

