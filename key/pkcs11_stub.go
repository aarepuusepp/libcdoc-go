//go:build !cgo
// +build !cgo

package key

import (
	"crypto/ecdsa"
	"crypto/x509"
)

// PKCS11Context is unavailable when built without CGO.
type PKCS11Context struct{}

func NewPKCS11Context(config PKCS11Config) (*PKCS11Context, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return nil, NewPKCS11Error("PKCS#11 support requires CGO-enabled build", nil)
}

func (c *PKCS11Context) Close() error {
	return nil
}

func (c *PKCS11Context) FindPrivateKey(label string, keyID []byte) (any, error) {
	return nil, NewPKCS11Error("PKCS#11 support requires CGO-enabled build", nil)
}

func (c *PKCS11Context) FindCertificate(label string, keyID []byte) (*x509.Certificate, error) {
	return nil, NewPKCS11Error("PKCS#11 support requires CGO-enabled build", nil)
}

func (c *PKCS11Context) FindMatchedKeyPair(recipient *x509.Certificate) (any, *x509.Certificate, error) {
	return nil, nil, NewPKCS11Error("PKCS#11 support requires CGO-enabled build", nil)
}

func (c *PKCS11Context) DecryptRSA(keyHandle any, encryptedKey []byte) ([]byte, error) {
	return nil, NewPKCS11Error("PKCS#11 support requires CGO-enabled build", nil)
}

func (c *PKCS11Context) DecryptEC(keyHandle any, ephemeralPublicKey *ecdsa.PublicKey) ([]byte, error) {
	return nil, NewPKCS11Error("PKCS#11 support requires CGO-enabled build", nil)
}
