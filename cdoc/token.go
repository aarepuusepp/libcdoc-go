package cdoc

import (
	"crypto/ecdsa"
	"crypto/x509"
)

// Token represents a cryptographic token (PKCS#11, PKCS#12, etc.)
// that can provide a certificate and perform decryption operations
type Token interface {
	// GetCertificate returns the certificate associated with this token
	GetCertificate() (*x509.Certificate, error)

	// DecryptRSA decrypts an RSA-encrypted transport key
	DecryptRSA(encryptedKey []byte) ([]byte, error)

	// DecryptEC performs ECDH key agreement and decrypts an EC-encrypted transport key
	// ephemeralPublicKey is the ephemeral public key from the CDOC recipient
	// algorithmID, partyUInfo, partyVInfo are ConcatKDF parameters from the recipient
	// encryptedKey is the wrapped content encryption key
	DecryptEC(ephemeralPublicKey *ecdsa.PublicKey, algorithmID []byte, partyUInfo []byte, partyVInfo []byte, encryptedKey []byte) ([]byte, error)
}

