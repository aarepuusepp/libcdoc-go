package key

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
)

// PrivateKey represents a private key abstraction
// This wraps Go's crypto.PrivateKey with type information
type PrivateKey struct {
	Key crypto.PrivateKey
}

// RSAPrivateKey returns the RSA private key if available
func (pk *PrivateKey) RSAPrivateKey() (*rsa.PrivateKey, bool) {
	if key, ok := pk.Key.(*rsa.PrivateKey); ok {
		return key, true
	}
	return nil, false
}

// ECPrivateKey returns the EC private key if available
func (pk *PrivateKey) ECPrivateKey() (*ecdsa.PrivateKey, bool) {
	if key, ok := pk.Key.(*ecdsa.PrivateKey); ok {
		return key, true
	}
	return nil, false
}

// IsRSA returns true if the key is an RSA key
func (pk *PrivateKey) IsRSA() bool {
	_, ok := pk.Key.(*rsa.PrivateKey)
	return ok
}

// IsEC returns true if the key is an EC key
func (pk *PrivateKey) IsEC() bool {
	_, ok := pk.Key.(*ecdsa.PrivateKey)
	return ok
}
