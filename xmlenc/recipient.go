package xmlenc

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
)

// Recipient represents a recipient abstraction
type Recipient interface {
	// GetCertificate returns the recipient's certificate
	GetCertificate() *x509.Certificate
	// GetCN returns the Common Name from the certificate
	GetCN() string
}

// RSARecipient represents an RSA recipient
type RSARecipient struct {
	Certificate  *x509.Certificate
	CN           string
	EncryptedKey []byte // Base64-encoded encrypted transport key
}

// GetCertificate returns the recipient's certificate
func (r *RSARecipient) GetCertificate() *x509.Certificate {
	return r.Certificate
}

// GetCN returns the Common Name
func (r *RSARecipient) GetCN() string {
	return r.CN
}

// ECRecipient represents an EC recipient
type ECRecipient struct {
	Certificate        *x509.Certificate
	CN                 string
	EphemeralPublicKey *ecdsa.PublicKey
	AlgorithmID        []byte
	PartyUInfo         []byte
	PartyVInfo         []byte
	DigestAlgorithm    string
	EncryptedKey       []byte // Base64-encoded wrapped transport key
}

// GetCertificate returns the recipient's certificate
func (r *ECRecipient) GetCertificate() *x509.Certificate {
	return r.Certificate
}

// GetCN returns the Common Name
func (r *ECRecipient) GetCN() string {
	return r.CN
}

// GetEphemeralPublicKey returns the ephemeral EC public key
func (r *ECRecipient) GetEphemeralPublicKey() *ecdsa.PublicKey {
	return r.EphemeralPublicKey
}

// GetAlgorithmID returns the AlgorithmID bytes
func (r *ECRecipient) GetAlgorithmID() []byte {
	return r.AlgorithmID
}

// GetPartyUInfo returns the PartyUInfo bytes
func (r *ECRecipient) GetPartyUInfo() []byte {
	return r.PartyUInfo
}

// GetPartyVInfo returns the PartyVInfo bytes
func (r *ECRecipient) GetPartyVInfo() []byte {
	return r.PartyVInfo
}

// GetDigestAlgorithm returns the digest algorithm URI used for ConcatKDF.
func (r *ECRecipient) GetDigestAlgorithm() string {
	return r.DigestAlgorithm
}

// GetEncryptedKey returns the encrypted/wrapped key (decoded from base64)
func (r *ECRecipient) GetEncryptedKey() ([]byte, error) {
	return base64.StdEncoding.DecodeString(string(r.EncryptedKey))
}
