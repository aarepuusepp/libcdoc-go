//go:build !cgo
// +build !cgo

package key

import (
	"crypto/tls"
	"crypto/x509"
)

// PKCS11Signer is unavailable when built without CGO.
type PKCS11Signer struct{}

// NewPKCS11Signer is unavailable when built without CGO.
func NewPKCS11Signer(config PKCS11Config) (*PKCS11Signer, *x509.Certificate, error) {
	return nil, nil, NewPKCS11Error("PKCS#11 signer requires CGO-enabled build", nil)
}

// Close is a no-op on stub builds.
func (s *PKCS11Signer) Close() error { return nil }

// TLSCertificateFromPKCS11 is unavailable when built without CGO.
func TLSCertificateFromPKCS11(config PKCS11Config) (tls.Certificate, error) {
	return tls.Certificate{}, NewPKCS11Error("PKCS#11 TLS certificate requires CGO-enabled build", nil)
}
