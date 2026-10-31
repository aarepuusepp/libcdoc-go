package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"
)

func TestValidateKeyUsage_RSA_KeyEncipherment(t *testing.T) {
	// Create a mock RSA certificate with keyEncipherment
	cert := &x509.Certificate{
		KeyUsage: x509.KeyUsageKeyEncipherment,
	}

	err := ValidateKeyUsage(cert, true)
	if err != nil {
		t.Errorf("ValidateKeyUsage() for RSA with keyEncipherment should not fail: %v", err)
	}
}

func TestValidateKeyUsage_RSA_NoKeyEncipherment(t *testing.T) {
	cert := &x509.Certificate{
		KeyUsage: x509.KeyUsageDigitalSignature, // Missing keyEncipherment
	}

	err := ValidateKeyUsage(cert, true)
	if err == nil {
		t.Error("ValidateKeyUsage() for RSA without keyEncipherment should fail")
	}
}

func TestValidateKeyUsage_EC_KeyAgreement(t *testing.T) {
	cert := &x509.Certificate{
		KeyUsage: x509.KeyUsageKeyAgreement,
	}

	err := ValidateKeyUsage(cert, false)
	if err != nil {
		t.Errorf("ValidateKeyUsage() for EC with keyAgreement should not fail: %v", err)
	}
}

func TestValidateKeyUsage_EC_NoKeyAgreement(t *testing.T) {
	cert := &x509.Certificate{
		KeyUsage: x509.KeyUsageDigitalSignature, // Missing keyAgreement
	}

	err := ValidateKeyUsage(cert, false)
	if err == nil {
		t.Error("ValidateKeyUsage() for EC without keyAgreement should fail")
	}
}

func TestIsRSACertificate(t *testing.T) {
	// Generate RSA key for testing
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	cert := &x509.Certificate{
		PublicKey:          privKey.Public(),
		PublicKeyAlgorithm: x509.RSA,
	}

	if !IsRSACertificate(cert) {
		t.Error("IsRSACertificate() should return true for RSA certificate")
	}
}

func TestIsECCertificate(t *testing.T) {
	// Generate EC key for testing
	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate EC key: %v", err)
	}

	cert := &x509.Certificate{
		PublicKey:          privKey.Public(),
		PublicKeyAlgorithm: x509.ECDSA,
	}

	if !IsECCertificate(cert) {
		t.Error("IsECCertificate() should return true for EC certificate")
	}
}

func TestValidateCertificate_Nil(t *testing.T) {
	err := ValidateCertificate(nil)
	if err == nil {
		t.Error("ValidateCertificate() with nil certificate should fail")
	}
}

func TestValidateRecipientCertificate_RSA(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	cert := &x509.Certificate{
		PublicKey:          privKey.Public(),
		PublicKeyAlgorithm: x509.RSA,
		KeyUsage:           x509.KeyUsageKeyEncipherment,
	}

	err = ValidateRecipientCertificate(cert)
	if err != nil {
		t.Errorf("ValidateRecipientCertificate() for valid RSA cert should not fail: %v", err)
	}
}

func TestValidateRecipientCertificate_EC(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate EC key: %v", err)
	}

	cert := &x509.Certificate{
		PublicKey:          privKey.Public(),
		PublicKeyAlgorithm: x509.ECDSA,
		KeyUsage:           x509.KeyUsageKeyAgreement,
	}

	err = ValidateRecipientCertificate(cert)
	if err != nil {
		t.Errorf("ValidateRecipientCertificate() for valid EC cert should not fail: %v", err)
	}
}
