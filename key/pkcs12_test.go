package key

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/aarepuusepp/libcdoc-go/v2/internal"
	"software.sslmate.com/src/go-pkcs12"
)

// createTestPKCS12 creates a test PKCS#12 keystore with RSA key and certificate
func createTestPKCS12(t *testing.T, password string) []byte {
	// Generate RSA private key
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test User",
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	// Create self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	// Create PKCS#12 keystore
	p12Data, err := pkcs12.Encode(rand.Reader, privKey, cert, nil, password)
	if err != nil {
		t.Fatalf("Failed to create PKCS#12 keystore: %v", err)
	}

	return p12Data
}

func createTestPKCS12WithChain(t *testing.T, password string) []byte {
	// Create a CA certificate for inclusion in the PKCS#12 chain
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate CA RSA key: %v", err)
	}

	caTemplate := x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("Failed to create CA certificate: %v", err)
	}

	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("Failed to parse CA certificate: %v", err)
	}

	// Generate RSA private key for leaf certificate
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	leafTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test User",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, &leafTemplate, caCert, &privKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("Failed to create leaf certificate: %v", err)
	}

	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("Failed to parse leaf certificate: %v", err)
	}

	// Create PKCS#12 keystore with a CA chain entry included
	p12Data, err := pkcs12.Encode(rand.Reader, privKey, leafCert, []*x509.Certificate{caCert}, password)
	if err != nil {
		t.Fatalf("Failed to create PKCS#12 keystore with chain: %v", err)
	}

	return p12Data
}

func TestParsePKCS12_ValidKeystore(t *testing.T) {
	password := "test-password-123"
	p12Data := createTestPKCS12(t, password)

	keyEntry, err := ParsePKCS12(p12Data, password)
	if err != nil {
		t.Fatalf("ParsePKCS12() failed: %v", err)
	}

	if keyEntry == nil {
		t.Fatal("ParsePKCS12() returned nil keyEntry")
	}

	if keyEntry.PrivateKey == nil {
		t.Error("PrivateKey is nil")
	}

	if keyEntry.Certificate == nil {
		t.Error("Certificate is nil")
	}

	if keyEntry.Certificate.Subject.CommonName != "Test User" {
		t.Errorf("Expected CN 'Test User', got '%s'", keyEntry.Certificate.Subject.CommonName)
	}

	// Verify private key is RSA
	if !keyEntry.PrivateKey.IsRSA() {
		t.Error("Private key is not RSA")
	}
}

func TestParsePKCS12_KeystoreWithChain(t *testing.T) {
	password := "test-password-123"
	p12Data := createTestPKCS12WithChain(t, password)

	keyEntry, err := ParsePKCS12(p12Data, password)
	if err != nil {
		t.Fatalf("ParsePKCS12() failed: %v", err)
	}

	if keyEntry == nil {
		t.Fatal("ParsePKCS12() returned nil keyEntry")
	}

	if keyEntry.PrivateKey == nil {
		t.Error("PrivateKey is nil")
	}

	if keyEntry.Certificate == nil {
		t.Error("Certificate is nil")
	}

	if keyEntry.Certificate.Subject.CommonName != "Test User" {
		t.Errorf("Expected CN 'Test User', got '%s'", keyEntry.Certificate.Subject.CommonName)
	}
}

func TestParsePKCS12_WrongPassword(t *testing.T) {
	password := "correct-password"
	p12Data := createTestPKCS12(t, password)

	_, err := ParsePKCS12(p12Data, "wrong-password")
	if err == nil {
		t.Error("ParsePKCS12() should fail with wrong password")
	}

	// Verify it's a certificate error
	if _, ok := err.(*internal.CertificateError); !ok {
		t.Errorf("Expected CertificateError, got %T", err)
	}
}

func TestParsePKCS12_EmptyData(t *testing.T) {
	_, err := ParsePKCS12([]byte{}, "password")
	if err == nil {
		t.Error("ParsePKCS12() should fail with empty data")
	}

	if _, ok := err.(*internal.CertificateError); !ok {
		t.Errorf("Expected CertificateError, got %T", err)
	}
}

func TestParsePKCS12_InvalidData(t *testing.T) {
	_, err := ParsePKCS12([]byte("not-a-pkcs12-file"), "password")
	if err == nil {
		t.Error("ParsePKCS12() should fail with invalid data")
	}

	if _, ok := err.(*internal.CertificateError); !ok {
		t.Errorf("Expected CertificateError, got %T", err)
	}
}

