//go:build cgo
// +build cgo

package cdoc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"
	"os"
	"strconv"
	"testing"

	"github.com/aarepuusepp/libcdoc-go/v2/key"
)

// TestCDOC2_PKCS11_RSA tests CDOC 2.0 decryption with PKCS#11 token (RSA key)
// This test requires a PKCS#11 hardware token or software token to be available.
// Set environment variables:
//   - PKCS11_LIBRARY: Path to PKCS#11 library (e.g., "/usr/lib/softhsm/libsofthsm2.so")
//   - PKCS11_SLOT: Slot ID (optional, defaults to 0)
//   - PKCS11_PIN: User PIN for the token
//   - PKCS11_LABEL: Label of the key on the token (optional)
//   - PKCS11_KEY_ID: Key ID (optional, hex-encoded)
func TestCDOC2_PKCS11_RSA(t *testing.T) {
	// Check if PKCS#11 is configured
	library := os.Getenv("PKCS11_LIBRARY")
	if library == "" {
		t.Skip("PKCS11_LIBRARY environment variable not set, skipping PKCS#11 test")
	}

	pin := os.Getenv("PKCS11_PIN")
	if pin == "" {
		t.Skip("PKCS11_PIN environment variable not set, skipping PKCS#11 test")
	}

	// Parse slot from environment (defaults to 0)
	slot := 0
	if slotStr := os.Getenv("PKCS11_SLOT"); slotStr != "" {
		var err error
		slot, err = strconv.Atoi(slotStr)
		if err != nil {
			t.Fatalf("Invalid PKCS11_SLOT value: %v", err)
		}
	}

	// Parse key ID from environment (hex-encoded, optional)
	var keyID []byte
	if keyIDStr := os.Getenv("PKCS11_KEY_ID"); keyIDStr != "" {
		var err error
		keyID, err = hex.DecodeString(keyIDStr)
		if err != nil {
			t.Fatalf("Invalid PKCS11_KEY_ID value (must be hex-encoded): %v", err)
		}
	}

	config := key.PKCS11Config{
		Library: library,
		Slot:    slot,
		PIN:     pin,
		Label:   os.Getenv("PKCS11_LABEL"),
		KeyID:   keyID,
	}

	// Create decrypter with PKCS#11 token
	decrypter := NewDecrypter()
	if err := decrypter.WithPKCS11Token(config); err != nil {
		t.Fatalf("Failed to initialize PKCS#11 token: %v", err)
	}
	defer func() {
		if token, ok := decrypter.token.(*PKCS11Token); ok {
			if err := token.Close(); err != nil {
				t.Logf("Warning: Failed to close PKCS#11 token: %v", err)
			}
		}
	}()

	// Get certificate from token for encryption
	cert, err := decrypter.token.GetCertificate()
	if err != nil {
		t.Fatalf("Failed to get certificate from PKCS#11 token: %v", err)
	}

	// Verify certificate has RSA key
	if cert.PublicKeyAlgorithm != x509.RSA {
		t.Skip("Certificate does not have RSA public key, skipping RSA test")
	}

	// Encrypt CDOC 2.0 with RSA certificate
	var encrypted bytes.Buffer
	builder := NewBuilder().Version(Version20)
	if err := builder.WithRecipientCertificate(cert); err != nil {
		t.Fatalf("Failed to add recipient certificate: %v", err)
	}

	testData := []byte("hello-cdoc2-pkcs11-rsa")
	builder.WithDataFile("test.txt", bytes.NewReader(testData), int64(len(testData)))

	if err := builder.BuildToWriter(&encrypted); err != nil {
		t.Fatalf("Failed to encrypt CDOC 2.0: %v", err)
	}

	// Decrypt using PKCS#11 token
	decrypter2 := NewDecrypter()
	if err := decrypter2.WithPKCS11Token(config); err != nil {
		t.Fatalf("Failed to initialize PKCS#11 token for decryption: %v", err)
	}
	defer func() {
		if token, ok := decrypter2.token.(*PKCS11Token); ok {
			if err := token.Close(); err != nil {
				t.Logf("Warning: Failed to close PKCS#11 token: %v", err)
			}
		}
	}()

	decrypter2.WithCDOC(bytes.NewReader(encrypted.Bytes()))

	files, err := decrypter2.Decrypt()
	if err != nil {
		t.Fatalf("Failed to decrypt CDOC 2.0: %v", err)
	}

	if len(files) != 1 {
		t.Fatalf("Expected 1 file, got %d", len(files))
	}

	if !bytes.Equal(files[0].Content, testData) {
		t.Errorf("Decrypted content mismatch")
	}

	if files[0].Name != "test.txt" {
		t.Errorf("Expected filename 'test.txt', got '%s'", files[0].Name)
	}
}

// TestCDOC2_PKCS11_ECC tests CDOC 2.0 decryption with PKCS#11 token (ECC key)
// This test requires a PKCS#11 hardware token or software token with an ECC key.
// Set environment variables (same as TestCDOC2_PKCS11_RSA)
func TestCDOC2_PKCS11_ECC(t *testing.T) {
	// Check if PKCS#11 is configured
	library := os.Getenv("PKCS11_LIBRARY")
	if library == "" {
		t.Skip("PKCS11_LIBRARY environment variable not set, skipping PKCS#11 test")
	}

	pin := os.Getenv("PKCS11_PIN")
	if pin == "" {
		t.Skip("PKCS11_PIN environment variable not set, skipping PKCS#11 test")
	}

	// Parse slot from environment (defaults to 0)
	slot := 0
	if slotStr := os.Getenv("PKCS11_SLOT"); slotStr != "" {
		var err error
		slot, err = strconv.Atoi(slotStr)
		if err != nil {
			t.Fatalf("Invalid PKCS11_SLOT value: %v", err)
		}
	}

	// Parse key ID from environment (hex-encoded, optional)
	var keyID []byte
	if keyIDStr := os.Getenv("PKCS11_KEY_ID"); keyIDStr != "" {
		var err error
		keyID, err = hex.DecodeString(keyIDStr)
		if err != nil {
			t.Fatalf("Invalid PKCS11_KEY_ID value (must be hex-encoded): %v", err)
		}
	}

	config := key.PKCS11Config{
		Library: library,
		Slot:    slot,
		PIN:     pin,
		Label:   os.Getenv("PKCS11_LABEL"),
		KeyID:   keyID,
	}

	// Create decrypter with PKCS#11 token
	decrypter := NewDecrypter()
	if err := decrypter.WithPKCS11Token(config); err != nil {
		t.Fatalf("Failed to initialize PKCS#11 token: %v", err)
	}
	defer func() {
		if token, ok := decrypter.token.(*PKCS11Token); ok {
			if err := token.Close(); err != nil {
				t.Logf("Warning: Failed to close PKCS#11 token: %v", err)
			}
		}
	}()

	// Get certificate from token for encryption
	cert, err := decrypter.token.GetCertificate()
	if err != nil {
		t.Fatalf("Failed to get certificate from PKCS#11 token: %v", err)
	}

	// Verify certificate has ECC key (ECDSA)
	if cert.PublicKeyAlgorithm != x509.ECDSA {
		t.Skip("Certificate does not have ECC public key, skipping ECC test")
	}

	// Verify curve is secp384r1 (required for CDOC 2.0)
	if ecdsaPub, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
		if ecdsaPub.Curve.Params().BitSize != 384 {
			t.Skipf("Certificate uses curve with %d bits, CDOC 2.0 requires secp384r1 (384 bits)", ecdsaPub.Curve.Params().BitSize)
		}
	} else {
		t.Fatal("Failed to cast public key to ECDSA")
	}

	// Encrypt CDOC 2.0 with ECC certificate
	var encrypted bytes.Buffer
	builder := NewBuilder().Version(Version20)
	if err := builder.WithRecipientCertificate(cert); err != nil {
		t.Fatalf("Failed to add recipient certificate: %v", err)
	}

	testData := []byte("hello-cdoc2-pkcs11-ecc")
	builder.WithDataFile("test.txt", bytes.NewReader(testData), int64(len(testData)))

	if err := builder.BuildToWriter(&encrypted); err != nil {
		t.Fatalf("Failed to encrypt CDOC 2.0: %v", err)
	}

	// Decrypt using PKCS#11 token
	decrypter2 := NewDecrypter()
	if err := decrypter2.WithPKCS11Token(config); err != nil {
		t.Fatalf("Failed to initialize PKCS#11 token for decryption: %v", err)
	}
	defer func() {
		if token, ok := decrypter2.token.(*PKCS11Token); ok {
			if err := token.Close(); err != nil {
				t.Logf("Warning: Failed to close PKCS#11 token: %v", err)
			}
		}
	}()

	decrypter2.WithCDOC(bytes.NewReader(encrypted.Bytes()))

	files, err := decrypter2.Decrypt()
	if err != nil {
		t.Fatalf("Failed to decrypt CDOC 2.0: %v", err)
	}

	if len(files) != 1 {
		t.Fatalf("Expected 1 file, got %d", len(files))
	}

	if !bytes.Equal(files[0].Content, testData) {
		t.Errorf("Decrypted content mismatch")
	}

	if files[0].Name != "test.txt" {
		t.Errorf("Expected filename 'test.txt', got '%s'", files[0].Name)
	}
}
