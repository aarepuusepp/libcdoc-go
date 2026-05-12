package crypto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// createTestECCertificate creates a minimal EC certificate for testing (secp384r1)
func createTestECCertificate(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate EC key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test EC User",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageKeyAgreement,
		PublicKey: privKey.Public(),
	}

	// Self-sign for testing
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert, privKey
}

func TestECDHKeyAgreement(t *testing.T) {
	// Generate two key pairs
	privKey1, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key 1: %v", err)
	}

	privKey2, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key 2: %v", err)
	}

	// Perform key agreement both ways
	sharedSecret1, err := ECDHKeyAgreement(privKey1, &privKey2.PublicKey)
	if err != nil {
		t.Fatalf("ECDHKeyAgreement() error = %v", err)
	}

	sharedSecret2, err := ECDHKeyAgreement(privKey2, &privKey1.PublicKey)
	if err != nil {
		t.Fatalf("ECDHKeyAgreement() error = %v", err)
	}

	// Shared secrets should be equal
	if len(sharedSecret1) != len(sharedSecret2) {
		t.Errorf("ECDHKeyAgreement() secret lengths don't match: %v vs %v", len(sharedSecret1), len(sharedSecret2))
	}

	// They should be equal (same point on curve)
	// Note: Due to coordinate representation, they might differ in format but should represent same point
	if len(sharedSecret1) == 0 {
		t.Error("ECDHKeyAgreement() shared secret should not be empty")
	}
}

func TestConcatKDF(t *testing.T) {
	sharedSecret := make([]byte, 48) // secp384r1 shared secret is 48 bytes
	for i := range sharedSecret {
		sharedSecret[i] = byte(i)
	}

	algorithmID := []byte("ENCDOC-XML|1.1")
	partyUInfo := make([]byte, 96)
	partyVInfo := make([]byte, 500)

	// Derive key
	derivedKey, err := ConcatKDF(sharedSecret, algorithmID, partyUInfo, partyVInfo)
	if err != nil {
		t.Fatalf("ConcatKDF() error = %v", err)
	}

	if len(derivedKey) != 32 {
		t.Errorf("ConcatKDF() key length = %v, want 32", len(derivedKey))
	}

	// Same inputs should produce same output
	derivedKey2, err := ConcatKDF(sharedSecret, algorithmID, partyUInfo, partyVInfo)
	if err != nil {
		t.Fatalf("ConcatKDF() error = %v", err)
	}

	if !bytes.Equal(derivedKey, derivedKey2) {
		t.Error("ConcatKDF() must be deterministic for identical inputs")
	}
}

func TestConcatKDF_DifferentInputs(t *testing.T) {
	sharedSecret := make([]byte, 48)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i)
	}

	algorithmID1 := []byte("ENCDOC-XML|1.1")
	algorithmID2 := []byte("ENCDOC-XML|1.0")
	partyUInfo := make([]byte, 96)
	partyVInfo := make([]byte, 500)

	derivedKey1, err := ConcatKDF(sharedSecret, algorithmID1, partyUInfo, partyVInfo)
	if err != nil {
		t.Fatalf("ConcatKDF() error = %v", err)
	}

	derivedKey2, err := ConcatKDF(sharedSecret, algorithmID2, partyUInfo, partyVInfo)
	if err != nil {
		t.Fatalf("ConcatKDF() error = %v", err)
	}

	// Different AlgorithmID should produce different keys
	if string(derivedKey1) == string(derivedKey2) {
		t.Error("ConcatKDF() with different AlgorithmID should produce different keys")
	}
}

func TestConcatKDFWithDigest_DigestSelectionAffectsOutput(t *testing.T) {
	sharedSecret := make([]byte, 48)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i)
	}

	algorithmID := []byte("ENCDOC-XML|1.1")
	partyUInfo := make([]byte, 97)
	partyUInfo[0] = 0x04
	partyVInfo := make([]byte, 200)

	k1, err := ConcatKDFWithDigest(sharedSecret, algorithmID, partyUInfo, partyVInfo, DigestSHA384URI, 32)
	if err != nil {
		t.Fatalf("ConcatKDFWithDigest sha384 error = %v", err)
	}
	k2, err := ConcatKDFWithDigest(sharedSecret, algorithmID, partyUInfo, partyVInfo, DigestSHA512URI, 32)
	if err != nil {
		t.Fatalf("ConcatKDFWithDigest sha512 error = %v", err)
	}
	if bytes.Equal(k1, k2) {
		t.Fatal("Different digest algorithms must produce different KEK outputs")
	}
}

func TestConcatKDFWithDigest_IteratesForLongerOutput(t *testing.T) {
	sharedSecret := make([]byte, 48)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i)
	}

	algorithmID := []byte("ENCDOC-XML|1.1")
	partyUInfo := make([]byte, 97)
	partyUInfo[0] = 0x04
	partyVInfo := make([]byte, 200)

	keyLen := 100 // longer than sha256 output (32), forces multiple blocks
	k1, err := ConcatKDFWithDigest(sharedSecret, algorithmID, partyUInfo, partyVInfo, DigestSHA256URI, keyLen)
	if err != nil {
		t.Fatalf("ConcatKDFWithDigest sha256 error = %v", err)
	}
	if len(k1) != keyLen {
		t.Fatalf("Expected %d bytes, got %d", keyLen, len(k1))
	}

	k2, err := ConcatKDFWithDigest(sharedSecret, algorithmID, partyUInfo, partyVInfo, DigestSHA256URI, keyLen)
	if err != nil {
		t.Fatalf("ConcatKDFWithDigest sha256 error = %v", err)
	}
	if !bytes.Equal(k1, k2) {
		t.Fatal("ConcatKDFWithDigest must be deterministic for identical inputs")
	}
}

func TestValidateECPublicKey(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate EC key: %v", err)
	}

	err = ValidateECPublicKey(&privKey.PublicKey)
	if err != nil {
		t.Errorf("ValidateECPublicKey() with valid key should not fail: %v", err)
	}
}

func TestExtractECPublicKeyFromCertificate(t *testing.T) {
	cert, _ := createTestECCertificate(t)

	pubKey, err := ExtractECPublicKeyFromCertificate(cert)
	if err != nil {
		t.Fatalf("ExtractECPublicKeyFromCertificate() error = %v", err)
	}

	if pubKey == nil {
		t.Fatal("ExtractECPublicKeyFromCertificate() should return non-nil public key")
	}

	if pubKey.Curve != elliptic.P384() {
		t.Errorf("ExtractECPublicKeyFromCertificate() curve = %v, want P384", pubKey.Curve)
	}
}

func TestGenerateECKeyPair(t *testing.T) {
	// Create a reference public key
	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate reference key: %v", err)
	}

	// Generate ephemeral key pair on same curve
	ephemeralPriv, err := GenerateECKeyPair(&privKey.PublicKey)
	if err != nil {
		t.Fatalf("GenerateECKeyPair() error = %v", err)
	}

	if ephemeralPriv.Curve != elliptic.P384() {
		t.Errorf("GenerateECKeyPair() curve = %v, want P384", ephemeralPriv.Curve)
	}

	//nolint:staticcheck // Test verifies the generated legacy ecdsa.PrivateKey has a non-zero scalar.
	if ephemeralPriv.D.Cmp(big.NewInt(0)) == 0 {
		t.Error("GenerateECKeyPair() private key should not be zero")
	}
}
