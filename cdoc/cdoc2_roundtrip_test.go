package cdoc

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/aarepuusepp/libcdoc-go/v2/key"
)

func generateSelfSignedRSA(t *testing.T) (*x509.Certificate, *key.PrivateKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen rsa: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert, &key.PrivateKey{Key: priv}
}

func TestCDOC2_RoundTrip_RSA(t *testing.T) {
	cert, priv := generateSelfSignedRSA(t)

	// Build CDOC2 in-memory
	var out bytes.Buffer
	b := NewBuilder().Version(Version20)
	if err := b.WithRecipientCertificate(cert); err != nil {
		t.Fatalf("with recipient: %v", err)
	}
	data := []byte("hello-cdoc2")
	b.WithDataFile("greeting.txt", bytes.NewReader(data), int64(len(data)))
	if err := b.BuildToWriter(&out); err != nil {
		t.Fatalf("build: %v", err)
	}

	// Decrypt
	d := NewDecrypter().WithCDOC(bytes.NewReader(out.Bytes())).WithPrivateKey(priv)
	files, err := d.Decrypt()
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("expected 1 file, got %d", len(files))
	}
	if files[0].Name != "greeting.txt" {
		t.Fatalf("unexpected name: %s", files[0].Name)
	}
	if !bytes.Equal(files[0].Content, data) {
		t.Fatalf("content mismatch")
	}
}

func TestCDOC2_RoundTrip_Password(t *testing.T) {
	password := "test-password-123"

	// Build CDOC2 in-memory
	var out bytes.Buffer
	b := NewBuilder().Version(Version20)
	if err := b.WithPasswordAndIterations(password, 100000); err != nil {
		t.Fatalf("with password: %v", err)
	}
	data := []byte("hello-cdoc2-password")
	b.WithDataFile("secret.txt", bytes.NewReader(data), int64(len(data)))
	if err := b.BuildToWriter(&out); err != nil {
		t.Fatalf("build: %v", err)
	}

	// Decrypt
	d := NewDecrypter().WithCDOC(bytes.NewReader(out.Bytes())).WithPassword(password)
	files, err := d.Decrypt()
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("expected 1 file, got %d", len(files))
	}
	if files[0].Name != "secret.txt" {
		t.Fatalf("unexpected name: %s", files[0].Name)
	}
	if !bytes.Equal(files[0].Content, data) {
		t.Fatalf("content mismatch")
	}
}

func TestCDOC2_RoundTrip_SymmetricKey(t *testing.T) {
	symmetricKey := make([]byte, 32) // 256-bit key
	if _, err := rand.Read(symmetricKey); err != nil {
		t.Fatalf("generate symmetric key: %v", err)
	}

	// Build CDOC2 in-memory
	var out bytes.Buffer
	b := NewBuilder().Version(Version20)
	if err := b.WithSymmetricKey(symmetricKey); err != nil {
		t.Fatalf("with symmetric key: %v", err)
	}
	data := []byte("hello-cdoc2-symmetric")
	b.WithDataFile("symmetric.txt", bytes.NewReader(data), int64(len(data)))
	if err := b.BuildToWriter(&out); err != nil {
		t.Fatalf("build: %v", err)
	}

	// Decrypt
	d := NewDecrypter().WithCDOC(bytes.NewReader(out.Bytes())).WithSymmetricKey(symmetricKey)
	files, err := d.Decrypt()
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("expected 1 file, got %d", len(files))
	}
	if files[0].Name != "symmetric.txt" {
		t.Fatalf("unexpected name: %s", files[0].Name)
	}
	if !bytes.Equal(files[0].Content, data) {
		t.Fatalf("content mismatch")
	}
}

func TestCDOC2_RoundTrip_MultipleFiles(t *testing.T) {
	cert, priv := generateSelfSignedRSA(t)

	// Build CDOC2 with multiple files
	var out bytes.Buffer
	b := NewBuilder().Version(Version20)
	if err := b.WithRecipientCertificate(cert); err != nil {
		t.Fatalf("with recipient: %v", err)
	}

	// Add multiple files
	files := []struct {
		name    string
		content []byte
	}{
		{"file1.txt", []byte("content of file 1")},
		{"file2.txt", []byte("content of file 2")},
		{"subdir/file3.txt", []byte("content of file 3 in subdir")},
	}

	for _, f := range files {
		b.WithDataFile(f.name, bytes.NewReader(f.content), int64(len(f.content)))
	}

	if err := b.BuildToWriter(&out); err != nil {
		t.Fatalf("build: %v", err)
	}

	// Decrypt and verify all files
	d := NewDecrypter().WithCDOC(bytes.NewReader(out.Bytes())).WithPrivateKey(priv)
	decryptedFiles, err := d.Decrypt()
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	if len(decryptedFiles) != len(files) {
		t.Fatalf("expected %d files, got %d", len(files), len(decryptedFiles))
	}

	// Create a map for easier lookup
	decryptedMap := make(map[string][]byte)
	for _, f := range decryptedFiles {
		decryptedMap[f.Name] = f.Content
	}

	// Verify each file
	for _, expected := range files {
		actual, exists := decryptedMap[expected.name]
		if !exists {
			t.Fatalf("file %s not found in decrypted files", expected.name)
		}
		if !bytes.Equal(actual, expected.content) {
			t.Fatalf("content mismatch for file %s", expected.name)
		}
	}
}

func TestCDOC2_RoundTrip_MixedRecipients(t *testing.T) {
	cert, priv := generateSelfSignedRSA(t)
	password := "mixed-password-456"
	symmetricKey := make([]byte, 32)
	if _, err := rand.Read(symmetricKey); err != nil {
		t.Fatalf("generate symmetric key: %v", err)
	}

	// Build CDOC2 with multiple recipient types
	var out bytes.Buffer
	b := NewBuilder().Version(Version20)
	if err := b.WithRecipientCertificate(cert); err != nil {
		t.Fatalf("with certificate: %v", err)
	}
	if err := b.WithPassword(password); err != nil {
		t.Fatalf("with password: %v", err)
	}
	if err := b.WithSymmetricKey(symmetricKey); err != nil {
		t.Fatalf("with symmetric key: %v", err)
	}

	data := []byte("hello-mixed-recipients")
	b.WithDataFile("mixed.txt", bytes.NewReader(data), int64(len(data)))
	if err := b.BuildToWriter(&out); err != nil {
		t.Fatalf("build: %v", err)
	}

	// Test decryption with each recipient type
	testCases := []struct {
		name      string
		decrypter func() *Decrypter
	}{
		{
			"RSA certificate",
			func() *Decrypter { return NewDecrypter().WithCDOC(bytes.NewReader(out.Bytes())).WithPrivateKey(priv) },
		},
		{
			"password",
			func() *Decrypter { return NewDecrypter().WithCDOC(bytes.NewReader(out.Bytes())).WithPassword(password) },
		},
		{
			"symmetric key",
			func() *Decrypter {
				return NewDecrypter().WithCDOC(bytes.NewReader(out.Bytes())).WithSymmetricKey(symmetricKey)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			files, err := tc.decrypter().Decrypt()
			if err != nil {
				t.Fatalf("decrypt with %s: %v", tc.name, err)
			}
			if len(files) != 1 {
				t.Fatalf("expected 1 file, got %d", len(files))
			}
			if files[0].Name != "mixed.txt" {
				t.Fatalf("unexpected name: %s", files[0].Name)
			}
			if !bytes.Equal(files[0].Content, data) {
				t.Fatalf("content mismatch")
			}
		})
	}
}
