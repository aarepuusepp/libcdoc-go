package cdoc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	c2keyserver "github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2/keyserver"
	"github.com/aarepuusepp/libcdoc-go/v2/key"
)

func generateSelfSignedRSA_KS(t *testing.T) (*x509.Certificate, *key.PrivateKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen rsa: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test RSA Key Server"},
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

func generateSelfSignedECC_KS(t *testing.T) (*x509.Certificate, *key.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("gen ecc: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test ECC Key Server"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
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

func TestCDOC2_RoundTrip_KeyServer_RSA(t *testing.T) {
	cert, priv := generateSelfSignedRSA_KS(t)

	// Start mock key server
	mockServer := c2keyserver.NewMockServer()
	defer mockServer.Stop()
	baseURL := mockServer.URL()

	// Create key server client
	client := c2keyserver.NewClient()

	// Create key server config
	serverID := "test-server-rsa"
	config := c2keyserver.KeyServerConfig{
		ServerID: serverID,
		PostURL:  baseURL,
		FetchURL: baseURL,
	}

	// Build CDOC2 with key server recipient
	var out bytes.Buffer
	b := NewBuilder().Version(Version20)
	b.SetKeyServerClient(client)
	b.AddKeyServerConfig(config)

	if err := b.WithKeyServerRecipient(cert, serverID, "test-label", 0); err != nil {
		t.Fatalf("with key server recipient: %v", err)
	}

	data := []byte("hello-cdoc2-keyserver-rsa")
	b.WithDataFile("greeting.txt", bytes.NewReader(data), int64(len(data)))

	if err := b.BuildToWriter(&out); err != nil {
		t.Fatalf("build: %v", err)
	}

	// Verify key material was stored on mock server
	// We need to extract transaction ID from the CDOC2 file, but for now just verify encryption worked
	cdoc2Data := out.Bytes()
	if len(cdoc2Data) == 0 {
		t.Fatal("cdoc2 data is empty")
	}

	// Decrypt using key server
	reader := bytes.NewReader(cdoc2Data)
	d := NewDecrypter()
	d.SetKeyServerClient(client)
	d.AddKeyServerConfig(config)
	d.WithCDOC(reader)
	d.WithPrivateKey(priv)

	files, err := d.Decrypt()
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	if len(files) != 1 {
		t.Fatalf("expected 1 file, got %d", len(files))
	}

	if !bytes.Equal(files[0].Content, data) {
		t.Errorf("content mismatch: got %q, want %q", files[0].Content, data)
	}
}

func TestCDOC2_RoundTrip_KeyServer_ECC(t *testing.T) {
	cert, priv := generateSelfSignedECC_KS(t)

	// Start mock key server
	mockServer := c2keyserver.NewMockServer()
	defer mockServer.Stop()
	baseURL := mockServer.URL()

	// Create key server client
	client := c2keyserver.NewClient()

	// Create key server config
	serverID := "test-server-ecc"
	config := c2keyserver.KeyServerConfig{
		ServerID: serverID,
		PostURL:  baseURL,
		FetchURL: baseURL,
	}

	// Build CDOC2 with key server recipient
	var out bytes.Buffer
	b := NewBuilder().Version(Version20)
	b.SetKeyServerClient(client)
	b.AddKeyServerConfig(config)

	if err := b.WithKeyServerRecipient(cert, serverID, "test-label-ecc", 0); err != nil {
		t.Fatalf("with key server recipient: %v", err)
	}

	data := []byte("hello-cdoc2-keyserver-ecc")
	b.WithDataFile("greeting.txt", bytes.NewReader(data), int64(len(data)))

	if err := b.BuildToWriter(&out); err != nil {
		t.Fatalf("build: %v", err)
	}

	// Decrypt using key server
	reader := bytes.NewReader(out.Bytes())
	d := NewDecrypter()
	d.SetKeyServerClient(client)
	d.AddKeyServerConfig(config)
	d.WithCDOC(reader)
	d.WithPrivateKey(priv)

	files, err := d.Decrypt()
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	if len(files) != 1 {
		t.Fatalf("expected 1 file, got %d", len(files))
	}

	if !bytes.Equal(files[0].Content, data) {
		t.Errorf("content mismatch: got %q, want %q", files[0].Content, data)
	}
}

func TestCDOC2_KeyServer_ExpiryTime(t *testing.T) {
	cert, priv := generateSelfSignedRSA_KS(t)

	mockServer := c2keyserver.NewMockServer()
	defer mockServer.Stop()
	baseURL := mockServer.URL()

	client := c2keyserver.NewClient()
	serverID := "test-server-expiry"
	config := c2keyserver.KeyServerConfig{
		ServerID: serverID,
		PostURL:  baseURL,
		FetchURL: baseURL,
	}

	var out bytes.Buffer
	b := NewBuilder().Version(Version20)
	b.SetKeyServerClient(client)
	b.AddKeyServerConfig(config)

	// Set expiry time to 1 hour from now
	expiryTime := uint64(time.Now().Add(1 * time.Hour).Unix())
	if err := b.WithKeyServerRecipient(cert, serverID, "test-label", expiryTime); err != nil {
		t.Fatalf("with key server recipient: %v", err)
	}

	data := []byte("hello-expiry")
	b.WithDataFile("greeting.txt", bytes.NewReader(data), int64(len(data)))

	if err := b.BuildToWriter(&out); err != nil {
		t.Fatalf("build: %v", err)
	}

	// Decrypt should work
	reader := bytes.NewReader(out.Bytes())
	d := NewDecrypter()
	d.SetKeyServerClient(client)
	d.AddKeyServerConfig(config)
	d.WithCDOC(reader)
	d.WithPrivateKey(priv)

	files, err := d.Decrypt()
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	if len(files) != 1 || !bytes.Equal(files[0].Content, data) {
		t.Error("decryption with expiry time failed")
	}
}

func TestCDOC2_KeyServer_MultipleRecipients(t *testing.T) {
	cert1, priv1 := generateSelfSignedRSA_KS(t)
	cert2, priv2 := generateSelfSignedRSA_KS(t)

	mockServer := c2keyserver.NewMockServer()
	defer mockServer.Stop()
	baseURL := mockServer.URL()

	client := c2keyserver.NewClient()
	serverID := "test-server-multi"
	config := c2keyserver.KeyServerConfig{
		ServerID: serverID,
		PostURL:  baseURL,
		FetchURL: baseURL,
	}

	var out bytes.Buffer
	b := NewBuilder().Version(Version20)
	b.SetKeyServerClient(client)
	b.AddKeyServerConfig(config)

	// Add key server recipient
	if err := b.WithKeyServerRecipient(cert1, serverID, "keyserver-recipient", 0); err != nil {
		t.Fatalf("with key server recipient: %v", err)
	}

	// Add regular recipient
	if err := b.WithRecipientCertificate(cert2); err != nil {
		t.Fatalf("with regular recipient: %v", err)
	}

	data := []byte("hello-multiple-recipients")
	b.WithDataFile("greeting.txt", bytes.NewReader(data), int64(len(data)))

	if err := b.BuildToWriter(&out); err != nil {
		t.Fatalf("build: %v", err)
	}

	// Decrypt with regular recipient (should work)
	reader := bytes.NewReader(out.Bytes())
	d := NewDecrypter()
	d.WithCDOC(reader)
	d.WithPrivateKey(priv2)

	files, err := d.Decrypt()
	if err != nil {
		t.Fatalf("decrypt with regular recipient: %v", err)
	}

	if len(files) != 1 || !bytes.Equal(files[0].Content, data) {
		t.Error("decryption with regular recipient failed")
	}

	// Decrypt with key server recipient
	reader2 := bytes.NewReader(out.Bytes())
	d2 := NewDecrypter()
	d2.SetKeyServerClient(client)
	d2.AddKeyServerConfig(config)
	d2.WithCDOC(reader2)
	d2.WithPrivateKey(priv1)

	files2, err := d2.Decrypt()
	if err != nil {
		t.Fatalf("decrypt with key server recipient: %v", err)
	}

	if len(files2) != 1 || !bytes.Equal(files2[0].Content, data) {
		t.Error("decryption with key server recipient failed")
	}
}

