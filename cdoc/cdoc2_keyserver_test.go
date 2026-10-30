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
	"github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2/riahttp"
	"github.com/aarepuusepp/libcdoc-go/v2/key"
)

func setupKeyServerMock(t *testing.T) (*c2keyserver.MockServer, *c2keyserver.Client) {
	t.Helper()
	riahttp.DevModePrivateHosts = true
	t.Cleanup(func() { riahttp.DevModePrivateHosts = false })
	mockServer := c2keyserver.NewMockServer()
	t.Cleanup(mockServer.Stop)
	return mockServer, c2keyserver.NewTestClient(mockServer)
}

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
	return generateSelfSignedECC_KS_Curve(t, elliptic.P384())
}

func generateSelfSignedECC_KS_Curve(t *testing.T, curve elliptic.Curve) (*x509.Certificate, *key.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
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

func roundTripKeyServer(t *testing.T, cert *x509.Certificate, priv *key.PrivateKey, serverID string, data []byte) {
	t.Helper()
	mockServer, client := setupKeyServerMock(t)
	baseURL := mockServer.URL()
	config := c2keyserver.KeyServerConfig{
		ServerID: serverID,
		PostURL:  baseURL,
		FetchURL: baseURL,
	}
	var out bytes.Buffer
	b := NewBuilder().Version(Version20)
	b.SetKeyServerClient(client)
	b.AddKeyServerConfig(config)
	if err := b.WithKeyServerRecipient(cert, serverID, "test-label", 0); err != nil {
		t.Fatalf("with key server recipient: %v", err)
	}
	b.WithDataFile("greeting.txt", bytes.NewReader(data), int64(len(data)))
	if err := b.BuildToWriter(&out); err != nil {
		t.Fatalf("build: %v", err)
	}
	d := NewDecrypter()
	d.SetKeyServerClient(client)
	d.AddKeyServerConfig(config)
	d.WithCDOC(bytes.NewReader(out.Bytes()))
	d.WithPrivateKey(priv)
	files, err := d.Decrypt()
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if len(files) != 1 || !bytes.Equal(files[0].Content, data) {
		t.Fatalf("unexpected decrypt result")
	}
}

func TestCDOC2_RoundTrip_KeyServer_ECC_P256(t *testing.T) {
	cert, priv := generateSelfSignedECC_KS_Curve(t, elliptic.P256())
	roundTripKeyServer(t, cert, priv, "test-server-ecc-p256", []byte("hello-p256"))
}

func TestCDOC2_RoundTrip_KeyServer_ECC_P521(t *testing.T) {
	cert, priv := generateSelfSignedECC_KS_Curve(t, elliptic.P521())
	roundTripKeyServer(t, cert, priv, "test-server-ecc-p521", []byte("hello-p521"))
}

func TestCDOC2_KeyServer_Mixed_RSA_ECC(t *testing.T) {
	certRSA, privRSA := generateSelfSignedRSA_KS(t)
	certECC, privECC := generateSelfSignedECC_KS_Curve(t, elliptic.P256())

	mockServer, client := setupKeyServerMock(t)
	baseURL := mockServer.URL()
	serverID := "test-server-mixed"
	config := c2keyserver.KeyServerConfig{
		ServerID: serverID,
		PostURL:  baseURL,
		FetchURL: baseURL,
	}

	var out bytes.Buffer
	b := NewBuilder().Version(Version20)
	b.SetKeyServerClient(client)
	b.AddKeyServerConfig(config)
	if err := b.WithKeyServerRecipient(certRSA, serverID, "rsa-recipient", 0); err != nil {
		t.Fatalf("rsa recipient: %v", err)
	}
	if err := b.WithKeyServerRecipient(certECC, serverID, "ecc-recipient", 0); err != nil {
		t.Fatalf("ecc recipient: %v", err)
	}
	data := []byte("hello-mixed-rsa-ecc")
	b.WithDataFile("greeting.txt", bytes.NewReader(data), int64(len(data)))
	if err := b.BuildToWriter(&out); err != nil {
		t.Fatalf("build: %v", err)
	}

	type recipientCase struct {
		name string
		priv *key.PrivateKey
		cert *x509.Certificate
	}
	for _, tc := range []recipientCase{
		{"rsa", privRSA, certRSA},
		{"ecc", privECC, certECC},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := NewDecrypter()
			d.SetKeyServerClient(client)
			d.AddKeyServerConfig(config)
			d.WithCDOC(bytes.NewReader(out.Bytes()))
			d.WithPrivateKey(tc.priv)
			d.WithCertificate(tc.cert)
			files, err := d.Decrypt()
			if err != nil {
				t.Fatalf("decrypt: %v", err)
			}
			if len(files) != 1 || !bytes.Equal(files[0].Content, data) {
				t.Fatal("content mismatch")
			}
		})
	}
}

func TestCDOC2_RoundTrip_KeyServer_RSA(t *testing.T) {
	cert, priv := generateSelfSignedRSA_KS(t)

	// Start mock key server
	mockServer, client := setupKeyServerMock(t)
	baseURL := mockServer.URL()

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
	mockServer, client := setupKeyServerMock(t)
	baseURL := mockServer.URL()

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

	mockServer, client := setupKeyServerMock(t)
	baseURL := mockServer.URL()

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

	mockServer, client := setupKeyServerMock(t)
	baseURL := mockServer.URL()

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
