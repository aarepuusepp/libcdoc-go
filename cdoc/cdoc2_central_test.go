package cdoc

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2/authtoken"
	"testing"

	c2 "github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2"
	"github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2/authserver"
	c2central "github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2/central"
	"github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2/keyserver"
	"github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2/keyshares"
	"github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2/riahttp"
	"github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2/rpserver"
)

func TestCDOC2_AuthMeans_UnverifiedExternalProofFailsClosed(t *testing.T) {
	riahttp.DevModePrivateHosts = true
	defer func() { riahttp.DevModePrivateHosts = false }()

	shares1 := keyshares.NewMockServer()
	defer shares1.Stop()
	shares2 := keyshares.NewMockServer()
	defer shares2.Stop()
	authSrv := authserver.NewMockServer()
	defer authSrv.Stop()
	rpSrv := rpserver.NewMockServer()
	defer rpSrv.Stop()

	client1, err := keyshares.NewTestClient(shares1)
	if err != nil {
		t.Fatal(err)
	}
	client2, err := keyshares.NewTestClient(shares2)
	if err != nil {
		t.Fatal(err)
	}
	authClient, err := authserver.NewTestClient(authSrv)
	if err != nil {
		t.Fatal(err)
	}
	rpClient, err := rpserver.NewTestClient(rpSrv)
	if err != nil {
		t.Fatal(err)
	}

	central := &c2central.Services{
		SharesClients:     []*keyshares.Client{client1, client2},
		SharesMinRequired: 2,
		AuthClient:        authClient,
		RPClient:          rpClient,
	}

	etsiID := "etsi/PNOEE-38001085718"
	payload := []byte("hello-auth-means")

	var buf bytes.Buffer
	builder := NewBuilder().Version(Version20)
	builder.SetSharesClients([]*keyshares.Client{client1, client2}, 2)
	if err := builder.WithAuthMeansRecipient(etsiID, etsiID); err != nil {
		t.Fatal(err)
	}
	builder.WithDataFile("test.txt", bytes.NewReader(payload), int64(len(payload)))
	if err := builder.BuildToWriter(&buf); err != nil {
		t.Fatal(err)
	}

	decrypter := NewDecrypter().
		SetCentralServices(central).
		WithAuthMeansDecrypt(etsiID, c2central.AuthMeansSID, "").
		WithCDOC(bytes.NewReader(buf.Bytes()))

	files, err := decrypter.Decrypt()
	if !errors.Is(err, authtoken.ErrExternalProofProfileUnsupported) || len(files) != 0 {
		t.Fatalf("unverified proof must not decrypt: files=%d err=%v", len(files), err)
	}

}

func TestCDOC2_AuthMeans_PreFetchedShares_MockCentral(t *testing.T) {
	riahttp.DevModePrivateHosts = true
	defer func() { riahttp.DevModePrivateHosts = false }()

	shares1 := keyshares.NewMockServer()
	defer shares1.Stop()
	shares2 := keyshares.NewMockServer()
	defer shares2.Stop()
	authSrv := authserver.NewMockServer()
	defer authSrv.Stop()
	rpSrv := rpserver.NewMockServer()
	defer rpSrv.Stop()

	client1, err := keyshares.NewTestClient(shares1)
	if err != nil {
		t.Fatal(err)
	}
	client2, err := keyshares.NewTestClient(shares2)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	etsiID := "etsi/PNOEE-38001085718"
	payload := []byte("hello-prefetched-shares")

	var buf bytes.Buffer
	builder := NewBuilder().Version(Version20)
	builder.SetSharesClients([]*keyshares.Client{client1, client2}, 2)
	if err := builder.WithAuthMeansRecipient(etsiID, etsiID); err != nil {
		t.Fatal(err)
	}
	builder.WithDataFile("test.txt", bytes.NewReader(payload), int64(len(payload)))
	if err := builder.BuildToWriter(&buf); err != nil {
		t.Fatal(err)
	}

	reader, err := c2.NewReader(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.ReadHeader(); err != nil {
		t.Fatal(err)
	}
	locks, err := reader.GetLocks()
	if err != nil {
		t.Fatal(err)
	}
	shareRefs := make([]c2central.ShareReference, 0, len(locks[0].KeyShares))
	for _, sh := range locks[0].KeyShares {
		shareRefs = append(shareRefs, c2central.ShareReference{
			ServerBaseURL: sh.URL,
			ShareID:       sh.TransactionID,
		})
	}
	// Fetch fixtures directly from permissive test servers. This verifies local
	// share reconstruction only, never the external authentication proof profile.
	var shareBytes [][]byte
	for _, ref := range shareRefs {
		client := client1
		if ref.ServerBaseURL == client2.BaseURL() {
			client = client2
		}
		share, err := client.GetKeyShare(ctx, ref.ShareID, keyshares.AuthHeaders{AuthToken: "fixture-only", SessionToken: "fixture-only"})
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := base64.StdEncoding.DecodeString(share.Share)
		if err != nil {
			t.Fatal(err)
		}
		shareBytes = append(shareBytes, decoded)
	}

	decrypter := NewDecrypter().
		WithAuthMeansDecrypt(etsiID, c2central.AuthMeansSID, "").
		WithPreFetchedKeyShares(shareBytes, 2).
		WithCDOC(bytes.NewReader(buf.Bytes()))

	files, err := decrypter.Decrypt()
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || !bytes.Equal(files[0].Content, payload) {
		t.Fatalf("unexpected decrypt result: %+v", files)
	}
}

func TestCDOC2_KeyServer_RoundTrip_MockCentral(t *testing.T) {
	riahttp.DevModePrivateHosts = true
	defer func() { riahttp.DevModePrivateHosts = false }()

	mockServer := keyserver.NewMockServer()
	defer mockServer.Stop()

	client := keyserver.NewTestClient(mockServer)
	config := keyserver.KeyServerConfig{
		ServerID: "test-server",
		PostURL:  mockServer.URL(),
		FetchURL: mockServer.URL(),
	}

	cert, priv := generateSelfSignedRSA_KS(t)
	payload := []byte("hello-key-server")

	var buf bytes.Buffer
	builder := NewBuilder().Version(Version20)
	builder.SetKeyServerClient(client)
	builder.AddKeyServerConfig(config)
	if err := builder.WithKeyServerRecipient(cert, config.ServerID, "label", 0); err != nil {
		t.Fatal(err)
	}
	builder.WithDataFile("test.txt", bytes.NewReader(payload), int64(len(payload)))
	if err := builder.BuildToWriter(&buf); err != nil {
		t.Fatal(err)
	}

	decrypter := NewDecrypter().
		SetKeyServerClient(client).
		AddKeyServerConfig(config).
		WithPrivateKey(priv).
		WithCertificate(cert).
		WithCDOC(bytes.NewReader(buf.Bytes()))

	files, err := decrypter.Decrypt()
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || !bytes.Equal(files[0].Content, payload) {
		t.Fatalf("unexpected decrypt result: %+v", files)
	}
}
