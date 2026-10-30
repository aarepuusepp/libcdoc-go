package keyshares_test

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2/keyshares"
	"github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2/riahttp"
)

func TestKeySharesClient_MockServer(t *testing.T) {
	riahttp.DevModePrivateHosts = true
	t.Cleanup(func() { riahttp.DevModePrivateHosts = false })

	mock := keyshares.NewMockServer()
	defer mock.Stop()

	client, err := keyshares.NewTestClient(mock)
	if err != nil {
		t.Fatal(err)
	}
	shareData := []byte("01234567890123456789012345678901")
	shareID, err := client.CreateKeyShare(context.Background(), keyshares.KeyShare{
		Share:     base64.StdEncoding.EncodeToString(shareData),
		Recipient: "etsi/PNOEE-38001085718",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if shareID == "" {
		t.Fatal("expected share id")
	}

	nr, err := client.CreateNonce(context.Background(), shareID, "mock-session", "mock-cert")
	if err != nil {
		t.Fatal(err)
	}
	if nr.Nonce == "" {
		t.Fatal("expected nonce")
	}

	got, err := client.GetKeyShare(context.Background(), shareID, keyshares.AuthHeaders{
		AuthToken:          "mock-auth-token",
		AuthCertificate:    "mock-auth-cert",
		SessionToken:       "mock-session",
		SessionCertificate: "mock-cert",
	})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.StdEncoding.DecodeString(got.Share)
	if err != nil {
		t.Fatal(err)
	}
	if !bytesEqual(decoded, shareData) {
		t.Fatalf("share mismatch")
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
