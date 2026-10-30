package keyserver_test

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2/keyserver"
	"github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2/riahttp"
)

func TestKeyCapsuleClient_MockServerExactPaths(t *testing.T) {
	riahttp.DevModePrivateHosts = true
	t.Cleanup(func() { riahttp.DevModePrivateHosts = false })

	mock := keyserver.NewMockServer()
	defer mock.Stop()

	client := keyserver.NewTestClient(mock)

	cfg, err := keyserver.PrepareConfig(keyserver.KeyServerConfig{
		ServerID: "ks-test",
		PostURL:  mock.URL(),
		FetchURL: mock.URL(),
	})
	if err != nil {
		t.Fatal(err)
	}

	recipient := []byte("recipient-key-bytes-1234567890")
	material := []byte("01234567890123456789012345678901")
	info, err := client.SendKeyWithContext(context.Background(), cfg, recipient, material, "ecc_secp256r1", 0)
	if err != nil {
		t.Fatal(err)
	}
	if info.TransactionID == "" {
		t.Fatal("expected transaction id")
	}

	got, err := client.FetchKeyWithContext(context.Background(), cfg, info.TransactionID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytesEqual(got, material) {
		t.Fatalf("material mismatch")
	}
}

func TestKeyCapsuleClient_RejectsInvalidCapsuleType(t *testing.T) {
	riahttp.DevModePrivateHosts = true
	t.Cleanup(func() { riahttp.DevModePrivateHosts = false })

	mock := keyserver.NewMockServer()
	defer mock.Stop()
	client := keyserver.NewTestClient(mock)
	cfg, err := keyserver.PrepareConfig(keyserver.KeyServerConfig{
		ServerID: "ks-test",
		PostURL:  mock.URL(),
		FetchURL: mock.URL(),
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.SendKeyWithContext(context.Background(), cfg, []byte("recipient"), []byte("01234567890123456789012345678901"), "unknown", 0)
	if err == nil {
		t.Fatal("expected unsupported capsule_type error")
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

func TestSendKeyRequest_Base64EncodesFields(t *testing.T) {
	raw := keyserver.SendKeyRequest{
		RecipientID:          base64.StdEncoding.EncodeToString([]byte("abc")),
		EphemeralKeyMaterial: base64.StdEncoding.EncodeToString([]byte("def")),
		CapsuleType:          "ecc_secp256r1",
	}
	if raw.RecipientID == "" || raw.EphemeralKeyMaterial == "" {
		t.Fatal("expected encoded fields")
	}
}
