package rpserver_test

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2/riahttp"
	"github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2/rpserver"
)

func TestSidAuthenticateAndPoll_MockServer(t *testing.T) {
	riahttp.DevModePrivateHosts = true
	t.Cleanup(func() { riahttp.DevModePrivateHosts = false })

	mock := rpserver.NewMockServer()
	defer mock.Stop()
	client, err := rpserver.NewTestClient(mock)
	if err != nil {
		t.Fatal(err)
	}

	hash := base64.StdEncoding.EncodeToString([]byte("signing-input-bytes-for-test"))
	req := rpserver.NewSidAuthenticateRequest("PNOEE-38001085718", hash)
	sessionID, err := client.SidAuthenticate(context.Background(), "mock-session", "mock-cert", req)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	status, err := client.PollSidUntilComplete(ctx, "mock-session", "mock-cert", sessionID, 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != rpserver.StateComplete {
		t.Fatalf("state: got %q", status.State)
	}
	sig, err := status.SignatureBytes()
	if err != nil || len(sig) == 0 {
		t.Fatal("expected sid signature bytes")
	}
	params, err := status.SidRPv3SignatureParameters()
	if err != nil || params == "" {
		t.Fatal("expected sid rpv3 signature parameters")
	}
}

func TestMidAuthenticateSessionRFC9421_MockServer(t *testing.T) {
	riahttp.DevModePrivateHosts = true
	t.Cleanup(func() { riahttp.DevModePrivateHosts = false })

	mock := rpserver.NewMockServer()
	defer mock.Stop()
	client, err := rpserver.NewTestClient(mock)
	if err != nil {
		t.Fatal(err)
	}

	hash := base64.StdEncoding.EncodeToString([]byte("mid-hash"))
	req, err := rpserver.NewMidAuthenticateRequest("+37260000000", "38001085718", hash, "EST", "CDOC2 decrypt")
	if err != nil {
		t.Fatal(err)
	}
	sessionID, err := client.MidAuthenticate(context.Background(), "mock-session", "mock-cert", req)
	if err != nil {
		t.Fatal(err)
	}
	status, err := client.MidSession(context.Background(), "mock-session", "mock-cert", sessionID)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != rpserver.StateComplete || status.Result != rpserver.MidResultOK {
		t.Fatalf("unexpected status: %+v", status)
	}
	if status.Proof.RpSignedHash == "" || status.Proof.SignatureInput == "" || status.Proof.Signature == "" {
		t.Fatal("expected RFC 9421 proof headers")
	}
}

func TestMidValidatePhoneInvalid(t *testing.T) {
	_, err := rpserver.NewMidAuthenticateRequest("37260000000", "38001085718", "abc", "EST", "text")
	if err == nil {
		t.Fatal("expected phone validation error")
	}
}

func TestPollSidCancelled(t *testing.T) {
	riahttp.DevModePrivateHosts = true
	t.Cleanup(func() { riahttp.DevModePrivateHosts = false })

	mock := rpserver.NewMockServer()
	defer mock.Stop()
	client, err := rpserver.NewTestClient(mock)
	if err != nil {
		t.Fatal(err)
	}
	req := rpserver.NewSidAuthenticateRequest("PNOEE-38001085718", base64.StdEncoding.EncodeToString([]byte("hash")))
	sessionID, err := client.SidAuthenticate(context.Background(), "mock-session", "mock-cert", req)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = client.PollSidUntilComplete(ctx, "mock-session", "mock-cert", sessionID, time.Second)
	if err == nil {
		t.Fatal("expected poll cancellation error")
	}
}
