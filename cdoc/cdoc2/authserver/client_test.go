package authserver_test

import (
	"context"
	"testing"
	"time"

	"github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2/authserver"
	"github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2/riahttp"
)

func TestAuthClient_StartAndPoll_MockServer(t *testing.T) {
	riahttp.DevModePrivateHosts = true
	t.Cleanup(func() { riahttp.DevModePrivateHosts = false })

	mock := authserver.NewMockServer()
	defer mock.Stop()

	client, err := authserver.NewTestClient(mock)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.StartAuth(context.Background(), authserver.AuthIdentity{
		Identifier: "etsi/PNOEE-38001085718",
		Language:   "et",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.AuthProcessUUID == "" || resp.VerificationCode == "" {
		t.Fatal("expected auth process uuid and verification code")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	status, err := client.PollUntilComplete(ctx, resp.AuthProcessUUID, 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if status.Status != authserver.StatusComplete {
		t.Fatalf("status: got %q", status.Status)
	}
	if status.SessionToken == nil || status.SigningCertificate == nil {
		t.Fatal("expected session token and signing certificate")
	}
}

func TestAuthClient_InvalidLanguage(t *testing.T) {
	riahttp.DevModePrivateHosts = true
	t.Cleanup(func() { riahttp.DevModePrivateHosts = false })

	mock := authserver.NewMockServer()
	defer mock.Stop()
	client, err := authserver.NewTestClient(mock)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.StartAuth(context.Background(), authserver.AuthIdentity{
		Identifier: "etsi/PNOEE-38001085718",
		Language:   "fi",
	})
	if err == nil {
		t.Fatal("expected language validation error")
	}
}

func TestAuthClient_PollCancelled(t *testing.T) {
	riahttp.DevModePrivateHosts = true
	t.Cleanup(func() { riahttp.DevModePrivateHosts = false })

	mock := authserver.NewMockServer()
	defer mock.Stop()
	client, err := authserver.NewTestClient(mock)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.StartAuth(context.Background(), authserver.AuthIdentity{
		Identifier: "etsi/PNOEE-38001085718",
		Language:   "en",
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = client.PollUntilComplete(ctx, resp.AuthProcessUUID, time.Second)
	if err == nil {
		t.Fatal("expected poll cancellation error")
	}
}
