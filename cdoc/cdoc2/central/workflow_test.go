package central_test

import (
	"context"
	"encoding/base64"
	"errors"
	"github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2/authtoken"
	"testing"

	"github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2/authserver"
	"github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2/central"
	"github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2/keyshares"
	"github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2/riahttp"
	"github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2/rpserver"
)

type centralFixture struct {
	svc      *central.Services
	share1   string
	share2   string
	share1B  []byte
	share2B  []byte
	baseURL1 string
	baseURL2 string
}

func setupCentralFixture(t *testing.T) centralFixture {
	t.Helper()
	riahttp.DevModePrivateHosts = true
	t.Cleanup(func() { riahttp.DevModePrivateHosts = false })

	shares1 := keyshares.NewMockServer()
	shares2 := keyshares.NewMockServer()
	authSrv := authserver.NewMockServer()
	rpSrv := rpserver.NewMockServer()
	t.Cleanup(func() {
		shares1.Stop()
		shares2.Stop()
		authSrv.Stop()
		rpSrv.Stop()
	})

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

	svc := &central.Services{
		SharesClients:     []*keyshares.Client{client1, client2},
		SharesMinRequired: 2,
		AuthClient:        authClient,
		RPClient:          rpClient,
	}

	ctx := context.Background()
	share1B := []byte("01234567890123456789012345678901")
	share2B := []byte("fedcba9876543210fedcba9876543210")
	id1, err := client1.CreateKeyShare(ctx, keyshares.KeyShare{
		Share:     base64.StdEncoding.EncodeToString(share1B),
		Recipient: "etsi/PNOEE-38001085718",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	id2, err := client2.CreateKeyShare(ctx, keyshares.KeyShare{
		Share:     base64.StdEncoding.EncodeToString(share2B),
		Recipient: "etsi/PNOEE-38001085718",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	return centralFixture{
		svc:      svc,
		share1:   id1,
		share2:   id2,
		share1B:  share1B,
		share2B:  share2B,
		baseURL1: client1.BaseURL(),
		baseURL2: client2.BaseURL(),
	}
}

func TestShareRecoveryWorkflow_StepByStepAndResume(t *testing.T) {
	fx := setupCentralFixture(t)
	ctx := context.Background()
	issuer := "etsi/PNOEE-38001085718"
	refs := []central.ShareReference{
		{ServerBaseURL: fx.baseURL1, ShareID: fx.share1},
		{ServerBaseURL: fx.baseURL2, ShareID: fx.share2},
	}
	session := &central.AuthSession{
		SessionToken:       "mock-session-token-resume",
		SigningCertificate: "mock-signing-cert-resume",
	}

	wf, err := central.NewShareRecoveryWorkflowWithSession(fx.svc, session, issuer, refs, central.AuthMeansSID, "")
	if err != nil {
		t.Fatal(err)
	}
	if wf.State().Step != central.StepCreateNonce {
		t.Fatalf("expected create_nonce start, got %s", wf.State().Step)
	}

	if err := wf.Advance(ctx); err != nil {
		t.Fatalf("first nonce: %v", err)
	}
	if wf.State().NonceIndex != 1 {
		t.Fatalf("expected one nonce, got index %d", wf.State().NonceIndex)
	}
	saved := wf.State()

	resumed, err := central.ResumeShareRecoveryWorkflow(fx.svc, saved)
	if err != nil {
		t.Fatal(err)
	}
	shares, err := resumed.RunToCompletion(ctx)
	if !errors.Is(err, authtoken.ErrExternalProofProfileUnsupported) || len(shares) != 0 {
		t.Fatalf("unverified proof must not release shares: shares=%d err=%v", len(shares), err)
	}
	if resumed.State().Step != central.StepRPAuth {
		t.Fatalf("unexpected step: %s", resumed.State().Step)
	}

}

func TestShareRecoveryWorkflow_UnverifiedExternalProofFailsClosed(t *testing.T) {
	fx := setupCentralFixture(t)
	ctx := context.Background()
	issuer := "etsi/PNOEE-38001085718"
	refs := []central.ShareReference{
		{ServerBaseURL: fx.baseURL1, ShareID: fx.share1},
		{ServerBaseURL: fx.baseURL2, ShareID: fx.share2},
	}

	wf, err := central.NewShareRecoveryWorkflow(fx.svc, issuer, refs, central.AuthMeansSID, "", "et")
	if err != nil {
		t.Fatal(err)
	}
	shares, err := wf.RunToCompletion(ctx)
	if !errors.Is(err, authtoken.ErrExternalProofProfileUnsupported) || len(shares) != 0 {
		t.Fatalf("unverified proof must not release shares: shares=%d err=%v", len(shares), err)
	}

}

func TestShareRecoveryWorkflow_RejectsPartialNOfN(t *testing.T) {
	fx := setupCentralFixture(t)
	fx.svc.SharesMinRequired = 3
	refs := []central.ShareReference{
		{ServerBaseURL: fx.baseURL1, ShareID: fx.share1},
		{ServerBaseURL: fx.baseURL2, ShareID: fx.share2},
	}
	_, err := central.NewShareRecoveryWorkflow(fx.svc, "etsi/PNOEE-38001085718", refs, central.AuthMeansSID, "", "et")
	if err == nil {
		t.Fatal("expected N-of-N validation error")
	}
}
