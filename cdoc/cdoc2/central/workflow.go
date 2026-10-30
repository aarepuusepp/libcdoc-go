package central

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2/authserver"
	"github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2/authtoken"
	"github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2/keyshares"
	"github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2/rpserver"
)

// ErrStepPending indicates the current remote step needs another Advance call (e.g. poll still RUNNING).
var ErrStepPending = errors.New("share recovery step pending")

// RecoveryStep identifies the next remote transition in share recovery.
type RecoveryStep string

const (
	StepAuthStart    RecoveryStep = "auth_start"
	StepAuthPoll     RecoveryStep = "auth_poll"
	StepCreateNonce  RecoveryStep = "create_nonce"
	StepRPAuth       RecoveryStep = "rp_auth"
	StepRPPoll       RecoveryStep = "rp_poll"
	StepBuildAuthJWT RecoveryStep = "build_auth_jwt"
	StepFetchShare   RecoveryStep = "fetch_share"
	StepComplete     RecoveryStep = "complete"
)

// ShareRecoveryState is a resumable snapshot of in-progress share recovery (sensitive fields must not be logged).
type ShareRecoveryState struct {
	Step             RecoveryStep
	Issuer           string
	AuthType         AuthMeansType
	MobileNr         string
	Language         string
	ShareRefs        []ShareReference
	AuthProcessUUID  string
	VerificationCode string
	Session          *AuthSession
	Nonces           []authtoken.ShareAccess
	NonceIndex       int
	RPSessionID      string
	AuthTokens       map[string]string
	AuthCert         string
	SidRPv3Params    string
	MIDProof         rpserver.RFC9421Proof
	FetchedShares    [][]byte
	FetchIndex       int
}

// ShareRecoveryWorkflow executes one RIA remote call per Advance.
type ShareRecoveryWorkflow struct {
	svc   *Services
	state ShareRecoveryState
}

// NewShareRecoveryWorkflow starts a new resumable share recovery flow.
func NewShareRecoveryWorkflow(
	svc *Services,
	issuer string,
	shareRefs []ShareReference,
	authType AuthMeansType,
	mobileNr, language string,
) (*ShareRecoveryWorkflow, error) {
	if svc == nil {
		return nil, fmt.Errorf("central services not configured")
	}
	if err := ValidateNOfN(len(shareRefs), svc.SharesMinRequired); err != nil {
		return nil, err
	}
	if svc.AuthClient == nil || svc.RPClient == nil {
		return nil, fmt.Errorf("auth and rp clients required for share recovery")
	}
	return &ShareRecoveryWorkflow{
		svc: svc,
		state: ShareRecoveryState{
			Step:      StepAuthStart,
			Issuer:    issuer,
			AuthType:  authType,
			MobileNr:  mobileNr,
			Language:  language,
			ShareRefs: append([]ShareReference(nil), shareRefs...),
		},
	}, nil
}

// ResumeShareRecoveryWorkflow continues from a previously saved state.
func ResumeShareRecoveryWorkflow(svc *Services, state ShareRecoveryState) (*ShareRecoveryWorkflow, error) {
	if svc == nil {
		return nil, fmt.Errorf("central services not configured")
	}
	if state.Step == StepComplete {
		return nil, fmt.Errorf("workflow already complete")
	}
	if err := ValidateNOfN(len(state.ShareRefs), svc.SharesMinRequired); err != nil {
		return nil, err
	}
	return &ShareRecoveryWorkflow{svc: svc, state: state}, nil
}

// NewShareRecoveryWorkflowWithSession skips auth-server calls when session is already available.
func NewShareRecoveryWorkflowWithSession(
	svc *Services,
	session *AuthSession,
	issuer string,
	shareRefs []ShareReference,
	authType AuthMeansType,
	mobileNr string,
) (*ShareRecoveryWorkflow, error) {
	wf, err := NewShareRecoveryWorkflow(svc, issuer, shareRefs, authType, mobileNr, "et")
	if err != nil {
		return nil, err
	}
	wf.state.Step = StepCreateNonce
	wf.state.Session = session
	return wf, nil
}

// State returns a copy of the workflow state for persistence.
func (w *ShareRecoveryWorkflow) State() ShareRecoveryState {
	return w.state
}

// Done reports whether all shares were fetched.
func (w *ShareRecoveryWorkflow) Done() bool {
	return w.state.Step == StepComplete
}

// Shares returns recovered share bytes after completion.
func (w *ShareRecoveryWorkflow) Shares() ([][]byte, error) {
	if !w.Done() {
		return nil, fmt.Errorf("share recovery not complete")
	}
	if len(w.state.FetchedShares) != len(w.state.ShareRefs) {
		return nil, fmt.Errorf("incomplete share set")
	}
	return w.state.FetchedShares, nil
}

// RunToCompletion executes Advance until complete or error.
func (w *ShareRecoveryWorkflow) RunToCompletion(ctx context.Context) ([][]byte, error) {
	for !w.Done() {
		if err := w.Advance(ctx); err != nil && !errors.Is(err, ErrStepPending) {
			return nil, err
		}
	}
	return w.Shares()
}

// Advance performs exactly one remote transition (or one local JWT build step).
func (w *ShareRecoveryWorkflow) Advance(ctx context.Context) error {
	// Previously persisted mock proofs are not valid production credentials.
	switch w.state.Step {
	case StepRPAuth, StepRPPoll, StepBuildAuthJWT, StepFetchShare:
		return authtoken.ErrExternalProofProfileUnsupported
	}

	switch w.state.Step {
	case StepAuthStart:
		return w.advanceAuthStart(ctx)
	case StepAuthPoll:
		return w.advanceAuthPoll(ctx)
	case StepCreateNonce:
		return w.advanceCreateNonce(ctx)
	case StepRPAuth:
		return w.advanceRPAuth(ctx)
	case StepRPPoll:
		return w.advanceRPPoll(ctx)
	case StepBuildAuthJWT:
		return w.advanceBuildAuthJWT()
	case StepFetchShare:
		return w.advanceFetchShare(ctx)
	case StepComplete:
		return nil
	default:
		return fmt.Errorf("unknown recovery step %q", w.state.Step)
	}
}

func (w *ShareRecoveryWorkflow) advanceAuthStart(ctx context.Context) error {
	resp, err := w.svc.AuthClient.StartAuth(ctx, authserver.AuthIdentity{
		Identifier: w.state.Issuer,
		MobileNr:   w.state.MobileNr,
		Language:   w.state.Language,
	})
	if err != nil {
		return err
	}
	w.state.AuthProcessUUID = resp.AuthProcessUUID
	w.state.VerificationCode = resp.VerificationCode
	w.state.Step = StepAuthPoll
	return nil
}

func (w *ShareRecoveryWorkflow) advanceAuthPoll(ctx context.Context) error {
	status, err := w.svc.AuthClient.GetAuthProcessStatus(ctx, w.state.AuthProcessUUID)
	if err != nil {
		return err
	}
	switch status.Status {
	case authserver.StatusComplete:
		if status.SessionToken == nil || status.SigningCertificate == nil {
			return fmt.Errorf("auth completed without session token")
		}
		w.state.Session = &AuthSession{
			SessionToken:       *status.SessionToken,
			SigningCertificate: *status.SigningCertificate,
			VerificationCode:   w.state.VerificationCode,
			AuthProcessUUID:    w.state.AuthProcessUUID,
		}
		w.state.Step = StepCreateNonce
		return nil
	case authserver.StatusRunning:
		return ErrStepPending
	default:
		return fmt.Errorf("auth process ended with status %s", status.Status)
	}
}

func (w *ShareRecoveryWorkflow) advanceCreateNonce(ctx context.Context) error {
	if w.state.NonceIndex >= len(w.state.ShareRefs) {
		w.state.Step = StepRPAuth
		return w.Advance(ctx)
	}
	ref := w.state.ShareRefs[w.state.NonceIndex]
	client := w.svc.clientForShareServer(ref.ServerBaseURL)
	if client == nil {
		return fmt.Errorf("no client for share server %s", ref.ServerBaseURL)
	}
	disclosedSession := discloseSessionForAudience(w.state.Session.SessionToken, ref.ServerBaseURL)
	nr, err := client.CreateNonce(ctx, ref.ShareID, disclosedSession, w.state.Session.SigningCertificate)
	if err != nil {
		return err
	}
	w.state.Nonces = append(w.state.Nonces, authtoken.ShareAccess{
		ServerBaseURL: ref.ServerBaseURL,
		ShareID:       ref.ShareID,
		Nonce:         nr.Nonce,
	})
	w.state.NonceIndex++
	if w.state.NonceIndex >= len(w.state.ShareRefs) {
		w.state.Step = StepRPAuth
	}
	return nil
}

func (w *ShareRecoveryWorkflow) advanceRPAuth(ctx context.Context) error {
	// A verified ACSP_V2/RFC9421-to-auth-token adapter is not implemented.
	// Do not initiate an authentication that cannot produce a valid bound token.
	return authtoken.ErrExternalProofProfileUnsupported
}

func (w *ShareRecoveryWorkflow) advanceRPPoll(ctx context.Context) error {
	session := w.state.Session
	rpSession := discloseSessionForAudience(session.SessionToken, w.svc.RPClientHost())

	switch w.state.AuthType {
	case AuthMeansSID:
		status, err := w.svc.RPClient.SidSession(ctx, rpSession, session.SigningCertificate, w.state.RPSessionID)
		if err != nil {
			return err
		}
		if status.State == rpserver.StateRunning {
			return ErrStepPending
		}
		if status.State != rpserver.StateComplete {
			return fmt.Errorf("sid session ended with state %s", status.State)
		}
		sigBytes, err := status.SignatureBytes()
		if err != nil {
			return err
		}
		certBytes, err := status.CertificateBytes()
		if err != nil {
			return err
		}
		w.state.SidRPv3Params, err = status.SidRPv3SignatureParameters()
		if err != nil {
			return err
		}
		w.state.AuthTokens, w.state.AuthCert, err = authtoken.CreateFromSignature(
			w.state.Issuer, w.state.Nonces, sigBytes, certBytes,
		)
		if err != nil {
			return err
		}
	default:
		status, err := w.svc.RPClient.MidSession(ctx, rpSession, session.SigningCertificate, w.state.RPSessionID)
		if err != nil {
			return err
		}
		if status.State == rpserver.StateRunning {
			return ErrStepPending
		}
		if status.State != rpserver.StateComplete || status.Result != rpserver.MidResultOK {
			return fmt.Errorf("mid session not complete")
		}
		sigBytes, err := status.SignatureBytes()
		if err != nil {
			return err
		}
		certBytes, err := status.CertificateBytes()
		if err != nil {
			return err
		}
		w.state.MIDProof = status.Proof
		w.state.AuthTokens, w.state.AuthCert, err = authtoken.CreateFromSignature(
			w.state.Issuer, w.state.Nonces, sigBytes, certBytes,
		)
		if err != nil {
			return err
		}
	}
	w.state.Step = StepBuildAuthJWT
	return w.advanceBuildAuthJWT()
}

func (w *ShareRecoveryWorkflow) advanceBuildAuthJWT() error {
	if len(w.state.AuthTokens) != len(w.state.ShareRefs) {
		return fmt.Errorf("auth tokens missing for one or more shares")
	}
	w.state.Step = StepFetchShare
	return nil
}

func (w *ShareRecoveryWorkflow) advanceFetchShare(ctx context.Context) error {
	if w.state.FetchIndex >= len(w.state.ShareRefs) {
		w.state.Step = StepComplete
		return nil
	}
	ref := w.state.ShareRefs[w.state.FetchIndex]
	client := w.svc.clientForShareServer(ref.ServerBaseURL)
	if client == nil {
		return fmt.Errorf("no client for share server %s", ref.ServerBaseURL)
	}
	authToken := w.state.AuthTokens[ref.ShareID]
	if authToken == "" {
		return fmt.Errorf("missing auth token for share %s", ref.ShareID)
	}
	disclosedSession := discloseSessionForAudience(w.state.Session.SessionToken, ref.ServerBaseURL)
	ks, err := client.GetKeyShare(ctx, ref.ShareID, keyshares.AuthHeaders{
		AuthToken:              authToken,
		AuthCertificate:        w.state.AuthCert,
		SessionToken:           disclosedSession,
		SessionCertificate:     w.state.Session.SigningCertificate,
		SidRpV3SignatureParams: w.state.SidRPv3Params,
		RpSignedHash:           w.state.MIDProof.RpSignedHash,
		RpName:                 w.state.MIDProof.RpName,
		SignatureInput:         w.state.MIDProof.SignatureInput,
		Signature:              w.state.MIDProof.Signature,
	})
	if err != nil {
		return err
	}
	shareBytes, err := base64.StdEncoding.DecodeString(ks.Share)
	if err != nil {
		return err
	}
	w.state.FetchedShares = append(w.state.FetchedShares, shareBytes)
	w.state.FetchIndex++
	if w.state.FetchIndex >= len(w.state.ShareRefs) {
		w.state.Step = StepComplete
	}
	return nil
}
