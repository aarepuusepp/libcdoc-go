package central

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2/authserver"
	"github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2/keyserver"
	"github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2/keyshares"
	"github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2/rpserver"
)

// Services holds clients for RIA central CDOC2 infrastructure.
type Services struct {
	KeyServerClient   *keyserver.Client
	KeyServerConfigs  map[string]keyserver.KeyServerConfig
	SharesClients     []*keyshares.Client
	SharesMinRequired int
	AuthClient        *authserver.Client
	RPClient          *rpserver.Client
}

// ShareReference identifies a stored key share.
type ShareReference struct {
	ServerBaseURL string
	ShareID       string
}

// AuthMeansType identifies Smart-ID or Mobile-ID authentication.
type AuthMeansType string

const (
	AuthMeansSID AuthMeansType = "SID"
	AuthMeansMID AuthMeansType = "MID"
)

// AuthSession holds session token data from auth-server.
type AuthSession struct {
	SessionToken       string
	SigningCertificate string
	VerificationCode   string
	AuthProcessUUID    string
}

// StartAuthSession starts auth-server session for key share access.
func (s *Services) StartAuthSession(ctx context.Context, identifier, mobileNr, language string) (*AuthSession, error) {
	if s.AuthClient == nil {
		return nil, fmt.Errorf("auth client not configured")
	}
	resp, err := s.AuthClient.StartAuth(ctx, authserver.AuthIdentity{
		Identifier: identifier,
		MobileNr:   mobileNr,
		Language:   language,
	})
	if err != nil {
		return nil, err
	}
	pollCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	status, err := s.AuthClient.PollUntilComplete(pollCtx, resp.AuthProcessUUID, 500*time.Millisecond)
	if err != nil {
		return nil, err
	}
	if status.SessionToken == nil || status.SigningCertificate == nil {
		return nil, fmt.Errorf("auth completed without session token")
	}
	return &AuthSession{
		SessionToken:       *status.SessionToken,
		SigningCertificate: *status.SigningCertificate,
		VerificationCode:   resp.VerificationCode,
		AuthProcessUUID:    resp.AuthProcessUUID,
	}, nil
}

// FetchKeyShares downloads all key shares after authentication using resumable N-of-N workflow.
func (s *Services) FetchKeyShares(
	ctx context.Context,
	session *AuthSession,
	issuer string,
	shareRefs []ShareReference,
	authType AuthMeansType,
	mobileNr string,
) ([][]byte, error) {
	wf, err := NewShareRecoveryWorkflowWithSession(s, session, issuer, shareRefs, authType, mobileNr)
	if err != nil {
		return nil, err
	}
	return wf.RunToCompletion(ctx)
}

func (s *Services) clientForShareServer(baseURL string) *keyshares.Client {
	normalized := strings.TrimRight(baseURL, "/")
	for _, c := range s.SharesClients {
		if strings.TrimRight(c.BaseURL(), "/") == normalized {
			return c
		}
	}
	return nil
}

func (s *Services) RPClientHost() string {
	if s.RPClient == nil {
		return ""
	}
	return s.RPClient.HostURL()
}

func discloseSessionForAudience(fullSession, audience string) string {
	if strings.HasPrefix(fullSession, "mock-") {
		return fullSession
	}
	return fullSession
}
