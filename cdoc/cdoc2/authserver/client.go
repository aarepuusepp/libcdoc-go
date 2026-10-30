package authserver

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2/bounds"
	"github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2/riahttp"
	"github.com/aarepuusepp/libcdoc-go/v2/internal"
)

// Client communicates with the CDOC2 auth-server.
type Client struct {
	http    *riahttp.Client
	baseURL *url.URL
}

// Config holds auth-server connection settings.
type Config struct {
	HostURL    string
	TrustStore *x509.CertPool
}

// AuthIdentity identifies the user for authentication.
type AuthIdentity struct {
	Identifier string `json:"identifier"`
	MobileNr   string `json:"mobileNr,omitempty"`
	Language   string `json:"language,omitempty"`
}

// StartAuthResponse holds data from starting auth.
type StartAuthResponse struct {
	AuthProcessUUID  string
	VerificationCode string
}

// AuthProcessStatus is the auth process poll result.
type AuthProcessStatus struct {
	Status             string  `json:"status"`
	EndResult          *string `json:"endResult"`
	SessionToken       *string `json:"sessionToken"`
	SigningCertificate *string `json:"signingCertificate"`
}

// StartAuthResponseBody is the JSON body from POST /auth/start.
type StartAuthResponseBody struct {
	VC string `json:"vc"`
}

// Terminal auth process states per OpenAPI 0.9.4-draft.
const (
	StatusComplete  = "COMPLETE"
	StatusFailed    = "FAILED"
	StatusCancelled = "CANCELLED"
	StatusRunning   = "RUNNING"
)

// NewClient creates an auth-server client.
func NewClient(cfg Config) (*Client, error) {
	base, err := riahttp.ValidateBaseURL(cfg.HostURL)
	if err != nil {
		return nil, fmt.Errorf("invalid auth-server URL: %w", err)
	}
	allow := riahttp.HostAllowlist{}
	allow.RegisterBase(base)
	return &Client{
		baseURL: base,
		http: riahttp.NewClient(riahttp.Config{
			Timeout:    60 * time.Second,
			AllowHosts: allow,
			Transport:  riahttp.NewTransportTLS(cfg.TrustStore, nil, false),
		}),
	}, nil
}

// NewClientWithHTTP injects HTTP client (tests).
func NewClientWithHTTP(base *url.URL, h *riahttp.Client) *Client {
	return &Client{baseURL: base, http: h}
}

// StartAuth begins an authentication process (POST /auth/start, expect 201).
func (c *Client) StartAuth(ctx context.Context, identity AuthIdentity) (*StartAuthResponse, error) {
	if c == nil || c.http == nil {
		return nil, internal.NewDecryptionError("auth client not configured", nil)
	}
	if lang := strings.TrimSpace(identity.Language); lang != "" && lang != "et" && lang != "en" {
		return nil, internal.NewDecryptionError("language must be ISO 639-1 et or en", nil)
	}
	body, err := json.Marshal(identity)
	if err != nil {
		return nil, internal.NewDecryptionError("failed to marshal auth identity", err)
	}
	req, err := c.http.NewJSONRequest(ctx, http.MethodPost, c.baseURL, []string{"auth", "start"}, body)
	if err != nil {
		return nil, internal.NewDecryptionError(err.Error(), err)
	}
	res, err := c.http.Do(ctx, req)
	if err != nil {
		return nil, internal.NewDecryptionError("auth start request failed", err)
	}
	if res.StatusCode != http.StatusCreated {
		return nil, internal.NewDecryptionError("auth start failed", &riahttp.RemoteError{
			Op: "auth start POST", StatusCode: res.StatusCode, Body: string(res.Body),
		})
	}
	var bodyResp StartAuthResponseBody
	if err := json.Unmarshal(res.Body, &bodyResp); err != nil {
		return nil, internal.NewDecryptionError("failed to decode auth start response", err)
	}
	location := res.Header.Get("Location")
	if err := riahttp.AssertSameHost(c.baseURL, location); err != nil {
		return nil, internal.NewDecryptionError("Location host mismatch", err)
	}
	uuid := extractAuthUUID(location)
	if len(uuid) < bounds.MinTransactionIDLen || len(uuid) > 36 {
		return nil, internal.NewDecryptionError("missing or invalid auth process uuid in Location", nil)
	}
	return &StartAuthResponse{
		AuthProcessUUID:  uuid,
		VerificationCode: bodyResp.VC,
	}, nil
}

// GetAuthProcessStatus polls auth process status.
func (c *Client) GetAuthProcessStatus(ctx context.Context, authProcessUUID string) (*AuthProcessStatus, error) {
	if c == nil || c.http == nil {
		return nil, internal.NewDecryptionError("auth client not configured", nil)
	}
	res, err := c.http.Get(ctx, c.baseURL, "auth", "status", authProcessUUID)
	if err != nil {
		return nil, internal.NewDecryptionError("auth status request failed", err)
	}
	if res.StatusCode != http.StatusOK {
		return nil, internal.NewDecryptionError("auth status failed", &riahttp.RemoteError{
			Op: "auth status GET", StatusCode: res.StatusCode, Body: string(res.Body),
		})
	}
	var status AuthProcessStatus
	if err := json.Unmarshal(res.Body, &status); err != nil {
		return nil, internal.NewDecryptionError("failed to decode auth status", err)
	}
	return &status, nil
}

// PollUntilComplete polls until terminal state or context deadline.
func (c *Client) PollUntilComplete(ctx context.Context, authProcessUUID string, interval time.Duration) (*AuthProcessStatus, error) {
	if interval <= 0 {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		status, err := c.GetAuthProcessStatus(ctx, authProcessUUID)
		if err != nil {
			return nil, err
		}
		switch status.Status {
		case StatusComplete:
			return status, nil
		case StatusFailed, StatusCancelled:
			return status, internal.NewDecryptionError("auth process ended with status "+status.Status, nil)
		}
		select {
		case <-ctx.Done():
			return nil, internal.NewDecryptionError("auth process poll cancelled", ctx.Err())
		case <-ticker.C:
		}
	}
}

func extractAuthUUID(location string) string {
	prefix := "/auth/status/"
	idx := strings.LastIndex(location, prefix)
	if idx == -1 {
		return ""
	}
	uuid := location[idx+len(prefix):]
	if q := strings.Index(uuid, "?"); q != -1 {
		uuid = uuid[:q]
	}
	return strings.Trim(uuid, "/")
}
