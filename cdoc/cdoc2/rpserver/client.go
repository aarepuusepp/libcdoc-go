package rpserver

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2/riahttp"
	"github.com/aarepuusepp/libcdoc-go/v2/internal"
)

// Client communicates with the CDOC2 RP-server.
type Client struct {
	http    *riahttp.Client
	baseURL *url.URL
}

// Config holds RP-server connection settings.
type Config struct {
	HostURL    string
	TrustStore *x509.CertPool
}

// NewClient creates an RP-server client.
func NewClient(cfg Config) (*Client, error) {
	base, err := riahttp.ValidateBaseURL(cfg.HostURL)
	if err != nil {
		return nil, fmt.Errorf("invalid rp-server URL: %w", err)
	}
	allow := riahttp.HostAllowlist{}
	allow.RegisterBase(base)
	return &Client{
		baseURL: base,
		http: riahttp.NewClient(riahttp.Config{
			Timeout:    120 * time.Second,
			AllowHosts: allow,
			Transport:  riahttp.NewTransportTLS(cfg.TrustStore, nil, false),
		}),
	}, nil
}

// NewClientWithHTTP injects HTTP client (tests).
func NewClientWithHTTP(base *url.URL, h *riahttp.Client) *Client {
	return &Client{baseURL: base, http: h}
}

// HostURL returns the configured RP server base URL.
func (c *Client) HostURL() string {
	if c == nil || c.baseURL == nil {
		return ""
	}
	return c.baseURL.String()
}

// SidAuthenticate starts Smart-ID authentication (POST /sid/authenticate, expect 200).
func (c *Client) SidAuthenticate(ctx context.Context, sessionToken, sessionCertificate string, req SidAuthenticateRequest) (string, error) {
	return c.postAuthenticate(ctx, []string{"sid", "authenticate"}, sessionToken, sessionCertificate, req)
}

// SidSession polls Smart-ID session status (GET /sid/session/{sessionID}).
func (c *Client) SidSession(ctx context.Context, sessionToken, sessionCertificate, sessionID string) (*SidSessionStatus, error) {
	res, err := c.getSession(ctx, []string{"sid", "session", sessionID}, sessionToken, sessionCertificate)
	if err != nil {
		return nil, err
	}
	var status SidSessionStatus
	if err := json.Unmarshal(res.Body, &status); err != nil {
		return nil, internal.NewDecryptionError("failed to decode sid session status", err)
	}
	return &status, nil
}

// PollSidUntilComplete polls SID session until COMPLETE or terminal failure.
func (c *Client) PollSidUntilComplete(ctx context.Context, sessionToken, sessionCertificate, sessionID string, interval time.Duration) (*SidSessionStatus, error) {
	if interval <= 0 {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		status, err := c.SidSession(ctx, sessionToken, sessionCertificate, sessionID)
		if err != nil {
			return nil, err
		}
		switch status.State {
		case StateComplete:
			if status.Result != nil {
				if err := sidTerminalError(status.Result.EndResult); err != nil {
					return status, err
				}
			}
			return status, nil
		case StateRunning:
		default:
			return status, internal.NewDecryptionError("sid session ended with state "+status.State, nil)
		}
		select {
		case <-ctx.Done():
			return nil, internal.NewDecryptionError("sid session poll cancelled", ctx.Err())
		case <-ticker.C:
		}
	}
}

// MidAuthenticate starts Mobile-ID authentication (POST /mid/authenticate, expect 200).
func (c *Client) MidAuthenticate(ctx context.Context, sessionToken, sessionCertificate string, req MidAuthenticateRequest) (string, error) {
	return c.postAuthenticate(ctx, []string{"mid", "authenticate"}, sessionToken, sessionCertificate, req)
}

// MidSession polls Mobile-ID session status and captures RFC 9421 proof headers.
func (c *Client) MidSession(ctx context.Context, sessionToken, sessionCertificate, sessionID string) (*MidSessionStatus, error) {
	res, err := c.getSession(ctx, []string{"mid", "session", sessionID}, sessionToken, sessionCertificate)
	if err != nil {
		return nil, err
	}
	var status MidSessionStatus
	if err := json.Unmarshal(res.Body, &status); err != nil {
		return nil, internal.NewDecryptionError("failed to decode mid session status", err)
	}
	status.Proof = RFC9421Proof{
		RpSignedHash:   res.Header.Get("x-rp-signed-hash"),
		RpName:         res.Header.Get("x-rp-name"),
		SignatureInput: res.Header.Get("Signature-Input"),
		Signature:      res.Header.Get("Signature"),
	}
	return &status, nil
}

// PollMidUntilComplete polls MID session until COMPLETE or terminal failure.
func (c *Client) PollMidUntilComplete(ctx context.Context, sessionToken, sessionCertificate, sessionID string, interval time.Duration) (*MidSessionStatus, error) {
	if interval <= 0 {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		status, err := c.MidSession(ctx, sessionToken, sessionCertificate, sessionID)
		if err != nil {
			return nil, err
		}
		switch status.State {
		case StateComplete:
			if err := midTerminalError(status.Result); err != nil {
				return status, err
			}
			return status, nil
		case StateRunning:
		default:
			return status, internal.NewDecryptionError("mid session ended with state "+status.State, nil)
		}
		select {
		case <-ctx.Done():
			return nil, internal.NewDecryptionError("mid session poll cancelled", ctx.Err())
		case <-ticker.C:
		}
	}
}

func (c *Client) postAuthenticate(ctx context.Context, path []string, sessionToken, sessionCertificate string, body any) (string, error) {
	if c == nil || c.http == nil {
		return "", internal.NewDecryptionError("rp client not configured", nil)
	}
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return "", internal.NewDecryptionError("failed to marshal authenticate request", err)
	}
	req, err := c.http.NewJSONRequest(ctx, http.MethodPost, c.baseURL, path, jsonBody)
	if err != nil {
		return "", internal.NewDecryptionError(err.Error(), err)
	}
	req.Header.Set("x-cdoc2-session-token", sessionToken)
	req.Header.Set("x-cdoc2-session-x5c", sessionCertificate)
	res, err := c.http.Do(ctx, req)
	if err != nil {
		return "", internal.NewDecryptionError("authenticate request failed", err)
	}
	if res.StatusCode != http.StatusOK {
		return "", internal.NewDecryptionError("authenticate failed", &riahttp.RemoteError{
			Op: "rp authenticate POST", StatusCode: res.StatusCode, Body: string(res.Body),
		})
	}
	var sidResp SessionIDResponse
	if err := json.Unmarshal(res.Body, &sidResp); err != nil {
		return "", internal.NewDecryptionError("failed to decode session id", err)
	}
	if sidResp.SessionID == "" {
		return "", internal.NewDecryptionError("missing sessionID in authenticate response", nil)
	}
	return sidResp.SessionID, nil
}

func (c *Client) getSession(ctx context.Context, path []string, sessionToken, sessionCertificate string) (*riahttp.Result, error) {
	if c == nil || c.http == nil {
		return nil, internal.NewDecryptionError("rp client not configured", nil)
	}
	target, err := riahttp.BuildURL(c.baseURL, path...)
	if err != nil {
		return nil, internal.NewDecryptionError(err.Error(), err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, internal.NewDecryptionError(err.Error(), err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("x-cdoc2-session-token", sessionToken)
	req.Header.Set("x-cdoc2-session-x5c", sessionCertificate)
	res, err := c.http.Do(ctx, req)
	if err != nil {
		return nil, internal.NewDecryptionError("session request failed", err)
	}
	if res.StatusCode != http.StatusOK {
		return nil, internal.NewDecryptionError("session poll failed", &riahttp.RemoteError{
			Op: "rp session GET", StatusCode: res.StatusCode, Body: string(res.Body),
		})
	}
	return res, nil
}
