package keyshares

import (
	"context"
	"crypto/tls"
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

// Client communicates with CDOC2 key-shares servers.
type Client struct {
	http    *riahttp.Client
	baseURL *url.URL
}

// Config holds connection settings for a key-shares server.
type Config struct {
	BaseURL            string
	TrustStore         *x509.CertPool
	ClientCert         *tls.Certificate
	InsecureSkipVerify bool
}

// KeyShare is the request/response body for key share operations.
type KeyShare struct {
	Share     string `json:"share"`
	Recipient string `json:"recipient"`
}

// NonceResponse is returned when creating a server nonce.
type NonceResponse struct {
	Nonce string `json:"nonce"`
}

// AuthHeaders holds authentication headers for GET /key-shares/{shareId}.
type AuthHeaders struct {
	AuthToken              string
	AuthCertificate        string
	SessionToken           string
	SessionCertificate     string
	SidRpV3SignatureParams string
	RpSignedHash           string
	RpName                 string
	SignatureInput         string
	Signature              string
}

// NewClient creates a client for the given base URL.
func NewClient(cfg Config) (*Client, error) {
	base, err := riahttp.ValidateBaseURL(cfg.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid key-shares base URL: %w", err)
	}
	allow := riahttp.HostAllowlist{}
	allow.RegisterBase(base)
	return &Client{
		baseURL: base,
		http: riahttp.NewClient(riahttp.Config{
			AllowHosts:         allow,
			InsecureSkipVerify: cfg.InsecureSkipVerify,
			Transport:          riahttp.NewTransportTLS(cfg.TrustStore, cfg.ClientCert, cfg.InsecureSkipVerify),
		}),
	}, nil
}

// NewClientWithHTTP injects a configured HTTP client (tests).
func NewClientWithHTTP(base *url.URL, h *riahttp.Client) *Client {
	return &Client{baseURL: base, http: h}
}

// BaseURL returns the configured server base URL string.
func (c *Client) BaseURL() string {
	if c == nil || c.baseURL == nil {
		return ""
	}
	return c.baseURL.String()
}

// CreateKeyShare stores a key share (POST /key-shares, expect 201).
func (c *Client) CreateKeyShare(ctx context.Context, share KeyShare, expiryTime *time.Time) (string, error) {
	if c == nil || c.http == nil {
		return "", internal.NewEncryptionError("key-shares client not configured", nil)
	}
	body, err := json.Marshal(share)
	if err != nil {
		return "", internal.NewEncryptionError("failed to marshal key share", err)
	}
	req, err := c.http.NewJSONRequest(ctx, http.MethodPost, c.baseURL, []string{"key-shares"}, body)
	if err != nil {
		return "", internal.NewEncryptionError(err.Error(), err)
	}
	if expiryTime != nil {
		req.Header.Set("x-expiry-time", expiryTime.UTC().Format(time.RFC3339))
	}
	res, err := c.http.Do(ctx, req)
	if err != nil {
		return "", internal.NewEncryptionError("failed to post key share", err)
	}
	if res.StatusCode != http.StatusCreated {
		return "", internal.NewEncryptionError("key share create failed", &riahttp.RemoteError{
			Op: "key-shares POST", StatusCode: res.StatusCode, Body: string(res.Body),
		})
	}
	location := res.Header.Get("Location")
	if err := riahttp.AssertSameHost(c.baseURL, location); err != nil {
		return "", internal.NewEncryptionError("Location host mismatch", err)
	}
	shareID := extractShareID(location)
	if len(shareID) < bounds.MinTransactionIDLen || len(shareID) > bounds.MaxTransactionIDLen {
		return "", internal.NewEncryptionError("invalid share id in Location", nil)
	}
	return shareID, nil
}

// CreateNonce requests a server nonce (POST /key-shares/{shareId}/nonce).
func (c *Client) CreateNonce(ctx context.Context, shareID, sessionToken, sessionCertificate string) (*NonceResponse, error) {
	if c == nil || c.http == nil {
		return nil, internal.NewDecryptionError("key-shares client not configured", nil)
	}
	req, err := c.http.NewJSONRequest(ctx, http.MethodPost, c.baseURL, []string{"key-shares", shareID, "nonce"}, []byte("{}"))
	if err != nil {
		return nil, internal.NewDecryptionError(err.Error(), err)
	}
	req.Header.Set("x-cdoc2-session-token", sessionToken)
	req.Header.Set("x-cdoc2-session-x5c", sessionCertificate)
	res, err := c.http.Do(ctx, req)
	if err != nil {
		return nil, internal.NewDecryptionError("failed to post nonce request", err)
	}
	if res.StatusCode != http.StatusOK {
		return nil, internal.NewDecryptionError("nonce create failed", &riahttp.RemoteError{
			Op: "key-shares nonce POST", StatusCode: res.StatusCode, Body: string(res.Body),
		})
	}
	var nr NonceResponse
	if err := json.Unmarshal(res.Body, &nr); err != nil {
		return nil, internal.NewDecryptionError("failed to decode nonce response", err)
	}
	return &nr, nil
}

// GetKeyShare retrieves a key share after authentication.
func (c *Client) GetKeyShare(ctx context.Context, shareID string, auth AuthHeaders) (*KeyShare, error) {
	if c == nil || c.http == nil {
		return nil, internal.NewDecryptionError("key-shares client not configured", nil)
	}
	target, err := riahttp.BuildURL(c.baseURL, "key-shares", shareID)
	if err != nil {
		return nil, internal.NewDecryptionError(err.Error(), err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, internal.NewDecryptionError("failed to create get key share request", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("x-cdoc2-auth-token", auth.AuthToken)
	req.Header.Set("x-cdoc2-auth-x5c", auth.AuthCertificate)
	req.Header.Set("x-cdoc2-session-token", auth.SessionToken)
	req.Header.Set("x-cdoc2-session-x5c", auth.SessionCertificate)
	if auth.SidRpV3SignatureParams != "" {
		req.Header.Set("x-cdoc2-sid-rpv3-signature-parameters", auth.SidRpV3SignatureParams)
	}
	if auth.RpSignedHash != "" {
		req.Header.Set("x-rp-signed-hash", auth.RpSignedHash)
	}
	if auth.RpName != "" {
		req.Header.Set("x-rp-name", auth.RpName)
	}
	if auth.SignatureInput != "" {
		req.Header.Set("Signature-Input", auth.SignatureInput)
	}
	if auth.Signature != "" {
		req.Header.Set("Signature", auth.Signature)
	}
	res, err := c.http.Do(ctx, req)
	if err != nil {
		return nil, riahttp.PrivacySafeError("key-shares GET", err)
	}
	if res.StatusCode == http.StatusNotFound {
		return nil, riahttp.PrivacySafeError("key-shares GET", &riahttp.RemoteError{Op: "key-shares GET", StatusCode: res.StatusCode})
	}
	if res.StatusCode != http.StatusOK {
		return nil, riahttp.PrivacySafeError("key-shares GET", &riahttp.RemoteError{
			Op: "key-shares GET", StatusCode: res.StatusCode, Body: string(res.Body),
		})
	}
	var ks KeyShare
	if err := json.Unmarshal(res.Body, &ks); err != nil {
		return nil, internal.NewDecryptionError("failed to decode key share", err)
	}
	return &ks, nil
}

func extractShareID(location string) string {
	prefix := "/key-shares/"
	idx := strings.LastIndex(location, prefix)
	if idx == -1 {
		if strings.Contains(location, prefix) {
			parts := strings.Split(location, prefix)
			if len(parts) > 1 {
				return strings.Trim(strings.Split(parts[1], "?")[0], "/")
			}
		}
		return ""
	}
	id := location[idx+len(prefix):]
	if slash := strings.Index(id, "/"); slash != -1 {
		id = id[:slash]
	}
	if q := strings.Index(id, "?"); q != -1 {
		id = id[:q]
	}
	return id
}
