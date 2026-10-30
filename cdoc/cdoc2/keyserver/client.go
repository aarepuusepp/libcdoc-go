package keyserver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
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

// Client performs key-capsule POST and GET with independent HTTP stacks when configured.
type Client struct {
	postHTTP         *riahttp.Client
	fetchHTTP        *riahttp.Client
	onCapsuleCreated func(CapsuleInfo)
}

// WithOnCapsuleCreated returns a copy that invokes fn after each successful POST /key-capsules.
func (c *Client) WithOnCapsuleCreated(fn func(CapsuleInfo)) *Client {
	if c == nil {
		return nil
	}
	clone := *c
	clone.onCapsuleCreated = fn
	return &clone
}

// postClient returns the HTTP client used for POST /key-capsules.
func (c *Client) postClient() *riahttp.Client {
	if c == nil {
		return nil
	}
	if c.postHTTP != nil {
		return c.postHTTP
	}
	return c.fetchHTTP
}

// fetchClient returns the HTTP client used for GET /key-capsules/{id} (recipient mTLS).
func (c *Client) fetchClient() *riahttp.Client {
	if c == nil {
		return nil
	}
	if c.fetchHTTP != nil {
		return c.fetchHTTP
	}
	return c.postHTTP
}

// NewClient creates a key server client with default TLS 1.3 transport for POST and GET.
func NewClient() *Client {
	h := riahttp.NewClient(riahttp.Config{})
	return &Client{postHTTP: h, fetchHTTP: h}
}

// KeyServerConfig holds configuration for a key server.
type KeyServerConfig struct {
	ServerID   string
	PostURL    string
	FetchURL   string
	TLSCert    *x509.Certificate
	ClientCert *tls.Certificate
	postBase   *url.URL
	fetchBase  *url.URL
}

// CapsuleInfo contains information returned from POST /key-capsules.
type CapsuleInfo struct {
	TransactionID  string
	ExpiryTime     time.Time
	ExpiryAdjusted bool
	CapsuleType    string
}

// SendKeyRequest is the JSON request body for sending key material.
type SendKeyRequest struct {
	RecipientID          string `json:"recipient_id"`
	EphemeralKeyMaterial string `json:"ephemeral_key_material"`
	CapsuleType          string `json:"capsule_type"`
}

// FetchKeyResponse represents GET /key-capsules/{id} JSON body.
type FetchKeyResponse struct {
	EphemeralKeyMaterial string `json:"ephemeral_key_material"`
}

var allowedCapsuleTypes = map[string]struct{}{
	"ecc_secp256r1": {},
	"ecc_secp384r1": {},
	"ecc_secp521r1": {},
	"rsa":           {},
}

// NewClientWithTLS creates a client with server trust and optional recipient-scoped mTLS cert for GET.
func NewClientWithTLS(serverCert *x509.Certificate, clientCert *tls.Certificate) *Client {
	var pool *x509.CertPool
	if serverCert != nil {
		pool = x509.NewCertPool()
		pool.AddCert(serverCert)
	}
	var cc *tls.Certificate
	if clientCert != nil {
		cc = clientCert
	}
	post := riahttp.NewClient(riahttp.Config{
		Transport: riahttp.NewTransportTLS(pool, nil, false),
	})
	fetch := riahttp.NewClient(riahttp.Config{
		Transport: riahttp.NewTransportTLS(pool, cc, false),
	})
	return &Client{postHTTP: post, fetchHTTP: fetch}
}

// NewClientWithTransports wires separate POST (publisher) and GET (recipient mTLS) HTTP clients.
func NewClientWithTransports(post, fetch *riahttp.Client) *Client {
	if post == nil && fetch == nil {
		return NewClient()
	}
	if post == nil {
		post = fetch
	}
	if fetch == nil {
		fetch = post
	}
	return &Client{postHTTP: post, fetchHTTP: fetch}
}

// NewClientWithHTTP allows injecting a configured riahttp client for both POST and GET (tests).
func NewClientWithHTTP(h *riahttp.Client) *Client {
	return &Client{postHTTP: h, fetchHTTP: h}
}

// PrepareConfig validates URLs and caches parsed bases on config.
func PrepareConfig(cfg KeyServerConfig) (KeyServerConfig, error) {
	post, err := riahttp.ValidateBaseURL(cfg.PostURL)
	if err != nil {
		return cfg, fmt.Errorf("invalid post URL: %w", err)
	}
	fetch, err := riahttp.ValidateBaseURL(cfg.FetchURL)
	if err != nil {
		return cfg, fmt.Errorf("invalid fetch URL: %w", err)
	}
	cfg.postBase = post
	cfg.fetchBase = fetch
	return cfg, nil
}

// SendKey posts a key capsule (OpenAPI 3.1.2 POST /key-capsules, expect 201).
func (c *Client) SendKeyWithContext(ctx context.Context, config KeyServerConfig, recipientKey, keyMaterial []byte, capsuleType string, expiryTS uint64) (*CapsuleInfo, error) {
	hc := c.postClient()
	if hc == nil {
		return nil, internal.NewEncryptionError("key server client not configured", nil)
	}
	if err := bounds.Len("recipient_id", len(recipientKey), bounds.MaxCapsuleFieldBytes); err != nil {
		return nil, internal.NewEncryptionError(err.Error(), err)
	}
	if err := bounds.Len("ephemeral_key_material", len(keyMaterial), bounds.MaxCapsuleFieldBytes); err != nil {
		return nil, internal.NewEncryptionError(err.Error(), err)
	}
	if _, ok := allowedCapsuleTypes[capsuleType]; !ok {
		return nil, internal.NewEncryptionError("unsupported capsule_type", nil)
	}

	cfg, err := PrepareConfig(config)
	if err != nil {
		return nil, internal.NewEncryptionError(err.Error(), err)
	}

	reqBody := SendKeyRequest{
		RecipientID:          base64.StdEncoding.EncodeToString(recipientKey),
		EphemeralKeyMaterial: base64.StdEncoding.EncodeToString(keyMaterial),
		CapsuleType:          capsuleType,
	}
	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, internal.NewEncryptionError("failed to marshal send key request", err)
	}

	req, err := hc.NewJSONRequest(ctx, http.MethodPost, cfg.postBase, []string{"key-capsules"}, jsonBody)
	if err != nil {
		return nil, internal.NewEncryptionError(err.Error(), err)
	}
	if expiryTS > 0 {
		req.Header.Set("x-expiry-time", time.Unix(int64(expiryTS), 0).UTC().Format(time.RFC3339))
	}

	res, err := hc.Do(ctx, req)
	if err != nil {
		return nil, internal.NewEncryptionError("failed to send key to server", err)
	}
	if res.StatusCode != http.StatusCreated {
		return nil, internal.NewEncryptionError("key server create failed", &riahttp.RemoteError{
			Op: "key-capsule POST", StatusCode: res.StatusCode, Body: string(res.Body),
		})
	}

	location := res.Header.Get("Location")
	if location == "" {
		return nil, internal.NewEncryptionError("no Location header in key server response", nil)
	}
	if err := riahttp.AssertSameHost(cfg.postBase, location); err != nil {
		return nil, internal.NewEncryptionError("Location host mismatch", err)
	}
	transactionID := extractTransactionID(location)
	if len(transactionID) < bounds.MinTransactionIDLen || len(transactionID) > bounds.MaxTransactionIDLen {
		return nil, internal.NewEncryptionError("invalid transaction id in Location", nil)
	}

	info := &CapsuleInfo{TransactionID: transactionID, CapsuleType: capsuleType}
	if expiryStr := res.Header.Get("x-expiry-time"); expiryStr != "" {
		parsed, err := time.Parse(time.RFC3339, expiryStr)
		if err != nil {
			return nil, internal.NewEncryptionError("invalid x-expiry-time", err)
		}
		info.ExpiryTime = parsed
	}
	if strings.EqualFold(res.Header.Get("x-expiry-time-adjusted"), "true") {
		info.ExpiryAdjusted = true
	}
	if c.onCapsuleCreated != nil {
		c.onCapsuleCreated(*info)
	}
	return info, nil
}

// FetchKey retrieves a key capsule (GET /key-capsules/{transactionId}, recipient mTLS on fetch base).
func (c *Client) FetchKeyWithContext(ctx context.Context, config KeyServerConfig, transactionID string) ([]byte, error) {
	hc := c.fetchClient()
	if hc == nil {
		return nil, internal.NewDecryptionError("key server client not configured", nil)
	}
	if len(transactionID) < bounds.MinTransactionIDLen || len(transactionID) > bounds.MaxTransactionIDLen {
		return nil, internal.NewDecryptionError("invalid transaction id", nil)
	}

	cfg, err := PrepareConfig(config)
	if err != nil {
		return nil, internal.NewDecryptionError(err.Error(), err)
	}

	res, err := hc.Get(ctx, cfg.fetchBase, "key-capsules", transactionID)
	if err != nil {
		return nil, riahttp.PrivacySafeError("key-capsule GET", err)
	}
	if res.StatusCode != http.StatusOK {
		re := &riahttp.RemoteError{Op: "key-capsule GET", StatusCode: res.StatusCode, Body: string(res.Body)}
		return nil, riahttp.PrivacySafeError("key-capsule GET", re)
	}

	var fetchResp FetchKeyResponse
	if err := json.Unmarshal(res.Body, &fetchResp); err != nil {
		return nil, internal.NewDecryptionError("failed to decode key server response", err)
	}
	keyMaterial, err := base64.StdEncoding.DecodeString(fetchResp.EphemeralKeyMaterial)
	if err != nil {
		return nil, internal.NewDecryptionError("failed to decode key material", err)
	}
	if err := bounds.Len("ephemeral_key_material", len(keyMaterial), bounds.MaxCapsuleFieldBytes); err != nil {
		return nil, internal.NewDecryptionError(err.Error(), err)
	}
	return keyMaterial, nil
}

func extractTransactionID(location string) string {
	prefix := "/key-capsules/"
	idx := strings.LastIndex(location, prefix)
	if idx == -1 {
		return ""
	}
	transactionID := location[idx+len(prefix):]
	if slashIdx := strings.Index(transactionID, "/"); slashIdx != -1 {
		transactionID = transactionID[:slashIdx]
	}
	if queryIdx := strings.Index(transactionID, "?"); queryIdx != -1 {
		transactionID = transactionID[:queryIdx]
	}
	return transactionID
}

// SendKey preserves the original API. Prefer SendKeyWithContext for cancellable requests.
func (c *Client) SendKey(config KeyServerConfig, recipientKey, keyMaterial []byte, capsuleType string, expiryTS uint64) (*CapsuleInfo, error) {
	return c.SendKeyWithContext(context.Background(), config, recipientKey, keyMaterial, capsuleType, expiryTS)
}

// FetchKey preserves the original API. Prefer FetchKeyWithContext for cancellable requests.
func (c *Client) FetchKey(config KeyServerConfig, transactionID string) ([]byte, error) {
	return c.FetchKeyWithContext(context.Background(), config, transactionID)
}
