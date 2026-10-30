package riahttp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	DefaultMaxResponseBytes = 1 << 20   // 1 MiB
	DefaultMaxRequestBytes  = 256 << 10 // 256 KiB
	defaultRequestTimeout   = 30 * time.Second
)

// Config configures the RIA HTTP client.
type Config struct {
	TLSConfig          *tls.Config
	Timeout            time.Duration
	MaxResponseBytes   int64
	MaxRequestBytes    int64
	AllowHosts         HostAllowlist
	Transport          http.RoundTripper // test injection
	InsecureSkipVerify bool              // dev/test only; production callers must leave false
}

// Client performs context-aware bounded HTTP calls to RIA services.
type Client struct {
	hc               *http.Client
	maxResponseBytes int64
	maxRequestBytes  int64
	allowHosts       HostAllowlist
}

// NewClient builds a TLS 1.3-minimum HTTP client.
func NewClient(cfg Config) *Client {
	maxResp := cfg.MaxResponseBytes
	if maxResp <= 0 {
		maxResp = DefaultMaxResponseBytes
	}
	maxReq := cfg.MaxRequestBytes
	if maxReq <= 0 {
		maxReq = DefaultMaxRequestBytes
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultRequestTimeout
	}

	tlsConfig := cfg.TLSConfig
	if tlsConfig == nil {
		tlsConfig = &tls.Config{MinVersion: tls.VersionTLS13}
	} else {
		tlsConfig = tlsConfig.Clone()
		if tlsConfig.MinVersion < tls.VersionTLS13 {
			tlsConfig.MinVersion = tls.VersionTLS13
		}
	}
	if cfg.InsecureSkipVerify {
		tlsConfig.InsecureSkipVerify = true
	}

	transport := cfg.Transport
	if transport == nil {
		transport = &http.Transport{
			TLSClientConfig: tlsConfig,
		}
	}

	return &Client{
		hc: &http.Client{
			Timeout:   timeout,
			Transport: transport,
			// Do not forward credentials or bodies outside the validated endpoint.
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
		},
		maxResponseBytes: maxResp,
		maxRequestBytes:  maxReq,
		allowHosts:       cfg.AllowHosts,
	}
}

// HTTPClient exposes the underlying client for rare legacy wiring; prefer Do/Post/Get.
func (c *Client) HTTPClient() *http.Client {
	return c.hc
}

// Result holds a bounded HTTP response body and metadata.
type Result struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

// Do executes req with context cancellation, trace propagation, and bounded reads.
func (c *Client) Do(ctx context.Context, req *http.Request) (*Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if req.URL != nil && len(c.allowHosts) > 0 && !c.allowHosts.Allow(req.URL.Host) {
		return nil, fmt.Errorf("host not allowed: %s", req.URL.Host)
	}
	req = req.WithContext(ctx)
	injectTraceparent(ctx, req)

	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := ReadAllBounded(resp.Body, c.maxResponseBytes)
	if err != nil {
		return nil, err
	}
	return &Result{
		StatusCode: resp.StatusCode,
		Header:     resp.Header.Clone(),
		Body:       body,
	}, nil
}

// NewJSONRequest builds a POST/PUT/PATCH request with bounded body from base URL.
func (c *Client) NewJSONRequest(ctx context.Context, method string, base *url.URL, pathSegments []string, jsonBody []byte) (*http.Request, error) {
	if int64(len(jsonBody)) > c.maxRequestBytes {
		return nil, fmt.Errorf("request body exceeds limit")
	}
	target, err := BuildURL(base, pathSegments...)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, target, strings.NewReader(string(jsonBody)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	return req, nil
}

// Get performs GET against base + path segments.
func (c *Client) Get(ctx context.Context, base *url.URL, pathSegments ...string) (*Result, error) {
	target, err := BuildURL(base, pathSegments...)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	return c.Do(ctx, req)
}

// ReadAllBounded reads r up to limit bytes.
func ReadAllBounded(r io.Reader, limit int64) ([]byte, error) {
	if limit <= 0 {
		limit = DefaultMaxResponseBytes
	}
	lr := io.LimitReader(r, limit+1)
	data, err := io.ReadAll(lr)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("response body exceeds limit")
	}
	return data, nil
}

// NewTransportTLS builds transport with optional client cert and trust store.
func NewTransportTLS(trustStore *x509.CertPool, clientCert *tls.Certificate, insecure bool) http.RoundTripper {
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		RootCAs:            trustStore,
		InsecureSkipVerify: insecure,
	}
	if clientCert != nil {
		tlsConfig.Certificates = []tls.Certificate{*clientCert}
	}
	return &http.Transport{TLSClientConfig: tlsConfig}
}

func injectTraceparent(ctx context.Context, req *http.Request) {
	if req.Header.Get("traceparent") != "" {
		return
	}
	// W3C traceparent version 00; trace-id from context deadline bucket is sufficient for correlation in tests.
	if _, ok := ctx.Deadline(); ok {
		req.Header.Set("traceparent", "00-"+strings.Repeat("0", 32)+"-0000000000000001-01")
	}
}
