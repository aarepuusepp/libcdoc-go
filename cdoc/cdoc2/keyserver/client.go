package keyserver

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aarepuusepp/libcdoc-go/v2/internal"
)

// Client handles communication with CDOC2 key servers
type Client struct {
	httpClient *http.Client
}

// KeyServerConfig holds configuration for a key server
type KeyServerConfig struct {
	ServerID   string            // UUID of the key server
	PostURL    string            // POST URL for sending key material (e.g., https://cdoc2.id.ee:8443)
	FetchURL   string            // GET URL for fetching key material (e.g., https://cdoc2.id.ee:8444)
	TLSCert    *x509.Certificate // Optional TLS certificate for server verification
	ClientCert *tls.Certificate  // Optional client TLS certificate for authentication
}

// CapsuleInfo contains information returned from sending key material to server
type CapsuleInfo struct {
	TransactionID string    // Transaction ID from Location header
	ExpiryTime    time.Time // Expiry time from x-expiry-time header
}

// SendKeyRequest is the JSON request body for sending key material
type SendKeyRequest struct {
	RecipientID          string `json:"recipient_id"`
	EphemeralKeyMaterial string `json:"ephemeral_key_material"`
	CapsuleType          string `json:"capsule_type"`
}

// SendKeyResponse represents the response from sending key material
type SendKeyResponse struct {
	Location   string    // Location header with transaction ID
	ExpiryTime time.Time // Expiry time from x-expiry-time header
}

// FetchKeyResponse represents the response from fetching key material
type FetchKeyResponse struct {
	EphemeralKeyMaterial string `json:"ephemeral_key_material"`
}

// NewClient creates a new key server client
func NewClient() *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// NewClientWithTLS creates a new key server client with custom TLS configuration
func NewClientWithTLS(serverCert *x509.Certificate, clientCert *tls.Certificate) *Client {
	client := NewClient()

	// Create TLS config
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	// Add server certificate to trust pool if provided
	if serverCert != nil {
		pool := x509.NewCertPool()
		pool.AddCert(serverCert)
		tlsConfig.RootCAs = pool
	}

	// Add client certificate if provided
	if clientCert != nil {
		tlsConfig.Certificates = []tls.Certificate{*clientCert}
	}

	// Update HTTP client transport
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	client.httpClient.Transport = transport

	return client
}

// SendKey sends key material to the key server and returns transaction information
func (c *Client) SendKey(config KeyServerConfig, recipientKey []byte, keyMaterial []byte, capsuleType string, expiryTS uint64) (*CapsuleInfo, error) {
	// Build request body
	reqBody := SendKeyRequest{
		RecipientID:          base64.StdEncoding.EncodeToString(recipientKey),
		EphemeralKeyMaterial: base64.StdEncoding.EncodeToString(keyMaterial),
		CapsuleType:          capsuleType,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, internal.NewEncryptionError("failed to marshal send key request", err)
	}

	// Build URL: add /key-capsules to the base URL
	url := config.PostURL
	if url[len(url)-1] != '/' {
		url += "/"
	}
	url += "key-capsules"

	// Create HTTP request
	req, err := http.NewRequest("POST", url, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, internal.NewEncryptionError("failed to create HTTP request", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Add expiry time header if provided
	if expiryTS > 0 {
		req.Header.Set("x-expiry-time", time.Unix(int64(expiryTS), 0).UTC().Format(time.RFC3339))
	}

	// Send request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, internal.NewEncryptionError("failed to send key to server", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Check status code
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, internal.NewEncryptionError(
			fmt.Sprintf("key server returned status %d: %s", resp.StatusCode, string(bodyBytes)),
			nil,
		)
	}

	// Extract transaction ID from Location header
	location := resp.Header.Get("Location")
	if location == "" {
		return nil, internal.NewEncryptionError("no Location header in key server response", nil)
	}

	// Extract transaction ID: location is like "/key-capsules/TRANSACTION_ID"
	// or "https://server/key-capsules/TRANSACTION_ID"
	transactionID := extractTransactionID(location)
	if transactionID == "" {
		return nil, internal.NewEncryptionError(fmt.Sprintf("failed to extract transaction ID from Location: %s", location), nil)
	}

	// Extract expiry time from x-expiry-time header
	var expiryTime time.Time
	if expiryStr := resp.Header.Get("x-expiry-time"); expiryStr != "" {
		if parsedExpiry, err := time.Parse(time.RFC3339, expiryStr); err == nil {
			expiryTime = parsedExpiry
		}
	}

	return &CapsuleInfo{
		TransactionID: transactionID,
		ExpiryTime:    expiryTime,
	}, nil
}

// FetchKey fetches key material from the key server using transaction ID
func (c *Client) FetchKey(config KeyServerConfig, transactionID string) ([]byte, error) {
	// Build URL: add /key-capsules/{transaction_id} to the base URL
	url := config.FetchURL
	if url[len(url)-1] != '/' {
		url += "/"
	}
	url += "key-capsules/" + transactionID

	// Create HTTP request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, internal.NewDecryptionError("failed to create HTTP request", err)
	}

	// Send request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, internal.NewDecryptionError("failed to fetch key from server", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Check status code
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, internal.NewDecryptionError(
			fmt.Sprintf("key server returned status %d: %s", resp.StatusCode, string(bodyBytes)),
			nil,
		)
	}

	// Parse JSON response
	var fetchResp FetchKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&fetchResp); err != nil {
		return nil, internal.NewDecryptionError("failed to decode key server response", err)
	}

	// Decode base64 key material
	keyMaterial, err := base64.StdEncoding.DecodeString(fetchResp.EphemeralKeyMaterial)
	if err != nil {
		return nil, internal.NewDecryptionError("failed to decode key material", err)
	}

	return keyMaterial, nil
}

// extractTransactionID extracts the transaction ID from a Location header
// Location can be:
// - "/key-capsules/TRANSACTION_ID"
// - "https://server/key-capsules/TRANSACTION_ID"
// - "https://server:8443/key-capsules/TRANSACTION_ID"
func extractTransactionID(location string) string {
	// Find the last occurrence of "/key-capsules/"
	prefix := "/key-capsules/"
	idx := strings.LastIndex(location, prefix)
	if idx == -1 {
		return ""
	}

	// Extract everything after "/key-capsules/"
	transactionID := location[idx+len(prefix):]

	// Remove any trailing path components or query parameters
	if slashIdx := strings.Index(transactionID, "/"); slashIdx != -1 {
		transactionID = transactionID[:slashIdx]
	}
	if queryIdx := strings.Index(transactionID, "?"); queryIdx != -1 {
		transactionID = transactionID[:queryIdx]
	}

	return transactionID
}
