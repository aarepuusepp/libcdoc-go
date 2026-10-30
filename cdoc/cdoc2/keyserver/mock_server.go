package keyserver

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"
)

// MockServer implements an in-memory key server for testing
type MockServer struct {
	server      *httptest.Server
	capsules    map[string]*KeyCapsule
	capsulesMux sync.RWMutex
}

// KeyCapsule represents a stored key capsule in the mock server
type KeyCapsule struct {
	RecipientID          string
	EphemeralKeyMaterial string
	CapsuleType          string
	StoredAt             time.Time
	ExpiryTime           *time.Time
}

// NewMockServer creates a new mock key server instance
func NewMockServer() *MockServer {
	mock := &MockServer{
		capsules: make(map[string]*KeyCapsule),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/key-capsules", mock.handlePostKeyCapsule)
	mux.HandleFunc("/key-capsules/", mock.handleGetKeyCapsule)

	mock.server = httptest.NewTLSServer(mux)

	return mock
}

// URL returns the base URL of the mock server
func (m *MockServer) URL() string {
	if m.server == nil {
		return ""
	}
	return m.server.URL
}

// Stop stops the mock server and cleans up resources
func (m *MockServer) Stop() {
	if m.server != nil {
		m.server.Close()
		m.server = nil
	}
	m.capsulesMux.Lock()
	defer m.capsulesMux.Unlock()
	m.capsules = make(map[string]*KeyCapsule)
}

// handlePostKeyCapsule handles POST /key-capsules requests
func (m *MockServer) handlePostKeyCapsule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req SendKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	// Generate transaction ID (16 bytes hex = 32 chars, within OpenAPI 18-34 when prefixed)
	txIDBytes := make([]byte, 16)
	if _, err := rand.Read(txIDBytes); err != nil {
		http.Error(w, fmt.Sprintf("Failed to generate transaction ID: %v", err), http.StatusInternalServerError)
		return
	}
	transactionID := "KC" + hex.EncodeToString(txIDBytes)

	// Parse expiry time from header if present
	var expiryTime *time.Time
	if expiryStr := r.Header.Get("x-expiry-time"); expiryStr != "" {
		if parsed, err := time.Parse(time.RFC3339, expiryStr); err == nil {
			expiryTime = &parsed
		}
	}

	// Store capsule
	capsule := &KeyCapsule{
		RecipientID:          req.RecipientID,
		EphemeralKeyMaterial: req.EphemeralKeyMaterial,
		CapsuleType:          req.CapsuleType,
		StoredAt:             time.Now(),
		ExpiryTime:           expiryTime,
	}

	m.capsulesMux.Lock()
	m.capsules[transactionID] = capsule
	m.capsulesMux.Unlock()

	// Return Location header with transaction ID
	location := fmt.Sprintf("%s/key-capsules/%s", m.URL(), transactionID)
	w.Header().Set("Location", location)
	if expiryTime != nil {
		w.Header().Set("x-expiry-time", expiryTime.UTC().Format(time.RFC3339))
	}
	w.WriteHeader(http.StatusCreated)
}

// handleGetKeyCapsule handles GET /key-capsules/{transaction_id} requests
func (m *MockServer) handleGetKeyCapsule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract transaction ID from path
	// Path will be "/key-capsules/{transaction_id}"
	path := r.URL.Path
	prefix := "/key-capsules/"
	if len(path) <= len(prefix) {
		http.Error(w, "Invalid transaction ID", http.StatusBadRequest)
		return
	}
	transactionID := path[len(prefix):]

	// Remove trailing slash if present
	if len(transactionID) > 0 && transactionID[len(transactionID)-1] == '/' {
		transactionID = transactionID[:len(transactionID)-1]
	}

	m.capsulesMux.RLock()
	capsule, exists := m.capsules[transactionID]
	m.capsulesMux.RUnlock()

	if !exists {
		http.Error(w, "Transaction not found", http.StatusNotFound)
		return
	}

	// Check expiry if set
	if capsule.ExpiryTime != nil && time.Now().After(*capsule.ExpiryTime) {
		http.Error(w, "Transaction expired", http.StatusGone)
		return
	}

	// Return key material
	response := FetchKeyResponse{
		EphemeralKeyMaterial: capsule.EphemeralKeyMaterial,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
		return
	}
}

// GetCapsule retrieves a stored capsule (for testing purposes)
func (m *MockServer) GetCapsule(transactionID string) (*KeyCapsule, bool) {
	m.capsulesMux.RLock()
	defer m.capsulesMux.RUnlock()
	capsule, exists := m.capsules[transactionID]
	return capsule, exists
}

// PutCapsule stores a capsule copy (for tests that use separate POST/GET mock bases).
func (m *MockServer) PutCapsule(transactionID string, capsule KeyCapsule) {
	m.capsulesMux.Lock()
	defer m.capsulesMux.Unlock()
	cp := capsule
	m.capsules[transactionID] = &cp
}

// DecodeKeyMaterial decodes base64-encoded key material from a capsule
func (c *KeyCapsule) DecodeKeyMaterial() ([]byte, error) {
	return base64.StdEncoding.DecodeString(c.EphemeralKeyMaterial)
}
