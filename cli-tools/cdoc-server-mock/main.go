package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"crypto/rand"
)

// KeyCapsule represents a stored key capsule in the mock server
type KeyCapsule struct {
	RecipientID          string
	EphemeralKeyMaterial string
	CapsuleType          string
	StoredAt             time.Time
	ExpiryTime           *time.Time
}

// SendKeyRequest is the JSON request body for sending key material
type SendKeyRequest struct {
	RecipientID          string `json:"recipient_id"`
	EphemeralKeyMaterial string `json:"ephemeral_key_material"`
	CapsuleType          string `json:"capsule_type"`
}

// FetchKeyResponse represents the response from fetching key material
type FetchKeyResponse struct {
	EphemeralKeyMaterial string `json:"ephemeral_key_material"`
}

// MockServer implements an in-memory key server for testing
type MockServer struct {
	capsules    map[string]*KeyCapsule
	capsulesMux sync.RWMutex
	port        string
}

// NewMockServer creates a new mock key server instance
func NewMockServer(port string) *MockServer {
	return &MockServer{
		capsules: make(map[string]*KeyCapsule),
		port:     port,
	}
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

	// Generate transaction ID (32 bytes hex-encoded = 64 chars)
	txIDBytes := make([]byte, 32)
	if _, err := rand.Read(txIDBytes); err != nil {
		http.Error(w, fmt.Sprintf("Failed to generate transaction ID: %v", err), http.StatusInternalServerError)
		return
	}
	transactionID := hex.EncodeToString(txIDBytes)

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

	log.Printf("Stored key capsule: transaction_id=%s, type=%s, expiry=%v", transactionID, req.CapsuleType, expiryTime)

	// Return Location header with transaction ID
	location := fmt.Sprintf("http://localhost:%s/key-capsules/%s", m.port, transactionID)
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

	log.Printf("Retrieved key capsule: transaction_id=%s, type=%s", transactionID, capsule.CapsuleType)

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

// DecodeKeyMaterial decodes base64-encoded key material from a capsule
func (c *KeyCapsule) DecodeKeyMaterial() ([]byte, error) {
	return base64.StdEncoding.DecodeString(c.EphemeralKeyMaterial)
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	server := NewMockServer(port)

	mux := http.NewServeMux()
	mux.HandleFunc("/key-capsules", server.handlePostKeyCapsule)
	mux.HandleFunc("/key-capsules/", server.handleGetKeyCapsule)

	addr := ":" + port
	log.Printf("Starting CDOC2 Key Server Mock on %s", addr)
	log.Printf("Endpoints:")
	log.Printf("  POST http://localhost:%s/key-capsules", port)
	log.Printf("  GET  http://localhost:%s/key-capsules/{transaction_id}", port)
	log.Printf("\nPress Ctrl+C to stop\n")

	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
