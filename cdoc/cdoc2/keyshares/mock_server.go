package keyshares

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"
)

// MockServer is an in-memory key-shares server for testing.
type MockServer struct {
	server   *httptest.Server
	shares   map[string]*storedShare
	nonces   map[string]string
	sharesMu sync.RWMutex
}

type storedShare struct {
	Share     string
	Recipient string
}

// NewMockServer creates a mock key-shares server.
func NewMockServer() *MockServer {
	m := &MockServer{
		shares: make(map[string]*storedShare),
		nonces: make(map[string]string),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/key-shares", m.handlePostShare)
	mux.HandleFunc("/key-shares/", m.handleShareSubroutes)
	m.server = httptest.NewTLSServer(mux)
	return m
}

func (m *MockServer) URL() string {
	if m.server == nil {
		return ""
	}
	return m.server.URL
}

func (m *MockServer) Stop() {
	if m.server != nil {
		m.server.Close()
		m.server = nil
	}
}

func (m *MockServer) handlePostShare(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var ks KeyShare
	if err := json.NewDecoder(r.Body).Decode(&ks); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	idBytes := make([]byte, 16)
	_, _ = rand.Read(idBytes)
	shareID := "KS" + hex.EncodeToString(idBytes)[:30]
	m.sharesMu.Lock()
	m.shares[shareID] = &storedShare{Share: ks.Share, Recipient: ks.Recipient}
	m.sharesMu.Unlock()
	w.Header().Set("Location", fmt.Sprintf("%s/key-shares/%s", m.URL(), shareID))
	w.WriteHeader(http.StatusCreated)
}

func (m *MockServer) handleShareSubroutes(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	prefix := "/key-shares/"
	if len(path) <= len(prefix) {
		http.NotFound(w, r)
		return
	}
	rest := path[len(prefix):]
	if rest == "" {
		http.NotFound(w, r)
		return
	}
	parts := splitPath(rest)
	if len(parts) == 0 {
		http.NotFound(w, r)
		return
	}
	shareID := parts[0]
	if len(parts) == 2 && parts[1] == "nonce" && r.Method == http.MethodPost {
		m.handleCreateNonce(w, r, shareID)
		return
	}
	if len(parts) == 1 && r.Method == http.MethodGet {
		m.handleGetShare(w, r, shareID)
		return
	}
	http.Error(w, "not found", http.StatusNotFound)
}

func (m *MockServer) handleCreateNonce(w http.ResponseWriter, r *http.Request, shareID string) {
	if r.Header.Get("x-cdoc2-session-token") == "" {
		http.Error(w, "missing session token", http.StatusForbidden)
		return
	}
	m.sharesMu.RLock()
	_, ok := m.shares[shareID]
	m.sharesMu.RUnlock()
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	nonceBytes := make([]byte, 8)
	_, _ = rand.Read(nonceBytes)
	nonce := hex.EncodeToString(nonceBytes)
	m.sharesMu.Lock()
	m.nonces[shareID] = nonce
	m.sharesMu.Unlock()
	_ = json.NewEncoder(w).Encode(NonceResponse{Nonce: nonce})
}

func (m *MockServer) handleGetShare(w http.ResponseWriter, r *http.Request, shareID string) {
	if r.Header.Get("x-cdoc2-auth-token") == "" || r.Header.Get("x-cdoc2-session-token") == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	m.sharesMu.RLock()
	share, ok := m.shares[shareID]
	m.sharesMu.RUnlock()
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("x-expiry-time", time.Now().Add(24*time.Hour).UTC().Format(time.RFC3339))
	_ = json.NewEncoder(w).Encode(KeyShare{Share: share.Share, Recipient: share.Recipient})
}

func splitPath(p string) []string {
	var parts []string
	for _, s := range splitOnSlash(p) {
		if s != "" {
			parts = append(parts, s)
		}
	}
	return parts
}

func splitOnSlash(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '/' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}
