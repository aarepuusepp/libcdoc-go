package authserver

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
)

// MockServer is an in-memory auth-server for testing.
type MockServer struct {
	server    *httptest.Server
	processes map[string]*mockAuthProcess
	mu        sync.RWMutex
}

type mockAuthProcess struct {
	identity         AuthIdentity
	complete         bool
	sessionToken     string
	signingCert      string
	verificationCode string
}

// NewMockServer creates a mock auth-server that auto-completes on first status poll.
func NewMockServer() *MockServer {
	m := &MockServer{processes: make(map[string]*mockAuthProcess)}
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/start", m.handleStart)
	mux.HandleFunc("/auth/status/", m.handleStatus)
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
	}
}

func (m *MockServer) handleStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var id AuthIdentity
	if err := json.NewDecoder(r.Body).Decode(&id); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	uuidBytes := make([]byte, 16)
	_, _ = rand.Read(uuidBytes)
	uuid := hex.EncodeToString(uuidBytes)
	m.mu.Lock()
	m.processes[uuid] = &mockAuthProcess{
		identity:         id,
		sessionToken:     "mock-session-token-" + uuid,
		signingCert:      "mock-signing-cert-" + uuid,
		verificationCode: "1234",
	}
	m.mu.Unlock()
	w.Header().Set("Location", fmt.Sprintf("%s/auth/status/%s", m.URL(), uuid))
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(StartAuthResponseBody{VC: "1234"})
}

func (m *MockServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	uuid := r.URL.Path[len("/auth/status/"):]
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.processes[uuid]
	if !ok {
		http.NotFound(w, r)
		return
	}
	p.complete = true
	st := p.sessionToken
	sc := p.signingCert
	_ = json.NewEncoder(w).Encode(AuthProcessStatus{
		Status:             "COMPLETE",
		SessionToken:       &st,
		SigningCertificate: &sc,
	})
}
