package rpserver

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
)

// MockServer is an in-memory RP-server for testing.
type MockServer struct {
	server   *httptest.Server
	sessions map[string]*mockSession
	mu       sync.RWMutex
}

type mockSession struct {
	kind      string
	signature *AcspV2Signature
	midSig    *MidSignature
	certB64   string
}

// NewMockServer creates a TLS mock RP-server that completes sessions on first poll.
func NewMockServer() *MockServer {
	m := &MockServer{sessions: make(map[string]*mockSession)}
	mux := http.NewServeMux()
	mux.HandleFunc("/sid/authenticate", m.handleSidAuth)
	mux.HandleFunc("/sid/session/", m.handleSidSession)
	mux.HandleFunc("/mid/authenticate", m.handleMidAuth)
	mux.HandleFunc("/mid/session/", m.handleMidSession)
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

func (m *MockServer) handleSidAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get("x-cdoc2-session-token") == "" {
		http.Error(w, "missing session token", http.StatusForbidden)
		return
	}
	var req SidAuthenticateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.SemanticsIdentifier == "" || req.SignatureProtocol != "ACSP_V2" || req.Interactions == "" || req.VcType == "" {
		http.Error(w, "invalid sid authenticate request", http.StatusBadRequest)
		return
	}
	if req.SignatureProtocolParameters.RpChallenge == "" || req.SignatureProtocolParameters.SignatureAlgorithm == "" {
		http.Error(w, "missing signature protocol parameters", http.StatusBadRequest)
		return
	}
	m.writeSessionID(w, "sid")
}

func (m *MockServer) handleMidAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get("x-cdoc2-session-token") == "" {
		http.Error(w, "missing session token", http.StatusForbidden)
		return
	}
	var req MidAuthenticateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if _, err := NewMidAuthenticateRequest(req.PhoneNumber, req.NationalIdentityNumber, req.Hash, req.Language, req.DisplayText); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.HashType == "" || req.DisplayTextFormat == "" {
		http.Error(w, "invalid mid authenticate request", http.StatusBadRequest)
		return
	}
	m.writeSessionID(w, "mid")
}

func (m *MockServer) writeSessionID(w http.ResponseWriter, kind string) {
	idBytes := make([]byte, 16)
	_, _ = rand.Read(idBytes)
	id := hex.EncodeToString(idBytes)
	sigValue := base64.StdEncoding.EncodeToString([]byte("mock-signature-" + id))
	cert := base64.StdEncoding.EncodeToString([]byte("mock-auth-cert-" + id))
	m.mu.Lock()
	m.sessions[id] = &mockSession{
		kind: kind,
		signature: &AcspV2Signature{
			Value:              sigValue,
			ServerRandom:       base64.StdEncoding.EncodeToString([]byte("mock-server-random")),
			UserChallenge:      strings.Repeat("A", 43),
			FlowType:           "Notification",
			SignatureAlgorithm: "rsassa-pss",
		},
		midSig: &MidSignature{
			Value:     sigValue,
			Algorithm: "SHA256WithECEncryption",
		},
		certB64: cert,
	}
	m.mu.Unlock()
	_ = json.NewEncoder(w).Encode(SessionIDResponse{SessionID: id})
}

func (m *MockServer) handleSidSession(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/sid/session/")
	m.writeSidSession(w, id)
}

func (m *MockServer) handleMidSession(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/mid/session/")
	m.writeMidSession(w, id)
}

func (m *MockServer) writeSidSession(w http.ResponseWriter, id string) {
	m.mu.RLock()
	s, ok := m.sessions[id]
	m.mu.RUnlock()
	if !ok || s.kind != "sid" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	_ = json.NewEncoder(w).Encode(SidSessionStatus{
		State:               StateComplete,
		SignatureProtocol:   "ACSP_V2",
		Result:              &SidSessionResult{EndResult: SidEndResultOK, DocumentNumber: "PNOEE-30001010004-BVFM-Q"},
		Signature:           s.signature,
		Cert:                &SidCertificate{Value: s.certB64, CertificateLevel: "QUALIFIED"},
		InteractionTypeUsed: "displayTextAndPIN",
	})
}

func (m *MockServer) writeMidSession(w http.ResponseWriter, id string) {
	m.mu.RLock()
	s, ok := m.sessions[id]
	m.mu.RUnlock()
	if !ok || s.kind != "mid" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("x-rp-signed-hash", base64.StdEncoding.EncodeToString([]byte("mock-rp-signed-hash")))
	w.Header().Set("x-rp-name", "cdoc2-RP.example.ee")
	w.Header().Set("Signature-Input", `sig1=("x-rp-signed-hash" "x-rp-name");created=1715269200;keyid="mock-key"`)
	w.Header().Set("Signature", "sig1=:"+base64.StdEncoding.EncodeToString([]byte("mock-rfc9421-sig"))+":")
	_ = json.NewEncoder(w).Encode(MidSessionStatus{
		State:     StateComplete,
		Result:    MidResultOK,
		Signature: s.midSig,
		Cert:      s.certB64,
		Time:      "2026-05-12T10:52:20Z",
		TraceID:   fmt.Sprintf("trace-%s", id),
	})
}

// MockSignatureBase64 returns a mock signature for tests.
func MockSignatureBase64() string {
	sig := make([]byte, 32)
	_, _ = rand.Read(sig)
	return base64.StdEncoding.EncodeToString(sig)
}
