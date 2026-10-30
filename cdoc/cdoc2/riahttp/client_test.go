package riahttp_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2/riahttp"
)

func TestValidateBaseURL_RejectsHTTPAndPrivate(t *testing.T) {
	riahttp.DevModePrivateHosts = false
	defer func() { riahttp.DevModePrivateHosts = false }()

	cases := []struct {
		raw string
		ok  bool
	}{
		{"https://cdoc2.example.com:8443", true},
		{"http://cdoc2.example.com", false},
		{"https://user:pass@cdoc2.example.com", false},
		{"https://127.0.0.1:8443", false},
		{"https://localhost:8443", false},
	}
	for _, tc := range cases {
		_, err := riahttp.ValidateBaseURL(tc.raw)
		if tc.ok && err != nil {
			t.Fatalf("%q: unexpected error: %v", tc.raw, err)
		}
		if !tc.ok && err == nil {
			t.Fatalf("%q: expected error", tc.raw)
		}
	}
}

func TestClient_BoundedResponseAndContext(t *testing.T) {
	riahttp.DevModePrivateHosts = true
	defer func() { riahttp.DevModePrivateHosts = false }()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload := strings.Repeat("x", 1024)
		_, _ = io.Copy(w, strings.NewReader(payload))
	}))
	defer srv.Close()

	base, err := riahttp.ValidateBaseURL(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	allow := riahttp.HostAllowlist{}
	allow.RegisterBase(base)

	client := riahttp.NewClient(riahttp.Config{
		MaxResponseBytes:   1024,
		AllowHosts:         allow,
		Transport:          srv.Client().Transport,
		InsecureSkipVerify: true,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	res, err := client.Get(ctx, base, "key-capsules", "abc")
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", res.StatusCode)
	}
	if len(res.Body) != 1024 {
		t.Fatalf("body len=%d", len(res.Body))
	}
}

func TestClient_Remote429And503ReturnBoundedResult(t *testing.T) {
	riahttp.DevModePrivateHosts = true
	defer func() { riahttp.DevModePrivateHosts = false }()

	for _, status := range []int{http.StatusTooManyRequests, http.StatusServiceUnavailable} {
		status := status
		t.Run(http.StatusText(status), func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
				_, _ = w.Write([]byte(`{"secret":"must-not-leak"}`))
			}))
			t.Cleanup(srv.Close)

			base, err := riahttp.ValidateBaseURL(srv.URL)
			if err != nil {
				t.Fatal(err)
			}
			allow := riahttp.HostAllowlist{}
			allow.RegisterBase(base)
			client := riahttp.NewClient(riahttp.Config{
				AllowHosts:         allow,
				Transport:          srv.Client().Transport,
				InsecureSkipVerify: true,
			})
			res, err := client.Get(context.Background(), base, "probe")
			if err != nil {
				t.Fatal(err)
			}
			if res.StatusCode != status {
				t.Fatalf("status=%d", res.StatusCode)
			}
			safe := riahttp.PrivacySafeError("probe", &riahttp.RemoteError{
				Op: "probe", StatusCode: res.StatusCode, Body: string(res.Body),
			})
			if strings.Contains(safe.Error(), "must-not-leak") {
				t.Fatalf("privacy-safe error leaked body: %q", safe.Error())
			}
		})
	}
}

func TestClient_RejectsDisallowedHost(t *testing.T) {
	riahttp.DevModePrivateHosts = true
	defer func() { riahttp.DevModePrivateHosts = false }()

	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()

	base, err := riahttp.ValidateBaseURL(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	allow := riahttp.HostAllowlist{"other.example.com": {}}
	client := riahttp.NewClient(riahttp.Config{
		AllowHosts:         allow,
		Transport:          srv.Client().Transport,
		InsecureSkipVerify: true,
	})
	_, err = client.Get(context.Background(), base)
	if err == nil || !strings.Contains(err.Error(), "host not allowed") {
		t.Fatalf("expected host not allowed, got %v", err)
	}
}

func TestClientDoesNotFollowRedirects(t *testing.T) {
	var calls atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer target.Close()
	for _, status := range []int{http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, status) }))
		base, err := url.Parse(source.URL)
		if err != nil {
			t.Fatal(err)
		}
		allow := riahttp.HostAllowlist{}
		allow.RegisterBase(base)
		client := riahttp.NewClient(riahttp.Config{AllowHosts: allow, Transport: source.Client().Transport})
		req, err := http.NewRequest(http.MethodPost, source.URL, strings.NewReader("private body"))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer test-only")
		result, err := client.Do(context.Background(), req)
		source.Close()
		if err != nil || result.StatusCode != status {
			t.Fatalf("redirect response: %v %v", result, err)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("followed redirect outside configured endpoint")
	}
}
