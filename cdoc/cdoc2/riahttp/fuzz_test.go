package riahttp

import (
	"strings"
	"testing"
)

func FuzzValidateBaseURL(f *testing.F) {
	f.Add("https://cdoc2.example.com:8443")
	f.Add("http://127.0.0.1")
	f.Add("")
	f.Add("://bad")
	f.Fuzz(func(t *testing.T, raw string) {
		DevModePrivateHosts = false
		t.Cleanup(func() { DevModePrivateHosts = false })

		u, err := ValidateBaseURL(raw)
		if err != nil {
			return
		}
		if u.Scheme != "https" {
			t.Fatalf("accepted non-https %q", raw)
		}
		if strings.Contains(u.Host, "127.0.0.1") || strings.HasPrefix(strings.ToLower(u.Host), "localhost") {
			t.Fatalf("accepted private host %q", raw)
		}
	})
}
