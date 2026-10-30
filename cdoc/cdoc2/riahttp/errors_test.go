package riahttp_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2/riahttp"
)

func TestPrivacySafeError_MapsStatusWithoutLeakingBody(t *testing.T) {
	t.Parallel()

	secretBody := "share=01234567890123456789012345678901&token=super-secret"
	cases := []struct {
		status int
		want   string
	}{
		{404, "key material unavailable"},
		{410, "key material unavailable"},
		{401, "authentication failed"},
		{403, "authentication failed"},
		{429, "service busy"},
		{503, "remote service error"},
	}
	for _, tc := range cases {
		raw := &riahttp.RemoteError{Op: "key-capsule GET", StatusCode: tc.status, Body: secretBody}
		got := riahttp.PrivacySafeError("key-capsule GET", raw)
		if got == nil {
			t.Fatalf("status %d: expected error", tc.status)
		}
		msg := got.Error()
		if !strings.Contains(msg, tc.want) {
			t.Fatalf("status %d: got %q want substring %q", tc.status, msg, tc.want)
		}
		if strings.Contains(msg, secretBody) || strings.Contains(msg, "super-secret") {
			t.Fatalf("status %d: leaked response body in %q", tc.status, msg)
		}
	}
}

func TestIsRemoteError(t *testing.T) {
	t.Parallel()
	err := riahttp.PrivacySafeError("op", &riahttp.RemoteError{Op: "op", StatusCode: 429})
	if riahttp.IsRemoteError(err, 429) {
		t.Fatal("PrivacySafeError wraps away RemoteError type")
	}
	raw := &riahttp.RemoteError{Op: "op", StatusCode: 503}
	if !riahttp.IsRemoteError(raw, 503) {
		t.Fatal("expected IsRemoteError match")
	}
	if riahttp.IsRemoteError(errors.New("other"), 503) {
		t.Fatal("unexpected match")
	}
}
