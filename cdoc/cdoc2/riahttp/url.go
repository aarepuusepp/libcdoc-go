package riahttp

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

var (
	errNotHTTPS     = fmt.Errorf("URL must use HTTPS")
	errUserInfo     = fmt.Errorf("URL must not contain userinfo")
	errFragment     = fmt.Errorf("URL must not contain fragment")
	errPrivateHost  = fmt.Errorf("host is not allowed")
	errHostMismatch = fmt.Errorf("URL host does not match configured base")
)

// DevModePrivateHosts allows localhost/private hosts for unit tests only.
var DevModePrivateHosts bool

// ValidateBaseURL parses and validates an absolute HTTPS base URL.
func ValidateBaseURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("empty URL")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse URL: %w", err)
	}
	if u.Scheme != "https" {
		return nil, errNotHTTPS
	}
	if u.User != nil {
		return nil, errUserInfo
	}
	if u.Fragment != "" {
		return nil, errFragment
	}
	if u.Host == "" {
		return nil, fmt.Errorf("URL missing host")
	}
	if err := rejectPrivateHost(u.Hostname()); err != nil {
		return nil, err
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawQuery = ""
	u.Fragment = ""
	return u, nil
}

// BuildURL joins a validated base URL with path segments.
func BuildURL(base *url.URL, segments ...string) (string, error) {
	if base == nil {
		return "", fmt.Errorf("base URL is nil")
	}
	clone := *base
	path := clone.Path
	for _, seg := range segments {
		seg = strings.Trim(seg, "/")
		if seg == "" || strings.Contains(seg, "..") {
			return "", fmt.Errorf("invalid path segment")
		}
		path += "/" + seg
	}
	clone.Path = path
	return clone.String(), nil
}

// AssertSameHost ensures fullURL targets the same host:port as base.
func AssertSameHost(base *url.URL, fullURL string) error {
	u, err := url.Parse(fullURL)
	if err != nil {
		return fmt.Errorf("parse URL: %w", err)
	}
	if normalizeHost(base.Host) != normalizeHost(u.Host) {
		return errHostMismatch
	}
	if u.Scheme != "https" {
		return errNotHTTPS
	}
	return nil
}

// HostAllowlist validates that host:port is explicitly allowed.
type HostAllowlist map[string]struct{}

// Allow reports whether host:port is on the allowlist.
func (a HostAllowlist) Allow(hostPort string) bool {
	if len(a) == 0 {
		return true
	}
	_, ok := a[normalizeHost(hostPort)]
	return ok
}

// RegisterBase adds the host:port from a validated base URL to the allowlist.
func (a HostAllowlist) RegisterBase(base *url.URL) {
	if a == nil || base == nil {
		return
	}
	a[normalizeHost(base.Host)] = struct{}{}
}

func normalizeHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if h, _, err := net.SplitHostPort(host); err == nil {
		return strings.ToLower(h)
	}
	return host
}

func rejectPrivateHost(host string) error {
	if DevModePrivateHosts {
		return nil
	}
	host = strings.Trim(host, "[]")
	ip := net.ParseIP(host)
	if ip == nil {
		lower := strings.ToLower(host)
		if lower == "localhost" || strings.HasSuffix(lower, ".localhost") {
			return errPrivateHost
		}
		return nil
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate() || ip.IsUnspecified() {
		return errPrivateHost
	}
	return nil
}
