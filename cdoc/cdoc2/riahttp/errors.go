package riahttp

import (
	"errors"
	"fmt"
)

// RemoteError is a typed HTTP error from a RIA central service.
type RemoteError struct {
	Op         string
	StatusCode int
	Body       string
}

func (e *RemoteError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Body != "" {
		return fmt.Sprintf("%s: HTTP %d: %s", e.Op, e.StatusCode, e.Body)
	}
	return fmt.Sprintf("%s: HTTP %d", e.Op, e.StatusCode)
}

// IsRemoteError reports whether err is a *RemoteError with the given status code.
func IsRemoteError(err error, status int) bool {
	var re *RemoteError
	if !errors.As(err, &re) {
		return false
	}
	return re.StatusCode == status
}

// PrivacySafeError maps remote failures to a single user-safe message class.
// Callers must not expose status-specific detail for Key Capsule GET 404 cases.
func PrivacySafeError(op string, err error) error {
	if err == nil {
		return nil
	}
	var re *RemoteError
	if errors.As(err, &re) {
		switch re.StatusCode {
		case 404, 410:
			return fmt.Errorf("%s: key material unavailable", op)
		case 401, 403:
			return fmt.Errorf("%s: authentication failed", op)
		case 429:
			return fmt.Errorf("%s: service busy", op)
		default:
			return fmt.Errorf("%s: remote service error", op)
		}
	}
	return fmt.Errorf("%s: remote service error", op)
}
