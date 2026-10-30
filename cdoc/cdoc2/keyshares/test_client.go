package keyshares

import (
	"github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2/riahttp"
)

// NewTestClient returns a client for the TLS mock server.
func NewTestClient(mock *MockServer) (*Client, error) {
	riahttp.DevModePrivateHosts = true
	base, err := riahttp.ValidateBaseURL(mock.URL())
	if err != nil {
		return nil, err
	}
	return NewClientWithHTTP(base, riahttp.NewClient(riahttp.Config{
		Transport:          mock.server.Client().Transport,
		InsecureSkipVerify: true,
	})), nil
}
