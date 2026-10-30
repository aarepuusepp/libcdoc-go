package keyserver

import (
	"github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2/riahttp"
)

// NewTestClient returns a client configured for the mock TLS server URL.
func NewTestClient(mock *MockServer) *Client {
	return NewClientWithHTTP(riahttp.NewClient(riahttp.Config{
		Transport:          mock.server.Client().Transport,
		InsecureSkipVerify: true,
	}))
}
