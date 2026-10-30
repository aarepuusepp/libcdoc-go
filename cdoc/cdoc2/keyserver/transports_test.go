package keyserver_test

import (
	"crypto/tls"
	"testing"

	"github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2/keyserver"
	"github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2/riahttp"
)

func TestNewClientWithTransports_SeparatePostAndFetch(t *testing.T) {
	post := riahttp.NewClient(riahttp.Config{})
	fetch := riahttp.NewClient(riahttp.Config{
		Transport: riahttp.NewTransportTLS(nil, &tls.Certificate{}, false),
	})
	c := keyserver.NewClientWithTransports(post, fetch)
	if c == nil {
		t.Fatal("expected client")
	}
	pub := keyserver.NewClientWithTransports(post, post)
	if c == pub {
		t.Fatal("expected distinct client instances")
	}
}
