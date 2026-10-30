package key_test

import (
	"testing"

	"github.com/aarepuusepp/libcdoc-go/v2/key"
)

func TestPKCS11Signer_RequiresCGO(t *testing.T) {
	t.Parallel()
	_, _, err := key.NewPKCS11Signer(key.PKCS11Config{})
	if err == nil {
		t.Fatal("expected error without CGO/HSM")
	}
	_, err = key.TLSCertificateFromPKCS11(key.PKCS11Config{})
	if err == nil {
		t.Fatal("expected TLS certificate error without CGO/HSM")
	}
}
