package cdoc2

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"testing"
)

func TestWriterRecipientLabels(t *testing.T) {
	for _, tt := range []struct {
		name      string
		recipient Recipient
		want      string
	}{
		{"certificate", Recipient{Certificate: &x509.Certificate{Subject: pkix.Name{CommonName: "TEST,Ülle & Co"}}}, "TEST,Ülle & Co"},
		{"serial fallback", Recipient{Certificate: &x509.Certificate{Subject: pkix.Name{SerialNumber: "PNOEE-test"}}}, "PNOEE-test"},
		{"anonymous certificate", Recipient{Certificate: &x509.Certificate{}}, "Certificate recipient"},
		{"explicit label", Recipient{Label: "data:,v=1&label=Custom", Password: "secret"}, "data:,v=1&label=Custom"},
		{"blank label", Recipient{Label: " \t", Password: "secret"}, "Password recipient"},
		{"password", Recipient{Password: "secret"}, "Password recipient"},
		{"symmetric", Recipient{SymmetricKey: []byte("secret key material")}, "Symmetric key recipient"},
		{"auth means", Recipient{AuthMeansID: "etsi/PNOEE-test"}, "etsi/PNOEE-test"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			writer := NewWriter(io.Discard)
			if err := writer.AddRecipient(tt.recipient); err != nil {
				t.Fatal(err)
			}
			if got := writer.recipients[0].Label; got != tt.want {
				t.Fatalf("label = %q, want %q", got, tt.want)
			}
		})
	}
}
