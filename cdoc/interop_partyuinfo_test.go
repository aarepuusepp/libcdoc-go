package cdoc

import (
	"bytes"
	"testing"

	"github.com/aarepuusepp/libcdoc-go/v2/xmlenc"
)

func TestEncryptCDOC11_EC_PartyUInfoStartsWithUncompressedPrefix(t *testing.T) {
	cert := loadTestCert(t, "ecc", "auth_cert.pem")

	builder := NewBuilder()
	builder.Version(Version11)
	builder.WithDataFile("interop_ec_partyuinfo.txt", bytes.NewReader([]byte("x")), 1)

	if err := builder.WithRecipientCertificate(cert); err != nil {
		t.Fatalf("Failed to add recipient: %v", err)
	}

	var output bytes.Buffer
	if err := builder.BuildToWriter(&output); err != nil {
		t.Fatalf("Failed to build CDOC: %v", err)
	}

	parser := NewParser()
	if err := parser.Parse(bytes.NewReader(output.Bytes())); err != nil {
		t.Fatalf("Failed to parse generated CDOC: %v", err)
	}

	recipients, err := parser.GetRecipients()
	if err != nil {
		t.Fatalf("Failed to get recipients: %v", err)
	}
	if len(recipients) != 1 {
		t.Fatalf("Expected 1 recipient, got %d", len(recipients))
	}

	ecRecipient, ok := recipients[0].(*xmlenc.ECRecipient)
	if !ok {
		t.Fatalf("Expected EC recipient, got %T", recipients[0])
	}

	partyUInfo := ecRecipient.GetPartyUInfo()
	if len(partyUInfo) == 0 {
		t.Fatal("PartyUInfo is empty")
	}
	if partyUInfo[0] != 0x04 {
		t.Fatalf("PartyUInfo must start with 0x04 (uncompressed point). Got 0x%02x", partyUInfo[0])
	}
}
