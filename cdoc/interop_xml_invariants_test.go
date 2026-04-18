package cdoc

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"testing"

	"github.com/aarepuusepp/libcdoc-go/v2/xmlenc"
)

func TestEncryptCDOC11_EC_XMLInvariants_PublicKeyAndPartyUInfo(t *testing.T) {
	cert := loadTestCert(t, "ecc", "auth_cert.pem")

	builder := NewBuilder()
	builder.Version(Version11)
	builder.WithDataFile("interop_ec_xmlinv.txt", bytes.NewReader([]byte("x")), 1)

	if err := builder.WithRecipientCertificate(cert); err != nil {
		t.Fatalf("Failed to add recipient: %v", err)
	}

	var output bytes.Buffer
	if err := builder.BuildToWriter(&output); err != nil {
		t.Fatalf("Failed to build CDOC: %v", err)
	}

	var ed xmlenc.EncryptedData
	if err := xml.Unmarshal(output.Bytes(), &ed); err != nil {
		t.Fatalf("Failed to unmarshal generated CDOC XML: %v", err)
	}
	if len(ed.KeyInfo.EncryptedKeys) != 1 {
		t.Fatalf("Expected 1 EncryptedKey, got %d", len(ed.KeyInfo.EncryptedKeys))
	}

	am := ed.KeyInfo.EncryptedKeys[0].KeyInfo.AgreementMethod
	if am == nil || am.KeyDerivationMethod == nil || am.KeyDerivationMethod.ConcatKDFParams == nil {
		t.Fatal("Missing AgreementMethod / ConcatKDFParams")
	}
	if am.OriginatorKeyInfo == nil || am.OriginatorKeyInfo.KeyValue == nil || am.OriginatorKeyInfo.KeyValue.ECKeyValue == nil {
		t.Fatal("Missing OriginatorKeyInfo / ECKeyValue")
	}

	pubKeyB64 := am.OriginatorKeyInfo.KeyValue.ECKeyValue.PublicKey
	pubKeyBytes, err := base64.StdEncoding.DecodeString(pubKeyB64)
	if err != nil {
		t.Fatalf("Failed to decode PublicKey base64: %v", err)
	}
	if len(pubKeyBytes) != 97 {
		t.Fatalf("PublicKey decoded length must be 97 bytes for P-384 uncompressed point, got %d", len(pubKeyBytes))
	}
	if pubKeyBytes[0] != 0x04 {
		t.Fatalf("PublicKey must start with 0x04, got 0x%02x", pubKeyBytes[0])
	}

	partyUHex := am.KeyDerivationMethod.ConcatKDFParams.PartyUInfo
	partyUBytes, err := hex.DecodeString(partyUHex)
	if err != nil {
		t.Fatalf("Failed to decode PartyUInfo hex: %v", err)
	}
	if len(partyUBytes) != 98 {
		t.Fatalf("PartyUInfo decoded length must be 98 bytes (00 + 97-byte point), got %d", len(partyUBytes))
	}
	if partyUBytes[0] != 0x00 || partyUBytes[1] != 0x04 {
		t.Fatalf("PartyUInfo must start with 00 04, got %02x %02x", partyUBytes[0], partyUBytes[1])
	}
	if !bytes.Equal(partyUBytes[1:], pubKeyBytes) {
		t.Fatal("PartyUInfo[1:] must equal decoded PublicKey bytes")
	}
}
