package cdoc

import (
	"crypto/elliptic"
	"encoding/pem"
	"testing"

	libcrypto "github.com/aarepuusepp/libcdoc-go/v2/crypto"
)

// Embedding the original interface hides the optional digest method, modelling
// a third-party token built against v2.0.4.
type legacyToken struct{ Token }

func TestClientUnwrapLegacyTokenCompatibility(t *testing.T) {
	priv, cert := createTestECCertWithKey(t)
	data := buildCDOCBytesOnly(t, Version11, cert, TestDataFile{Name: "legacy.txt", Content: []byte("legacy"), Size: 6})
	challenge, err := PrepareClientUnwrap(data, cert)
	if err != nil {
		t.Fatal(err)
	}
	token := legacyToken{softwareTokenFromKeys(t, priv, cert)}
	cek, err := UnwrapTransportKeyWithToken(token, *challenge)
	if err != nil {
		t.Fatal(err)
	}
	files, err := FinishClientDecrypt(data, cert, cek)
	if err != nil || len(files) != 1 || string(files[0].Content) != "legacy" {
		t.Fatalf("legacy round trip failed: %v", err)
	}
	challenge.DigestAlgorithm = libcrypto.DigestSHA256URI
	if _, err := UnwrapTransportKeyWithToken(token, *challenge); err == nil {
		t.Fatal("legacy token must reject unsupported digest")
	}
}

func TestClientUnwrapRejectsMalformedInputs(t *testing.T) {
	priv, cert := createTestRSACertWithKey(t)
	token := softwareTokenFromKeys(t, priv, cert)
	for _, version := range []string{"", "3.0", "1.2"} {
		if _, err := UnwrapTransportKeyWithToken(token, ClientUnwrapChallenge{CdocVersion: version, RecipientType: "RSA", EncryptedKeyB64: "AQ=="}); err == nil {
			t.Fatalf("accepted version %q", version)
		}
	}
	if _, err := UnwrapTransportKeyWithToken(nil, ClientUnwrapChallenge{CdocVersion: "1.1"}); err == nil {
		t.Fatal("accepted nil token")
	}
	for _, input := range []string{"", "%%%"} {
		if _, err := decodeChallengeB64(input, "key"); err == nil {
			t.Fatal("accepted malformed base64")
		}
	}
	if _, err := DecodeEphemeralPublicKey(nil, []byte{4}); err == nil {
		t.Fatal("accepted nil curve")
	}
	if _, err := DecodeEphemeralPublicKey(elliptic.P384(), []byte{4}); err == nil {
		t.Fatal("accepted invalid point")
	}
	challenge := ClientUnwrapChallenge{CdocVersion: "1.1", RecipientType: "EC", RecipientCertPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))}
	if _, err := UnwrapTransportKeyWithToken(token, challenge); err == nil {
		t.Fatal("accepted RSA certificate for EC")
	}
}

func TestClientDecryptRejectsWrongKeyAndTamperedPayload(t *testing.T) {
	priv, cert := createTestECCertWithKey(t)
	data := buildCDOC2BytesOnly(t, cert, TestDataFile{Name: "x.txt", Content: []byte("secret"), Size: 6})
	challenge, err := PrepareClientUnwrap(data, cert)
	if err != nil {
		t.Fatal(err)
	}
	kek, err := UnwrapTransportKeyWithToken(softwareTokenFromKeys(t, priv, cert), *challenge)
	if err != nil {
		t.Fatal(err)
	}
	if files, err := FinishClientDecrypt(data, cert, make([]byte, 32)); err == nil || len(files) > 0 {
		t.Fatal("returned content for wrong key")
	}
	data[len(data)-1] ^= 1
	if files, err := FinishClientDecrypt(data, cert, kek); err == nil || len(files) > 0 {
		t.Fatal("returned unauthenticated content")
	}
}

var _ Token = legacyToken{}
var _ DigestToken = (*PKCS12Token)(nil)
var _ DigestToken = (*PKCS11Token)(nil)
