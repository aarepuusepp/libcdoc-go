package cdoc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/aarepuusepp/libcdoc-go/v2/key"
)

func buildCDOCBytesOnly(t *testing.T, version Version, cert *x509.Certificate, dataFiles ...TestDataFile) []byte {
	t.Helper()
	builder := NewBuilder()
	builder.Version(version)
	for _, df := range dataFiles {
		builder.WithDataFile(df.Name, bytes.NewReader(df.Content), df.Size)
	}
	if err := builder.WithRecipientCertificate(cert); err != nil {
		t.Fatalf("WithRecipientCertificate: %v", err)
	}
	var out bytes.Buffer
	if err := builder.BuildToWriter(&out); err != nil {
		t.Fatalf("BuildToWriter: %v", err)
	}
	return out.Bytes()
}

func softwareTokenFromKeys(t *testing.T, privKey interface{}, cert *x509.Certificate) Token {
	t.Helper()
	var pk *key.PrivateKey
	switch k := privKey.(type) {
	case *rsa.PrivateKey:
		pk = &key.PrivateKey{Key: k}
	case *ecdsa.PrivateKey:
		pk = &key.PrivateKey{Key: k}
	default:
		t.Fatalf("unsupported key type %T", privKey)
	}
	return NewPKCS12Token(&key.PKCS12KeyEntry{PrivateKey: pk, Certificate: cert})
}

func TestClientDecrypt_PrepareFinish_RSA_CDOC11(t *testing.T) {
	privKey, cert := createTestRSACertWithKey(t)
	dataFile := TestDataFile{Name: "test.txt", Content: []byte("client decrypt round trip"), Size: 24}
	cdocBytes := buildCDOCBytesOnly(t, Version11, cert, dataFile)

	challenge, err := PrepareClientUnwrap(cdocBytes, cert)
	if err != nil {
		t.Fatalf("PrepareClientUnwrap: %v", err)
	}
	if challenge.RecipientType != "RSA" {
		t.Fatalf("RecipientType = %q, want RSA", challenge.RecipientType)
	}
	if challenge.CdocVersion != "1.1" {
		t.Fatalf("CdocVersion = %q, want 1.1", challenge.CdocVersion)
	}

	token := softwareTokenFromKeys(t, privKey, cert)
	cek, err := UnwrapTransportKeyWithToken(token, *challenge)
	if err != nil {
		t.Fatalf("UnwrapTransportKeyWithToken: %v", err)
	}

	files, err := FinishClientDecrypt(cdocBytes, cert, cek)
	if err != nil {
		t.Fatalf("FinishClientDecrypt: %v", err)
	}
	if len(files) != 1 || string(files[0].Content) != string(dataFile.Content) {
		t.Fatalf("unexpected decrypted files: %+v", files)
	}
}

func TestClientDecrypt_PrepareFinish_EC_CDOC11(t *testing.T) {
	privKey, cert := createTestECCertWithKey(t)
	dataFile := TestDataFile{Name: "ec.txt", Content: []byte("ec client decrypt"), Size: 17}
	cdocBytes := buildCDOCBytesOnly(t, Version11, cert, dataFile)

	challenge, err := PrepareClientUnwrap(cdocBytes, cert)
	if err != nil {
		t.Fatalf("PrepareClientUnwrap: %v", err)
	}
	if challenge.RecipientType != "EC" {
		t.Fatalf("RecipientType = %q, want EC", challenge.RecipientType)
	}

	token := softwareTokenFromKeys(t, privKey, cert)
	cek, err := UnwrapTransportKeyWithToken(token, *challenge)
	if err != nil {
		t.Fatalf("UnwrapTransportKeyWithToken: %v", err)
	}

	files, err := FinishClientDecrypt(cdocBytes, cert, cek)
	if err != nil {
		t.Fatalf("FinishClientDecrypt: %v", err)
	}
	if len(files) != 1 || string(files[0].Content) != string(dataFile.Content) {
		t.Fatalf("unexpected decrypted files: %+v", files)
	}
}

func TestClientDecrypt_PrepareFinish_RSA_CDOC10(t *testing.T) {
	privKey, cert := createTestRSACertWithKey(t)
	dataFile := TestDataFile{Name: "v10.txt", Content: []byte("cdoc 1.0 client"), Size: 15}
	cdocBytes := buildCDOCBytesOnly(t, Version10, cert, dataFile)

	challenge, err := PrepareClientUnwrap(cdocBytes, cert)
	if err != nil {
		t.Fatalf("PrepareClientUnwrap: %v", err)
	}
	if challenge.CdocVersion != "1.0" {
		t.Fatalf("CdocVersion = %q, want 1.0", challenge.CdocVersion)
	}

	token := softwareTokenFromKeys(t, privKey, cert)
	cek, err := UnwrapTransportKeyWithToken(token, *challenge)
	if err != nil {
		t.Fatalf("UnwrapTransportKeyWithToken: %v", err)
	}

	files, err := FinishClientDecrypt(cdocBytes, cert, cek)
	if err != nil {
		t.Fatalf("FinishClientDecrypt: %v", err)
	}
	if len(files) != 1 || string(files[0].Content) != string(dataFile.Content) {
		t.Fatalf("unexpected decrypted files: %+v", files)
	}
}

func buildCDOC2BytesOnly(t *testing.T, cert *x509.Certificate, dataFiles ...TestDataFile) []byte {
	t.Helper()
	builder := NewBuilder().Version(Version20)
	for _, df := range dataFiles {
		builder.WithDataFile(df.Name, bytes.NewReader(df.Content), df.Size)
	}
	if err := builder.WithRecipientCertificate(cert); err != nil {
		t.Fatalf("WithRecipientCertificate: %v", err)
	}
	var out bytes.Buffer
	if err := builder.BuildToWriter(&out); err != nil {
		t.Fatalf("BuildToWriter: %v", err)
	}
	return out.Bytes()
}

func TestClientDecrypt_PrepareFinish_RSA_CDOC20(t *testing.T) {
	privKey, cert := createTestRSACertWithKey(t)
	dataFile := TestDataFile{Name: "cdoc2.txt", Content: []byte("cdoc2 client decrypt"), Size: 20}
	cdocBytes := buildCDOC2BytesOnly(t, cert, dataFile)

	challenge, err := PrepareClientUnwrap(cdocBytes, cert)
	if err != nil {
		t.Fatalf("PrepareClientUnwrap: %v", err)
	}
	if challenge.CdocVersion != "2.0" || challenge.RecipientType != "RSA" {
		t.Fatalf("unexpected challenge: %+v", challenge)
	}

	token := softwareTokenFromKeys(t, privKey, cert)
	kek, err := UnwrapTransportKeyWithToken(token, *challenge)
	if err != nil {
		t.Fatalf("UnwrapTransportKeyWithToken: %v", err)
	}
	if len(kek) != 32 {
		t.Fatalf("kek length = %d, want 32", len(kek))
	}

	files, err := FinishClientDecrypt(cdocBytes, cert, kek)
	if err != nil {
		t.Fatalf("FinishClientDecrypt: %v", err)
	}
	if len(files) != 1 || string(files[0].Content) != string(dataFile.Content) {
		t.Fatalf("unexpected decrypted files: %+v", files)
	}
}

func TestClientDecrypt_PrepareFinish_EC_CDOC20(t *testing.T) {
	privKey, cert := createTestECCertWithKey(t)
	dataFile := TestDataFile{Name: "cdoc2-ec.txt", Content: []byte("cdoc2 ec client"), Size: 15}
	cdocBytes := buildCDOC2BytesOnly(t, cert, dataFile)

	challenge, err := PrepareClientUnwrap(cdocBytes, cert)
	if err != nil {
		t.Fatalf("PrepareClientUnwrap: %v", err)
	}
	if challenge.CdocVersion != "2.0" || challenge.RecipientType != "EC" {
		t.Fatalf("unexpected challenge: %+v", challenge)
	}
	if challenge.RecipientKeyB64 == "" {
		t.Fatal("expected recipientKeyB64 for CDOC2 ECC")
	}

	token := softwareTokenFromKeys(t, privKey, cert)
	kek, err := UnwrapTransportKeyWithToken(token, *challenge)
	if err != nil {
		t.Fatalf("UnwrapTransportKeyWithToken: %v", err)
	}

	files, err := FinishClientDecrypt(cdocBytes, cert, kek)
	if err != nil {
		t.Fatalf("FinishClientDecrypt: %v", err)
	}
	if len(files) != 1 || string(files[0].Content) != string(dataFile.Content) {
		t.Fatalf("unexpected decrypted files: %+v", files)
	}
}

func TestClientDecrypt_PrepareFinish_WrongCert_CDOC20(t *testing.T) {
	_, cert := createTestRSACertWithKey(t)
	_, otherCert := createTestRSACertWithKey(t)
	cdocBytes := buildCDOC2BytesOnly(t, cert, TestDataFile{Name: "x.txt", Content: []byte("x"), Size: 1})

	_, err := PrepareClientUnwrap(cdocBytes, otherCert)
	if err == nil {
		t.Fatal("expected error for non-matching certificate")
	}
}
