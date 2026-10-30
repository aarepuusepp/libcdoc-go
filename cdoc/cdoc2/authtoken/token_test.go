package authtoken_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2/authtoken"
)

func testAuthCert(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			SerialNumber: "PNOEE-38001085718",
			CommonName:   "TEST,OK",
			Country:      []string{"EE"},
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func TestAuthToken_SDJWT_RoundTrip(t *testing.T) {
	cert, key := testAuthCert(t)
	shares := []authtoken.ShareAccess{
		{ServerBaseURL: "https://shares1.test:8443", ShareID: "KS111111111111111111111111111111", Nonce: "nonce-a"},
		{ServerBaseURL: "https://shares2.test:8443", ShareID: "KS222222222222222222222222222222", Nonce: "nonce-b"},
	}
	issuer := "etsi/PNOEE-38001085718"
	creator, err := authtoken.NewCreator(issuer, shares)
	if err != nil {
		t.Fatal(err)
	}
	if err := creator.SignWithSigner(key, cert.Raw); err != nil {
		t.Fatal(err)
	}
	for _, sh := range shares {
		ticket, err := creator.TicketForShareID(sh.ShareID)
		if err != nil {
			t.Fatal(err)
		}
		claims, err := authtoken.VerifyTicket(ticket, cert.Raw, sh.AccessURL())
		if err != nil {
			t.Fatalf("verify share %s: %v", sh.ShareID, err)
		}
		if claims.Issuer != issuer {
			t.Fatal("issuer mismatch")
		}
		if len(claims.Aud) != 1 || claims.Aud[0] != sh.AccessURL() {
			t.Fatalf("aud not selectively disclosed: %+v", claims.Aud)
		}
	}
}

func TestAuthToken_Verify_AudienceMismatch(t *testing.T) {
	cert, key := testAuthCert(t)
	sh := authtoken.ShareAccess{ServerBaseURL: "https://shares1.test:8443", ShareID: "KS111111111111111111111111111111", Nonce: "nonce-a"}
	creator, err := authtoken.NewCreator("etsi/PNOEE-38001085718", []authtoken.ShareAccess{sh})
	if err != nil {
		t.Fatal(err)
	}
	if err := creator.SignWithSigner(key, cert.Raw); err != nil {
		t.Fatal(err)
	}
	ticket, err := creator.TicketForShareID(sh.ShareID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = authtoken.VerifyTicket(ticket, cert.Raw, "https://other.test/key-shares/x?nonce=y")
	if err == nil {
		t.Fatal("expected audience mismatch")
	}
}

func TestAuthToken_Verify_SignatureTamper(t *testing.T) {
	cert, key := testAuthCert(t)
	sh := authtoken.ShareAccess{ServerBaseURL: "https://shares1.test:8443", ShareID: "KS111111111111111111111111111111", Nonce: "nonce-a"}
	creator, err := authtoken.NewCreator("etsi/PNOEE-38001085718", []authtoken.ShareAccess{sh})
	if err != nil {
		t.Fatal(err)
	}
	if err := creator.SignWithSigner(key, cert.Raw); err != nil {
		t.Fatal(err)
	}
	ticket, err := creator.TicketForShareID(sh.ShareID)
	if err != nil {
		t.Fatal(err)
	}
	tampered := ticket[:len(ticket)-4] + "AAAA"
	_, err = authtoken.VerifyTicket(tampered, cert.Raw, sh.AccessURL())
	if err == nil {
		t.Fatal("expected signature verification failure")
	}
}

func TestAuthToken_Verify_ReplayAtWrongShareURL(t *testing.T) {
	cert, key := testAuthCert(t)
	sh1 := authtoken.ShareAccess{ServerBaseURL: "https://shares1.test:8443", ShareID: "KS111111111111111111111111111111", Nonce: "nonce-a"}
	sh2 := authtoken.ShareAccess{ServerBaseURL: "https://shares2.test:8443", ShareID: "KS222222222222222222222222222222", Nonce: "nonce-b"}
	creator, err := authtoken.NewCreator("etsi/PNOEE-38001085718", []authtoken.ShareAccess{sh1, sh2})
	if err != nil {
		t.Fatal(err)
	}
	if err := creator.SignWithSigner(key, cert.Raw); err != nil {
		t.Fatal(err)
	}
	ticket, err := creator.TicketForShareID(sh1.ShareID)
	if err != nil {
		t.Fatal(err)
	}
	// Replaying share-1 ticket against share-2 URL must fail (audience binding).
	_, err = authtoken.VerifyTicket(ticket, cert.Raw, sh2.AccessURL())
	if err == nil {
		t.Fatal("expected replay at wrong share URL to fail")
	}
}

func TestCreateFromSignature_RequiresShares(t *testing.T) {
	_, _, err := authtoken.CreateFromSignature("etsi/PNOEE-38001085718", nil, []byte("sig"), []byte("cert"))
	if err == nil {
		t.Fatal("expected error for empty shares")
	}
}

func TestAuthToken_ES256UsesJWSFormat(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{SerialNumber: "PNOEE-38001085718"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	share := authtoken.ShareAccess{ServerBaseURL: "https://shares.test", ShareID: "KS111111111111111111111111111111", Nonce: "nonce"}
	creator, err := authtoken.NewCreator("etsi/PNOEE-38001085718", []authtoken.ShareAccess{share})
	if err != nil {
		t.Fatal(err)
	}
	if err := creator.SignWithSigner(key, der); err != nil {
		t.Fatal(err)
	}
	ticket, err := creator.TicketForShareID(share.ShareID)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(strings.Split(ticket, "~")[0], ".")
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		t.Fatalf("JWS signature must be 64 bytes: %d %v", len(sig), err)
	}
	hash := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r, ss := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(&key.PublicKey, hash[:], r, ss) {
		t.Fatal("independent JWS verification failed")
	}
	if _, err := authtoken.VerifyTicket(ticket, der, share.AccessURL()); err != nil {
		t.Fatal(err)
	}
	asn1Sig, _ := asn1.Marshal(struct{ R, S *big.Int }{r, ss})
	if err := creator.AttachSignature(asn1Sig, der, "ES256"); err == nil {
		t.Fatal("ASN.1 signature accepted as JWS")
	}
	sig[0] ^= 1
	if err := creator.AttachSignature(sig, der, "ES256"); err == nil {
		t.Fatal("tampered signature accepted")
	}
}
func TestAuthToken_RejectsInvalidProofAndIdentity(t *testing.T) {
	cert, key := testAuthCert(t)
	share := authtoken.ShareAccess{ServerBaseURL: "https://shares.test", ShareID: "KS111111111111111111111111111111", Nonce: "nonce"}
	creator, err := authtoken.NewCreator("etsi/PNOEE-99999999999", []authtoken.ShareAccess{share})
	if err != nil {
		t.Fatal(err)
	}
	if err := creator.SignWithSigner(key, cert.Raw); err == nil {
		t.Fatal("mismatched identity accepted")
	}
	for _, signature := range [][]byte{nil, []byte("bogus")} {
		if err := creator.AttachSignature(signature, []byte("invalid certificate"), "RS256"); err == nil {
			t.Fatal("invalid proof accepted")
		}
		if _, _, err := authtoken.CreateFromSignature("etsi/PNOEE-38001085718", []authtoken.ShareAccess{share}, signature, cert.Raw); !errors.Is(err, authtoken.ErrExternalProofProfileUnsupported) {
			t.Fatalf("external proof not blocked: %v", err)
		}
	}
	if _, err := creator.TicketForShareID(share.ShareID); err == nil {
		t.Fatal("ticket issued without valid signature")
	}
	other, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err := creator.SignWithSigner(other, cert.Raw); err == nil {
		t.Fatal("P-384 accepted as ES256")
	}
}
