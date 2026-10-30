//go:build cgo

package key

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"github.com/miekg/pkcs11"
	"math/big"
	"testing"
)

func TestSigningInputRSAUsesDigestInfo(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("already hashed message"))
	mech, input, err := signingInput(&private.PublicKey, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if mech.Mechanism != pkcs11.CKM_RSA_PKCS {
		t.Fatal("token must not hash digest again")
	}
	signature, err := rsa.SignPKCS1v15(rand.Reader, private, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	encoded := new(big.Int).Exp(new(big.Int).SetBytes(signature), big.NewInt(int64(private.E)), private.N).FillBytes(make([]byte, private.Size()))
	separator := bytes.IndexByte(encoded[2:], 0) + 2
	if separator < 2 || !bytes.Equal(encoded[separator+1:], input) {
		t.Fatal("PKCS11 input differs from standard RSA DigestInfo")
	}
	mech, input, err = signingInput(&private.PublicKey, digest[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
	if err != nil || mech.Mechanism != pkcs11.CKM_RSA_PKCS_PSS || !bytes.Equal(input, digest[:]) {
		t.Fatalf("PSS input: %v", err)
	}
	if _, _, err := signingInput(&private.PublicKey, digest[:3], crypto.SHA256); err == nil {
		t.Fatal("accepted truncated digest")
	}
	if _, _, err := signingInput(&private.PublicKey, digest[:], &rsa.PSSOptions{SaltLength: 300, Hash: crypto.SHA256}); err == nil {
		t.Fatal("accepted oversized salt")
	}
}

func TestECDSATokenSignatureConvertsToDER(t *testing.T) {
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		t.Run(curve.Params().Name, func(t *testing.T) {
			private, err := ecdsa.GenerateKey(curve, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256([]byte("TLS signature"))
			r, s, err := ecdsa.Sign(rand.Reader, private, digest[:])
			if err != nil {
				t.Fatal(err)
			}
			size := (curve.Params().N.BitLen() + 7) / 8
			raw := append(r.FillBytes(make([]byte, size)), s.FillBytes(make([]byte, size))...)
			signature, err := ecdsaSignatureDER(&private.PublicKey, raw)
			if err != nil || !ecdsa.VerifyASN1(&private.PublicKey, digest[:], signature) {
				t.Fatalf("invalid DER signature: %v", err)
			}
			if _, err := ecdsaSignatureDER(&private.PublicKey, raw[1:]); err == nil {
				t.Fatal("accepted truncated signature")
			}
			if _, err := ecdsaSignatureDER(&private.PublicKey, make([]byte, 2*size)); err == nil {
				t.Fatal("accepted zero signature")
			}
		})
	}
}
