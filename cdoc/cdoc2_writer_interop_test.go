package cdoc

import (
	"archive/tar"
	"bytes"
	"compress/zlib"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"io"
	"testing"

	c2 "github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2"
	"golang.org/x/crypto/chacha20poly1305"
)

// Independent decoder for newly emitted files: no libcdoc KDF/decryption helpers.
// Together with imported Java fixtures this catches symmetric writer/reader bugs.
func TestCDOC2WriterStandardEncoding(t *testing.T) {
	for _, kind := range []string{"RSA", "P256", "P384", "P521"} {
		t.Run(kind, func(t *testing.T) {
			var priv any
			var pub any
			if kind == "RSA" {
				k, e := rsa.GenerateKey(rand.Reader, 2048)
				if e != nil {
					t.Fatal(e)
				}
				priv = k
				pub = &k.PublicKey
			} else {
				curve := elliptic.P384()
				if kind == "P256" {
					curve = elliptic.P256()
				}
				if kind == "P521" {
					curve = elliptic.P521()
				}
				k, e := ecdsa.GenerateKey(curve, rand.Reader)
				if e != nil {
					t.Fatal(e)
				}
				priv = k
				pub = &k.PublicKey
			}
			cert := referenceCertificate(t, priv, pub)
			plain := []byte("Independent CDOC2 writer verification")
			input := buildCDOC2BytesOnly(t, cert, TestDataFile{Name: "test.txt", Content: plain, Size: int64(len(plain))})
			r, _ := c2.NewReader(bytes.NewReader(input))
			if _, e := r.ReadHeader(); e != nil {
				t.Fatal(e)
			}
			locks, e := r.GetLocks()
			if e != nil || len(locks) != 1 {
				t.Fatal(e)
			}
			lock := locks[0]
			var kek []byte
			switch key := priv.(type) {
			case *rsa.PrivateKey:
				if !bytes.Equal(lock.RecipientKey, x509.MarshalPKCS1PublicKey(&key.PublicKey)) {
					t.Fatal("RSA is not PKCS1 encoded")
				}
				kek, e = rsa.DecryptOAEP(sha256.New(), rand.Reader, key, lock.KeyMaterial, nil)
			case *ecdsa.PrivateKey:
				secretKey, err := key.ECDH()
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(lock.RecipientKey, secretKey.PublicKey().Bytes()) {
					t.Fatal("ECC is not TLS encoded")
				}
				eph, err := secretKey.Curve().NewPublicKey(lock.KeyMaterial)
				if err != nil {
					t.Fatal(err)
				}
				shared, err := secretKey.ECDH(eph)
				if err != nil {
					t.Fatal(err)
				}
				defer clear(shared)
				pm := referenceHMAC([]byte("CDOC20kekpremaster"), shared)
				defer clear(pm)
				info := append([]byte("CDOC20kekXOR"), lock.RecipientKey...)
				info = append(info, lock.KeyMaterial...)
				kek = referenceExpand(pm, info)
			}
			if e != nil {
				t.Fatal(e)
			}
			defer clear(kek)
			fmk := make([]byte, 32)
			for i := range fmk {
				fmk[i] = lock.EncryptedFMK[i] ^ kek[i]
			}
			defer clear(fmk)
			n := int(binary.BigEndian.Uint32(input[5:9]))
			header := input[9 : 9+n]
			tag := input[9+n : 9+n+32]
			hhk := referenceExpand(fmk, []byte("CDOC20hmac"))
			defer clear(hhk)
			if !hmac.Equal(tag, referenceHMAC(hhk, header)) {
				t.Fatal("header HMAC mismatch")
			}
			cek := referenceExpand(fmk, []byte("CDOC20cek"))
			defer clear(cek)
			cipher, e := chacha20poly1305.New(cek)
			if e != nil {
				t.Fatal(e)
			}
			aad := append([]byte("CDOC20payload"), header...)
			aad = append(aad, tag...)
			payload, e := cipher.Open(nil, input[9+n+32:9+n+44], input[9+n+44:], aad)
			if e != nil {
				t.Fatal(e)
			}
			z, e := zlib.NewReader(bytes.NewReader(payload))
			if e != nil {
				t.Fatal("not standard zlib:", e)
			}
			defer func() { _ = z.Close() }()
			archive := tar.NewReader(z)
			file, e := archive.Next()
			if e != nil {
				t.Fatal(e)
			}
			content, e := io.ReadAll(archive)
			if e != nil || file.Name != "test.txt" || !bytes.Equal(content, plain) {
				t.Fatal("plaintext mismatch")
			}
		})
	}
}
func referenceHMAC(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}
func referenceExpand(prk, info []byte) []byte {
	return referenceHMAC(prk, append(bytes.Clone(info), 1))
}
