//go:build cgo
// +build cgo

package key

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"

	"github.com/miekg/pkcs11"
)

// PKCS11Signer implements crypto.Signer using a PKCS#11 private key (no key export).
type PKCS11Signer struct {
	ctx       *PKCS11Context
	keyHandle pkcs11.ObjectHandle
	cert      *x509.Certificate
}

// NewPKCS11Signer opens a PKCS#11 session and loads the signing key + certificate.
func NewPKCS11Signer(config PKCS11Config) (*PKCS11Signer, *x509.Certificate, error) {
	ctx, err := NewPKCS11Context(config)
	if err != nil {
		return nil, nil, err
	}
	cert := config.RecipientCert
	if cert == nil {
		cert, err = ctx.FindCertificate(config.Label, config.KeyID)
		if err != nil {
			_ = ctx.Close()
			return nil, nil, err
		}
	}
	keyHandle, cert, err := ctx.FindMatchedKeyPair(cert)
	if err != nil {
		_ = ctx.Close()
		return nil, nil, err
	}
	return &PKCS11Signer{ctx: ctx, keyHandle: keyHandle, cert: cert}, cert, nil
}

// Close releases the PKCS#11 session.
func (s *PKCS11Signer) Close() error {
	if s == nil || s.ctx == nil {
		return nil
	}
	return s.ctx.Close()
}

// Public returns the certificate public key.
func (s *PKCS11Signer) Public() crypto.PublicKey {
	if s == nil || s.cert == nil {
		return nil
	}
	return s.cert.PublicKey
}

// Sign implements crypto.Signer using token-resident key material.
func (s *PKCS11Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if s == nil || s.ctx == nil || s.cert == nil {
		return nil, NewPKCS11Error("pkcs11 signer not initialized", nil)
	}
	mech, input, err := signingInput(s.cert.PublicKey, digest, opts)
	if err != nil {
		return nil, err
	}
	if err := s.ctx.ctx.SignInit(s.ctx.session, []*pkcs11.Mechanism{mech}, s.keyHandle); err != nil {
		return nil, NewPKCS11Error("failed to initialize sign", err)
	}
	sig, err := s.ctx.ctx.Sign(s.ctx.session, input)
	if err != nil {
		return nil, NewPKCS11Error("sign failed", err)
	}
	if pub, ok := s.cert.PublicKey.(*ecdsa.PublicKey); ok {
		return ecdsaSignatureDER(pub, sig)
	}
	return sig, nil
}

// crypto.Signer receives an already hashed message; token mechanisms must not hash it again.
func signingInput(public crypto.PublicKey, digest []byte, opts crypto.SignerOpts) (*pkcs11.Mechanism, []byte, error) {
	if opts == nil {
		return nil, nil, fmt.Errorf("signer options required")
	}
	hash := opts.HashFunc()
	if hash != 0 && (!hash.Available() || len(digest) != hash.Size()) {
		return nil, nil, fmt.Errorf("invalid signing digest")
	}
	switch pub := public.(type) {
	case *rsa.PublicKey:
		if pss, ok := opts.(*rsa.PSSOptions); ok {
			var algorithm, mgf uint
			switch hash {
			case crypto.SHA256:
				algorithm, mgf = pkcs11.CKM_SHA256, pkcs11.CKG_MGF1_SHA256
			case crypto.SHA384:
				algorithm, mgf = pkcs11.CKM_SHA384, pkcs11.CKG_MGF1_SHA384
			case crypto.SHA512:
				algorithm, mgf = pkcs11.CKM_SHA512, pkcs11.CKG_MGF1_SHA512
			default:
				return nil, nil, fmt.Errorf("unsupported RSA-PSS hash")
			}
			maxSalt := (pub.N.BitLen()-1+7)/8 - hash.Size() - 2
			salt := pss.SaltLength
			if salt == rsa.PSSSaltLengthAuto {
				salt = maxSalt
			}
			if salt == rsa.PSSSaltLengthEqualsHash {
				salt = hash.Size()
			}
			if salt < 0 || salt > maxSalt {
				return nil, nil, fmt.Errorf("invalid RSA-PSS salt length")
			}
			return pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_PSS, pkcs11.NewPSSParams(algorithm, mgf, uint(salt))), digest, nil
		}
		prefixes := map[crypto.Hash]string{
			crypto.SHA256: "3031300d060960864801650304020105000420",
			crypto.SHA384: "3041300d060960864801650304020205000430",
			crypto.SHA512: "3051300d060960864801650304020305000440",
		}
		prefix, ok := prefixes[hash]
		if !ok {
			return nil, nil, fmt.Errorf("unsupported RSA signing hash")
		}
		encoded, _ := hex.DecodeString(prefix)
		return pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil), append(encoded, digest...), nil
	case *ecdsa.PublicKey:
		return pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil), digest, nil
	default:
		return nil, nil, fmt.Errorf("unsupported signing key")
	}
}

func ecdsaSignatureDER(public *ecdsa.PublicKey, raw []byte) ([]byte, error) {
	size := (public.Params().N.BitLen() + 7) / 8
	if len(raw) != 2*size {
		return nil, fmt.Errorf("invalid PKCS11 ECDSA signature size")
	}
	r, s := new(big.Int).SetBytes(raw[:size]), new(big.Int).SetBytes(raw[size:])
	if r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(public.Params().N) >= 0 || s.Cmp(public.Params().N) >= 0 {
		return nil, fmt.Errorf("invalid PKCS11 ECDSA signature values")
	}
	return asn1.Marshal(struct{ R, S *big.Int }{r, s})
}

// TLSCertificateFromPKCS11 builds a tls.Certificate whose PrivateKey is a PKCS11Signer.
func TLSCertificateFromPKCS11(config PKCS11Config) (tls.Certificate, error) {
	signer, cert, err := NewPKCS11Signer(config)
	if err != nil {
		return tls.Certificate{}, err
	}
	if cert == nil || signer == nil {
		return tls.Certificate{}, fmt.Errorf("pkcs11 signer or certificate missing")
	}
	return tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  signer,
		Leaf:        cert,
	}, nil
}
