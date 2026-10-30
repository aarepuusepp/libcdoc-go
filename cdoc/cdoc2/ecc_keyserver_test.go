package cdoc2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func TestEncodeECKeyServerRecipient_Curves(t *testing.T) {
	tests := []struct {
		name        string
		curve       elliptic.Curve
		capsuleType string
		coordLen    int
	}{
		{"P256", elliptic.P256(), "ecc_secp256r1", 32},
		{"P384", elliptic.P384(), "ecc_secp384r1", 48},
		{"P521", elliptic.P521(), "ecc_secp521r1", 66},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			priv, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			enc, err := EncodeECKeyServerRecipient(&priv.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			if enc.CapsuleType != tc.capsuleType {
				t.Fatalf("capsule type: got %q want %q", enc.CapsuleType, tc.capsuleType)
			}
			wantLen := 1 + tc.coordLen*2
			if len(enc.TLSPoint) != wantLen {
				t.Fatalf("TLS point len: got %d want %d", len(enc.TLSPoint), wantLen)
			}
			if enc.TLSPoint[0] != 0x04 {
				t.Fatal("expected uncompressed point prefix 0x04")
			}
		})
	}
}
