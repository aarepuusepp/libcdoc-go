package cdoc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func TestEncodeECPublicKeyBytes_UncompressedPointMatchesEllipticMarshal(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate EC key: %v", err)
	}

	got, err := encodeECPublicKeyBytes(privKey.PublicKey)
	if err != nil {
		t.Fatalf("encodeECPublicKeyBytes() error: %v", err)
	}

	//nolint:staticcheck // Test asserts compatibility with the legacy SEC1 uncompressed point encoding.
	want := elliptic.Marshal(elliptic.P384(), privKey.PublicKey.X, privKey.PublicKey.Y)

	if len(got) != 97 {
		t.Fatalf("Expected 97-byte uncompressed point, got %d", len(got))
	}
	if got[0] != 0x04 {
		t.Fatalf("Expected uncompressed point prefix 0x04, got 0x%02x", got[0])
	}
	if !bytes.Equal(got, want) {
		t.Fatal("Uncompressed point bytes do not match elliptic.Marshal output")
	}
}
