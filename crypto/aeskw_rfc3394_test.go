package crypto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode failed: %v", err)
	}
	return b
}

func TestAESKW_RFC3394_TestVectors_WrapUnwrap(t *testing.T) {
	// Official RFC 3394 test vectors (Section 4).
	// KEK = key-encryption key, Key Data = plaintext key material.
	tests := []struct {
		name      string
		kekHex    string
		plainHex  string
		cipherHex string
	}{
		{
			name:      "4.1 128-bit key data with 128-bit KEK",
			kekHex:    "000102030405060708090A0B0C0D0E0F",
			plainHex:  "00112233445566778899AABBCCDDEEFF",
			cipherHex: "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5",
		},
		{
			name:      "4.2 128-bit key data with 192-bit KEK",
			kekHex:    "000102030405060708090A0B0C0D0E0F1011121314151617",
			plainHex:  "00112233445566778899AABBCCDDEEFF",
			cipherHex: "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D",
		},
		{
			name:      "4.3 128-bit key data with 256-bit KEK",
			kekHex:    "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
			plainHex:  "00112233445566778899AABBCCDDEEFF",
			cipherHex: "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7",
		},
		{
			name:      "4.4 192-bit key data with 192-bit KEK",
			kekHex:    "000102030405060708090A0B0C0D0E0F1011121314151617",
			plainHex:  "00112233445566778899AABBCCDDEEFF0001020304050607",
			cipherHex: "031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2",
		},
		{
			name:      "4.5 192-bit key data with 256-bit KEK",
			kekHex:    "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
			plainHex:  "00112233445566778899AABBCCDDEEFF0001020304050607",
			cipherHex: "A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1",
		},
		{
			name:      "4.6 256-bit key data with 256-bit KEK",
			kekHex:    "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
			plainHex:  "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
			cipherHex: "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kek := mustHex(t, tt.kekHex)
			plain := mustHex(t, tt.plainHex)
			wantCipher := mustHex(t, tt.cipherHex)

			gotCipher, err := wrapRFC3394(kek, plain)
			if err != nil {
				t.Fatalf("wrapRFC3394() error = %v", err)
			}
			if !bytes.Equal(gotCipher, wantCipher) {
				t.Fatalf("wrapRFC3394() ciphertext mismatch\n got:  %x\n want: %x", gotCipher, wantCipher)
			}

			gotPlain, err := unwrapRFC3394(kek, wantCipher)
			if err != nil {
				t.Fatalf("unwrapRFC3394() error = %v", err)
			}
			if !bytes.Equal(gotPlain, plain) {
				t.Fatalf("unwrapRFC3394() plaintext mismatch\n got:  %x\n want: %x", gotPlain, plain)
			}
		})
	}
}

func TestAESKW_RFC3394_UnwrapRejectsWrongIV(t *testing.T) {
	kek := mustHex(t, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
	plain := mustHex(t, "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F")
	cipher, err := wrapRFC3394(kek, plain)
	if err != nil {
		t.Fatalf("wrapRFC3394() error = %v", err)
	}

	cipher[0] ^= 0x01
	if _, err := unwrapRFC3394(kek, cipher); err == nil {
		t.Fatal("unwrapRFC3394() expected error for wrong IV, got nil")
	}
}

func TestWrapAES256_RFC3394_Vector46(t *testing.T) {
	// Exercise the exported AES-KW-256 helpers against RFC 3394 section 4.6.
	kek := mustHex(t, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
	plain := mustHex(t, "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F")
	wantCipher := mustHex(t, "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21")

	gotCipher, err := WrapAES256(plain, kek)
	if err != nil {
		t.Fatalf("WrapAES256() error = %v", err)
	}
	if !bytes.Equal(gotCipher, wantCipher) {
		t.Fatalf("WrapAES256() ciphertext mismatch\n got:  %x\n want: %x", gotCipher, wantCipher)
	}

	gotPlain, err := UnwrapAES256(wantCipher, kek)
	if err != nil {
		t.Fatalf("UnwrapAES256() error = %v", err)
	}
	if !bytes.Equal(gotPlain, plain) {
		t.Fatalf("UnwrapAES256() plaintext mismatch\n got:  %x\n want: %x", gotPlain, plain)
	}
}
