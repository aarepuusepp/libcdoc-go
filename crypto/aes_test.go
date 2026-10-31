package crypto

import (
	"bytes"
	"testing"
)

func TestEncryptDecryptAESGCM(t *testing.T) {
	plaintext := []byte("Hello, World! This is a test message.")
	key := make([]byte, 32) // AES-256
	copy(key, []byte("01234567890123456789012345678901"))

	iv, err := GenerateIV(12)
	if err != nil {
		t.Fatalf("GenerateIV() error = %v", err)
	}

	// Encrypt
	ciphertext, err := EncryptAESGCM(plaintext, key, iv)
	if err != nil {
		t.Fatalf("EncryptAESGCM() error = %v", err)
	}

	if len(ciphertext) <= len(plaintext) {
		t.Error("EncryptAESGCM() ciphertext should be longer than plaintext (includes auth tag)")
	}

	// Decrypt
	decrypted, err := DecryptAESGCM(ciphertext, key, iv)
	if err != nil {
		t.Fatalf("DecryptAESGCM() error = %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("DecryptAESGCM() = %v, want %v", decrypted, plaintext)
	}
}

func TestEncryptDecryptAESGCM_EmptyPlaintext(t *testing.T) {
	plaintext := []byte{}
	key := make([]byte, 32)
	copy(key, []byte("01234567890123456789012345678901"))

	iv, err := GenerateIV(12)
	if err != nil {
		t.Fatalf("GenerateIV() error = %v", err)
	}

	// Encrypt
	ciphertext, err := EncryptAESGCM(plaintext, key, iv)
	if err != nil {
		t.Fatalf("EncryptAESGCM() error = %v", err)
	}

	// Decrypt
	decrypted, err := DecryptAESGCM(ciphertext, key, iv)
	if err != nil {
		t.Fatalf("DecryptAESGCM() error = %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("DecryptAESGCM() = %v, want %v", decrypted, plaintext)
	}
}

func TestEncryptDecryptAESGCM_WrongKey(t *testing.T) {
	plaintext := []byte("Hello, World!")
	key := make([]byte, 32)
	copy(key, []byte("01234567890123456789012345678901"))

	wrongKey := make([]byte, 32)
	copy(wrongKey, []byte("98765432109876543210987654321098"))

	iv, err := GenerateIV(12)
	if err != nil {
		t.Fatalf("GenerateIV() error = %v", err)
	}

	// Encrypt
	ciphertext, err := EncryptAESGCM(plaintext, key, iv)
	if err != nil {
		t.Fatalf("EncryptAESGCM() error = %v", err)
	}

	// Try to decrypt with wrong key
	_, err = DecryptAESGCM(ciphertext, wrongKey, iv)
	if err == nil {
		t.Error("DecryptAESGCM() with wrong key should fail")
	}
}

func TestEncryptDecryptAESCBC(t *testing.T) {
	plaintext := []byte("Hello, World! This is a test message for CBC mode.")
	key := make([]byte, 16) // AES-128
	copy(key, []byte("0123456789012345"))

	iv, err := GenerateIV(16)
	if err != nil {
		t.Fatalf("GenerateIV() error = %v", err)
	}

	// Encrypt
	ciphertext, err := EncryptAESCBC(plaintext, key, iv)
	if err != nil {
		t.Fatalf("EncryptAESCBC() error = %v", err)
	}

	if len(ciphertext)%16 != 0 {
		t.Error("EncryptAESCBC() ciphertext length should be multiple of block size")
	}

	// Decrypt
	decrypted, err := DecryptAESCBC(ciphertext, key, iv)
	if err != nil {
		t.Fatalf("DecryptAESCBC() error = %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("DecryptAESCBC() = %v, want %v", string(decrypted), string(plaintext))
	}
}

func TestEncryptDecryptAESCBC_VariousSizes(t *testing.T) {
	tests := []struct {
		name      string
		plaintext string
	}{
		{"1 byte", "A"},
		{"15 bytes", "123456789012345"},
		{"16 bytes", "1234567890123456"},
		{"17 bytes", "12345678901234567"},
		{"32 bytes", "12345678901234567890123456789012"},
		{"100 bytes", "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},
	}

	key := make([]byte, 16)
	copy(key, []byte("0123456789012345"))

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plaintext := []byte(tt.plaintext)
			iv, err := GenerateIV(16)
			if err != nil {
				t.Fatalf("GenerateIV() error = %v", err)
			}

			// Encrypt
			ciphertext, err := EncryptAESCBC(plaintext, key, iv)
			if err != nil {
				t.Fatalf("EncryptAESCBC() error = %v", err)
			}

			// Decrypt
			decrypted, err := DecryptAESCBC(ciphertext, key, iv)
			if err != nil {
				t.Fatalf("DecryptAESCBC() error = %v", err)
			}

			if !bytes.Equal(decrypted, plaintext) {
				t.Errorf("DecryptAESCBC() = %v, want %v", string(decrypted), tt.plaintext)
			}
		})
	}
}

func TestDecryptAESGCM_InvalidCiphertext(t *testing.T) {
	key := make([]byte, 32)
	copy(key, []byte("01234567890123456789012345678901"))
	iv, _ := GenerateIV(12)

	// Too short ciphertext
	_, err := DecryptAESGCM([]byte{1, 2, 3}, key, iv)
	if err == nil {
		t.Error("DecryptAESGCM() with invalid ciphertext should fail")
	}
}
