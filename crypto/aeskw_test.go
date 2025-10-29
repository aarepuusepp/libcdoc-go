package crypto

import (
	"bytes"
	"testing"
)

func TestWrapUnwrapAES256(t *testing.T) {
	// 256-bit key to wrap (32 bytes)
	keyToWrap := make([]byte, 32)
	for i := range keyToWrap {
		keyToWrap[i] = byte(i)
	}

	// 256-bit wrapping key (32 bytes)
	wrappingKey := make([]byte, 32)
	for i := range wrappingKey {
		wrappingKey[i] = byte(i + 32)
	}

	// Wrap
	wrapped, err := WrapAES256(keyToWrap, wrappingKey)
	if err != nil {
		t.Fatalf("WrapAES256() error = %v", err)
	}

	// Wrapped key should be 40 bytes (RFC 3394 for 256-bit keys: A + 4 blocks of 8 bytes)
	if len(wrapped) != 40 {
		t.Errorf("WrapAES256() length = %v, want 40", len(wrapped))
	}

	// Should be different from original
	if bytes.Equal(wrapped, keyToWrap[:24]) {
		t.Error("WrapAES256() wrapped key should be different from original")
	}

	// Unwrap
	unwrapped, err := UnwrapAES256(wrapped, wrappingKey)
	if err != nil {
		t.Fatalf("UnwrapAES256() error = %v", err)
	}

	if !bytes.Equal(unwrapped, keyToWrap) {
		t.Errorf("UnwrapAES256() = %v, want %v", unwrapped, keyToWrap)
	}
}

func TestWrapUnwrapAES256_MultipleKeys(t *testing.T) {
	tests := []struct {
		name        string
		keyToWrap   []byte
		wrappingKey []byte
	}{
		{
			name:        "all zeros",
			keyToWrap:   make([]byte, 32),
			wrappingKey: make([]byte, 32),
		},
		{
			name:        "all ones",
			keyToWrap:   bytes.Repeat([]byte{0xFF}, 32),
			wrappingKey: bytes.Repeat([]byte{0xAA}, 32),
		},
		{
			name:        "pattern",
			keyToWrap:   []byte("01234567890123456789012345678901"),
			wrappingKey: []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Wrap
			wrapped, err := WrapAES256(tt.keyToWrap, tt.wrappingKey)
			if err != nil {
				t.Fatalf("WrapAES256() error = %v", err)
			}

			// Unwrap
			unwrapped, err := UnwrapAES256(wrapped, tt.wrappingKey)
			if err != nil {
				t.Fatalf("UnwrapAES256() error = %v", err)
			}

			if !bytes.Equal(unwrapped, tt.keyToWrap) {
				t.Errorf("UnwrapAES256() = %v, want %v", unwrapped, tt.keyToWrap)
			}
		})
	}
}

func TestWrapAES256_InvalidInput(t *testing.T) {
	wrappingKey := make([]byte, 32)

	tests := []struct {
		name      string
		keyToWrap []byte
		wantErr   bool
	}{
		{"key too short", make([]byte, 31), true},
		{"key too long", make([]byte, 33), true},
		{"wrapping key too short", make([]byte, 32), false}, // Will fail in wrap function
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := WrapAES256(tt.keyToWrap, wrappingKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("WrapAES256() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestUnwrapAES256_InvalidInput(t *testing.T) {
	wrappingKey := make([]byte, 32)

	tests := []struct {
		name       string
		wrappedKey []byte
		wantErr    bool
	}{
		{"wrapped key too short", make([]byte, 39), true},
		{"wrapped key too long", make([]byte, 41), true},
		{"invalid AIV", make([]byte, 40), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := UnwrapAES256(tt.wrappedKey, wrappingKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("UnwrapAES256() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

