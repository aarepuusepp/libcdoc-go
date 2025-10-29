package internal

import (
	"encoding/hex"
)

// EncodeHex encodes data to hexadecimal string
func EncodeHex(data []byte) string {
	return hex.EncodeToString(data)
}

// DecodeHex decodes hexadecimal string to bytes
func DecodeHex(s string) ([]byte, error) {
	return hex.DecodeString(s)
}

