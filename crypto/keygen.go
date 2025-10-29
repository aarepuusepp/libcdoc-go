package crypto

import (
	"crypto/rand"
)

// GenerateDataEncryptionKey generates a random AES key of specified length in bytes
func GenerateDataEncryptionKey(lengthInBytes int) ([]byte, error) {
	key := make([]byte, lengthInBytes)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// GenerateIV generates a random IV/nonce of specified length in bytes
func GenerateIV(lengthInBytes int) ([]byte, error) {
	iv := make([]byte, lengthInBytes)
	_, err := rand.Read(iv)
	if err != nil {
		return nil, err
	}
	return iv, nil
}
