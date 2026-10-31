package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"github.com/aarepuusepp/libcdoc-go/v2/internal"
	"io"
)

// EncryptAESGCM encrypts data using AES-256-GCM
func EncryptAESGCM(plaintext []byte, key []byte, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, internal.NewEncryptionError("failed to create AES cipher", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, internal.NewEncryptionError("failed to create GCM", err)
	}

	ciphertext := gcm.Seal(nil, iv, plaintext, nil)
	return ciphertext, nil
}

// DecryptAESGCM decrypts data using AES-256-GCM
func DecryptAESGCM(ciphertext []byte, key []byte, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, internal.NewDecryptionError("failed to create AES cipher", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, internal.NewDecryptionError("failed to create GCM", err)
	}

	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return nil, internal.NewDecryptionError("failed to decrypt with GCM", err)
	}

	return plaintext, nil
}

// EncryptAESGCMStream encrypts data stream using AES-256-GCM
func EncryptAESGCMStream(dst io.Writer, src io.Reader, key []byte, iv []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return internal.NewEncryptionError("failed to create AES cipher", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return internal.NewEncryptionError("failed to create GCM", err)
	}

	// Read all data from source
	plaintext, err := io.ReadAll(src)
	if err != nil {
		return internal.NewEncryptionError("failed to read source data", err)
	}

	// Encrypt
	ciphertext := gcm.Seal(nil, iv, plaintext, nil)

	// Write to destination
	_, err = dst.Write(ciphertext)
	if err != nil {
		return internal.NewEncryptionError("failed to write encrypted data", err)
	}

	return nil
}

// EncryptAESCBC encrypts data using AES-128-CBC with X.923 + PKCS#7 padding
func EncryptAESCBC(plaintext []byte, key []byte, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, internal.NewEncryptionError("failed to create AES cipher", err)
	}

	// Apply X.923 padding first, then PKCS#7
	// For CDOC 1.0, both paddings are applied
	paddedData := make([]byte, len(plaintext))
	copy(paddedData, plaintext)

	blockSize := aes.BlockSize
	x923PadLength := blockSize - (len(paddedData) % blockSize)

	// Add X.923 padding
	x923Padding := make([]byte, x923PadLength)
	for i := 0; i < x923PadLength-1; i++ {
		x923Padding[i] = 0x00
	}
	x923Padding[x923PadLength-1] = byte(x923PadLength)
	paddedData = append(paddedData, x923Padding...)

	// Add PKCS#7 padding
	pkcs7PadLength := blockSize - (len(paddedData) % blockSize)
	pkcs7Padding := make([]byte, pkcs7PadLength)
	for i := range pkcs7Padding {
		pkcs7Padding[i] = byte(pkcs7PadLength)
	}
	paddedData = append(paddedData, pkcs7Padding...)

	if len(paddedData)%blockSize != 0 {
		return nil, internal.NewEncryptionError("padding error: data length not multiple of block size", nil)
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(paddedData))
	mode.CryptBlocks(ciphertext, paddedData)

	return ciphertext, nil
}

// DecryptAESCBC decrypts data using AES-128-CBC and removes padding
func DecryptAESCBC(ciphertext []byte, key []byte, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, internal.NewDecryptionError("failed to create AES cipher", err)
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, internal.NewDecryptionError("ciphertext length is not a multiple of block size", nil)
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	// Remove PKCS#7 padding first, then X.923
	// For CDOC 1.0, both paddings are applied in reverse order
	plaintext, err = RemovePKCS7Padding(plaintext)
	if err != nil {
		return nil, internal.NewDecryptionError("failed to remove PKCS#7 padding", err)
	}

	plaintext, err = RemoveX923Padding(plaintext)
	if err != nil {
		return nil, internal.NewDecryptionError("failed to remove X.923 padding", err)
	}

	return plaintext, nil
}

// RemovePKCS7Padding removes PKCS#7 padding (internal helper)
func RemovePKCS7Padding(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, internal.NewDecryptionError("cannot remove padding from empty data", nil)
	}

	padLength := int(data[len(data)-1])
	if padLength == 0 || padLength > len(data) || padLength > aes.BlockSize {
		return nil, internal.NewDecryptionError("invalid padding length", nil)
	}

	// Verify all padding bytes are equal to padLength
	for i := len(data) - padLength; i < len(data); i++ {
		if data[i] != byte(padLength) {
			return nil, internal.NewDecryptionError("invalid PKCS#7 padding", nil)
		}
	}

	return data[:len(data)-padLength], nil
}

// RemoveX923Padding removes X.923 padding (internal helper)
func RemoveX923Padding(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, internal.NewDecryptionError("cannot remove padding from empty data", nil)
	}

	padLength := int(data[len(data)-1])
	if padLength == 0 || padLength > len(data) {
		return nil, internal.NewDecryptionError("invalid padding length", nil)
	}

	// Verify padding bytes are zeros
	for i := len(data) - padLength; i < len(data)-1; i++ {
		if data[i] != 0x00 {
			return nil, internal.NewDecryptionError("invalid X.923 padding", nil)
		}
	}

	return data[:len(data)-padLength], nil
}
