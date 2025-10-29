package crypto

import (
	"errors"
	"io"
)

// AddX923Padding adds X.923 padding to the output stream
// X.923 padding fills with zeros and ends with the padding length
func AddX923Padding(w io.Writer, dataSize int64, blockSize int) (int, error) {
	padLength := blockSize - int(dataSize%int64(blockSize))

	for i := 0; i < padLength-1; i++ {
		if _, err := w.Write([]byte{0x00}); err != nil {
			return 0, err
		}
	}
	if _, err := w.Write([]byte{byte(padLength)}); err != nil {
		return 0, err
	}

	return padLength, nil
}

// RemoveX923PaddingFromData removes X.923 padding from the data
// This is a separate function to avoid conflict with the internal helper in aes.go
func RemoveX923PaddingFromData(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("cannot remove padding from empty data")
	}

	padLength := int(data[len(data)-1])
	if padLength == 0 || padLength > len(data) {
		return nil, errors.New("invalid padding length")
	}

	// Verify padding bytes are zeros
	for i := len(data) - padLength; i < len(data)-1; i++ {
		if data[i] != 0x00 {
			return nil, errors.New("invalid X.923 padding")
		}
	}

	return data[:len(data)-padLength], nil
}

// AddPKCS7Padding adds PKCS#7 padding to the output stream
// PKCS#7 padding fills with bytes equal to the padding length
func AddPKCS7Padding(w io.Writer, dataSize int64, blockSize int) (int, error) {
	padLength := blockSize - int(dataSize%int64(blockSize))

	padByte := byte(padLength)
	padBytes := make([]byte, padLength)
	for i := range padBytes {
		padBytes[i] = padByte
	}

	if _, err := w.Write(padBytes); err != nil {
		return 0, err
	}

	return padLength, nil
}

// RemovePKCS7PaddingFromData removes PKCS#7 padding from the data
// This is a separate function to avoid conflict with the internal helper in aes.go
func RemovePKCS7PaddingFromData(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("cannot remove padding from empty data")
	}

	padLength := int(data[len(data)-1])
	if padLength == 0 || padLength > len(data) || padLength > 16 {
		return nil, errors.New("invalid padding length")
	}

	// Verify all padding bytes are equal to padLength
	for i := len(data) - padLength; i < len(data); i++ {
		if data[i] != byte(padLength) {
			return nil, errors.New("invalid PKCS#7 padding")
		}
	}

	return data[:len(data)-padLength], nil
}
