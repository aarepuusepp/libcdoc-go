package cdoc2

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"io"

	"github.com/aarepuusepp/libcdoc-go/v2/crypto"
	"github.com/aarepuusepp/libcdoc-go/v2/internal"
)

// AddFileToArchive adds a file to the TAR archive being built
func (w *Writer) AddFileToArchive(name string, content io.Reader, size int64) error {
	if !w.headerWritten {
		return internal.NewEncryptionError("header must be written before adding files", nil)
	}

	// TAR archive building is already implemented in buildTARArchive() function
	// This method could be extended in the future to support incremental file addition
	return internal.NewEncryptionError("not yet implemented", nil)
}

// WriteEncryptedData writes encrypted payload to destination
func (w *Writer) WriteEncryptedData(files []DataFile) error {
	if !w.headerWritten {
		return internal.NewEncryptionError("header must be written first", nil)
	}

	// Build TAR archive from files
	tarData, err := buildTARArchive(files)
	if err != nil {
		return err
	}

	// Compress with gzip
	compressedData, err := compressGzip(tarData)
	if err != nil {
		return err
	}

	// Derive CEK from FMK
	cek, err := DeriveCEK(w.fmk)
	if err != nil {
		return err
	}

	// Generate nonce
	nonce := make([]byte, NonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return internal.NewEncryptionError("failed to generate nonce", err)
	}

	// Construct AAD: "CDOC20payload" + header + headerHMAC
	// headerData and headerHMAC are stored in Writer during writeHeader()
	hmacKey, err := DeriveHMACKey(w.fmk)
	if err != nil {
		return err
	}
	headerHMAC := computeHMACSHA256(w.headerData, hmacKey)

	aad := []byte(PAYLOAD)
	aad = append(aad, w.headerData...)
	aad = append(aad, headerHMAC...)

	// Encrypt with ChaCha20-Poly1305
	encryptedPayload, err := crypto.EncryptChaCha20Poly1305(compressedData, cek, nonce, aad)
	if err != nil {
		return err
	}

	// Write nonce
	if _, err := w.destination.Write(nonce); err != nil {
		return internal.NewEncryptionError("failed to write nonce", err)
	}

	// Write encrypted payload
	if _, err := w.destination.Write(encryptedPayload); err != nil {
		return internal.NewEncryptionError("failed to write encrypted payload", err)
	}

	w.payloadStarted = true
	return nil
}

// buildTARArchive creates a TAR archive from data files
func buildTARArchive(files []DataFile) ([]byte, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	for _, file := range files {
		header := &tar.Header{
			Name: file.Name,
			Size: file.Size,
			Mode: 0644,
		}

		if err := tw.WriteHeader(header); err != nil {
			return nil, internal.NewEncryptionError("failed to write tar header", err)
		}

		if _, err := io.Copy(tw, file.Content); err != nil {
			return nil, internal.NewEncryptionError("failed to write tar file content", err)
		}
	}

	if err := tw.Close(); err != nil {
		return nil, internal.NewEncryptionError("failed to close tar writer", err)
	}

	return buf.Bytes(), nil
}

// compressGzip compresses data with gzip
func compressGzip(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)

	if _, err := gz.Write(data); err != nil {
		return nil, internal.NewEncryptionError("failed to write to gzip", err)
	}

	if err := gz.Close(); err != nil {
		return nil, internal.NewEncryptionError("failed to close gzip writer", err)
	}

	return buf.Bytes(), nil
}

// DataFile represents a file to be encrypted in CDOC2
type DataFile struct {
	Name     string
	Content  io.Reader
	Size     int64
	MimeType string
}
