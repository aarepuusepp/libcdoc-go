package cdoc

import (
	"io"
	"strings"

	"github.com/aarepuusepp/libcdoc-go/v2/internal"
)

// LibraryVersion is the version of this library
const LibraryVersion = "2.0.0"

// Version represents CDOC format version
type Version string

const (
	// Version10 represents CDOC 1.0
	Version10 Version = "1.0"
	// Version11 represents CDOC 1.1
	Version11 Version = "1.1"
	// Version20 represents CDOC 2.0
	Version20 Version = "2.0"
)

// AlgorithmURI represents encryption algorithm URIs
type AlgorithmURI string

const (
	// URI_AES128CBC is AES-128-CBC (CDOC 1.0)
	URI_AES128CBC AlgorithmURI = "http://www.w3.org/2001/04/xmlenc#aes128-cbc"
	// URI_AES256GCM is AES-256-GCM (CDOC 1.1)
	URI_AES256GCM AlgorithmURI = "http://www.w3.org/2009/xmlenc11#aes256-gcm"
	// URI_RSA15 is RSA PKCS#1 v1.5
	URI_RSA15 AlgorithmURI = "http://www.w3.org/2001/04/xmlenc#rsa-1_5"
	// URI_AES256KW is AES Key Wrap 256
	URI_AES256KW AlgorithmURI = "http://www.w3.org/2001/04/xmlenc#kw-aes256"
)

// DetectVersion detects CDOC version from EncryptionMethod URI
func DetectVersion(algorithmURI string) Version {
	switch AlgorithmURI(algorithmURI) {
	case URI_AES256GCM:
		return Version11
	case URI_AES128CBC:
		return Version10
	default:
		// Default to 1.0 for backward compatibility
		return Version10
	}
}

// IsCDOC11 returns true if the algorithm URI indicates CDOC 1.1
func IsCDOC11(algorithmURI string) bool {
	return DetectVersion(algorithmURI) == Version11
}

// CDOC2MagicLabel is the magic label for CDOC2 files
const CDOC2MagicLabel = "CDOC\x02"

// DetectCDOC2 detects if a reader contains a CDOC2 file by checking the magic label
// It reads the first 5 bytes and checks if they match "CDOC\x02"
// The reader must be a ReaderAt or support seeking to position 0
func DetectCDOC2(reader io.ReaderAt) (bool, error) {
	magic := make([]byte, len(CDOC2MagicLabel))
	n, err := reader.ReadAt(magic, 0)
	if err != nil && err != io.EOF {
		return false, err
	}
	if n < len(CDOC2MagicLabel) {
		return false, nil
	}
	return string(magic) == CDOC2MagicLabel, nil
}

// DetectFileVersion detects the CDOC version from a file
// It first checks for CDOC2 magic label, then attempts to parse as CDOC 1.x XML
// Returns the version or an error if the file is not a valid CDOC file
func DetectFileVersion(reader io.ReaderAt) (Version, error) {
	// First check for CDOC2
	isCDOC2, err := DetectCDOC2(reader)
	if err != nil {
		return "", err
	}
	if isCDOC2 {
		return Version20, nil
	}

	// Try to detect CDOC 1.x by reading and checking for XML signature
	// Read first few bytes to check for XML declaration or <EncryptedData
	buf := make([]byte, 128)
	n, err := reader.ReadAt(buf, 0)
	if err != nil && err != io.EOF {
		return "", err
	}
	if n < 5 {
		return "", internal.NewParseError("file too short to be a valid CDOC file", nil)
	}

	content := string(buf[:n])
	// Check for XML declaration or EncryptedData element
	if strings.Contains(content, "<?xml") || strings.Contains(content, "<EncryptedData") {
		// This is likely CDOC 1.x, but we can't determine 1.0 vs 1.1 without full parsing
		// Return a default that will be refined during parsing
		return Version10, nil
	}

	return "", internal.NewParseError("file does not appear to be a valid CDOC file", nil)
}
