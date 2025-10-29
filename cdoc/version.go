package cdoc

// Version represents CDOC format version
type Version string

const (
	// Version10 represents CDOC 1.0
	Version10 Version = "1.0"
	// Version11 represents CDOC 1.1
	Version11 Version = "1.1"
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
