package cdoc2

// CDOC2 constants based on libcdoc CDoc2.h

const (
	// Label is the magic label for CDOC2 files (5 bytes: "CDOC\x02")
	Label = "CDOC\x02"

	// CEK is the label used for Content Encryption Key derivation via HKDF
	CEK = "CDOC20cek"

	// HMAC is the label used for HMAC key derivation via HKDF
	HMAC = "CDOC20hmac"

	// KEK is the label used for Key Encryption Key derivation via HKDF
	KEK = "CDOC20kek"

	// KEKPREMASTER is the label used for KEK premaster key derivation via HKDF
	KEKPREMASTER = "CDOC20kekpremaster"

	// PAYLOAD is the label used in AAD for payload encryption
	PAYLOAD = "CDOC20payload"

	// SALT is the label used for salt in HKDF extract operations
	SALT = "CDOC20salt"

	// KeyLen is the length of keys in bytes (32 bytes = 256 bits)
	KeyLen = 32

	// NonceLen is the length of nonces in bytes (12 bytes for ChaCha20-Poly1305)
	NonceLen = 12

	// KeyLabelVersion is the version of key label format
	KeyLabelVersion = 1
)
