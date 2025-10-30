package key

// PKCS11Config holds configuration for PKCS#11 token operations
type PKCS11Config struct {
	// Library is the path to the PKCS#11 library (e.g., /usr/lib/pkcs11/libpkcs11.so)
	Library string

	// Slot is the slot number (default: 0)
	Slot int

	// PIN is the token PIN/password
	PIN string

	// Label is an optional key label to find specific keys on the token
	Label string

	// KeyID is an optional key ID (bytes) to find specific keys on the token
	KeyID []byte
}

// Validate validates the PKCS11Config
func (c *PKCS11Config) Validate() error {
	if c.Library == "" {
		return NewPKCS11Error("PKCS#11 library path is required", nil)
	}

	if c.PIN == "" {
		return NewPKCS11Error("PIN is required", nil)
	}

	if c.Slot < 0 {
		return NewPKCS11Error("slot number must be non-negative", nil)
	}

	return nil
}

