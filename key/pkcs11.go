package key

import (
	"crypto/ecdsa"
	"crypto/x509"

	"github.com/miekg/pkcs11"
	"github.com/yourorg/cdoc1-go/cert"
)

// PKCS11Context wraps PKCS#11 operations
type PKCS11Context struct {
	ctx      *pkcs11.Ctx
	config   PKCS11Config
	session  pkcs11.SessionHandle
	loggedIn bool
}

// NewPKCS11Context creates a new PKCS#11 context and initializes the session
func NewPKCS11Context(config PKCS11Config) (*PKCS11Context, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	ctx := pkcs11.New(config.Library)
	if ctx == nil {
		return nil, NewPKCS11Error("failed to initialize PKCS#11 context", nil)
	}

	err := ctx.Initialize()
	if err != nil {
		return nil, NewPKCS11Error("failed to initialize PKCS#11 library", err)
	}

	// Find slot
	slots, err := ctx.GetSlotList(true) // true = only slots with tokens
	if err != nil {
		ctx.Finalize()
		return nil, NewPKCS11Error("failed to get slot list", err)
	}

	if len(slots) == 0 {
		ctx.Finalize()
		return nil, NewPKCS11Error("no slots with tokens found", nil)
	}

	// Use configured slot or first available
	slot := uint(config.Slot)
	if config.Slot >= len(slots) {
		slot = slots[0]
	} else {
		slot = slots[config.Slot]
	}

	// Open session
	session, err := ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		ctx.Finalize()
		return nil, NewPKCS11Error("failed to open PKCS#11 session", err)
	}

	// Login
	err = ctx.Login(session, pkcs11.CKU_USER, config.PIN)
	if err != nil {
		ctx.CloseSession(session)
		ctx.Finalize()
		return nil, NewPKCS11Error("failed to login to PKCS#11 token", err)
	}

	return &PKCS11Context{
		ctx:      ctx,
		config:   config,
		session:  session,
		loggedIn: true,
	}, nil
}

// Close closes the PKCS#11 session and finalizes the context
func (c *PKCS11Context) Close() error {
	var firstErr error

	if c.loggedIn && c.ctx != nil {
		if err := c.ctx.Logout(c.session); err != nil {
			firstErr = err
		}
		c.loggedIn = false
	}

	if c.session != 0 && c.ctx != nil {
		if err := c.ctx.CloseSession(c.session); err != nil && firstErr == nil {
			firstErr = err
		}
		c.session = 0
	}

	if c.ctx != nil {
		if err := c.ctx.Finalize(); err != nil && firstErr == nil {
			firstErr = err
		}
		c.ctx = nil
	}

	if firstErr != nil {
		return NewPKCS11Error("error closing PKCS#11 context", firstErr)
	}

	return nil
}

// FindPrivateKey finds a private key on the token
func (c *PKCS11Context) FindPrivateKey(label string, keyID []byte) (pkcs11.ObjectHandle, error) {
	attributes := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
	}

	// Add label filter if provided
	if label != "" {
		attributes = append(attributes, pkcs11.NewAttribute(pkcs11.CKA_LABEL, label))
	}

	// Add key ID filter if provided
	if len(keyID) > 0 {
		attributes = append(attributes, pkcs11.NewAttribute(pkcs11.CKA_ID, keyID))
	}

	// Start finding objects
	err := c.ctx.FindObjectsInit(c.session, attributes)
	if err != nil {
		return 0, NewPKCS11Error("failed to initialize key search", err)
	}
	defer c.ctx.FindObjectsFinal(c.session)

	// Get first matching key
	objects, _, err := c.ctx.FindObjects(c.session, 1)
	if err != nil {
		return 0, NewPKCS11Error("failed to find private key", err)
	}

	if len(objects) == 0 {
		return 0, NewPKCS11Error("no private key found on token", nil)
	}

	return objects[0], nil
}

// FindCertificate finds a certificate on the token
func (c *PKCS11Context) FindCertificate(label string, keyID []byte) (*x509.Certificate, error) {
	attributes := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
	}

	// Add label filter if provided
	if label != "" {
		attributes = append(attributes, pkcs11.NewAttribute(pkcs11.CKA_LABEL, label))
	}

	// Add key ID filter if provided
	if len(keyID) > 0 {
		attributes = append(attributes, pkcs11.NewAttribute(pkcs11.CKA_ID, keyID))
	}

	// Start finding objects
	err := c.ctx.FindObjectsInit(c.session, attributes)
	if err != nil {
		return nil, NewPKCS11Error("failed to initialize certificate search", err)
	}
	defer c.ctx.FindObjectsFinal(c.session)

	// Get first matching certificate
	objects, _, err := c.ctx.FindObjects(c.session, 1)
	if err != nil {
		return nil, NewPKCS11Error("failed to find certificate", err)
	}

	if len(objects) == 0 {
		return nil, NewPKCS11Error("no certificate found on token", nil)
	}

	certHandle := objects[0]

	// Get certificate value
	certTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
	}
	attributes, err = c.ctx.GetAttributeValue(c.session, certHandle, certTemplate)
	if err != nil {
		return nil, NewPKCS11Error("failed to get certificate value", err)
	}

	var certBytes []byte
	for _, attr := range attributes {
		if attr.Type == pkcs11.CKA_VALUE {
			certBytes = attr.Value
			break
		}
	}

	if certBytes == nil {
		return nil, NewPKCS11Error("certificate value not found", nil)
	}

	// Parse certificate
	certificate, err := cert.ParseCertificate(certBytes)
	if err != nil {
		return nil, NewPKCS11Error("failed to parse certificate", err)
	}

	return certificate, nil
}

// DecryptRSA decrypts data using an RSA private key on the token
func (c *PKCS11Context) DecryptRSA(keyHandle pkcs11.ObjectHandle, encryptedData []byte) ([]byte, error) {
	// Use PKCS#11 C_Decrypt operation
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}

	err := c.ctx.DecryptInit(c.session, mech, keyHandle)
	if err != nil {
		return nil, NewPKCS11Error("failed to initialize RSA decryption", err)
	}

	decrypted, err := c.ctx.Decrypt(c.session, encryptedData)
	if err != nil {
		return nil, NewPKCS11Error("failed to decrypt with RSA key", err)
	}

	return decrypted, nil
}

// DecryptEC performs ECDH key agreement and derives a key for EC decryption
// Note: PKCS#11 ECDH key derivation is complex. For now, we'll extract the private key
// and perform the key agreement in software. This is a limitation, but many tokens
// don't support C_DeriveKey for ECDH properly.
func (c *PKCS11Context) DecryptEC(keyHandle pkcs11.ObjectHandle, ephemeralPublicKey *ecdsa.PublicKey) ([]byte, error) {
	// EC decryption via PKCS#11 is complex and varies by token implementation
	// Some tokens don't allow reading private key values directly
	// ECDH key derivation should use C_DeriveKey, but implementation varies
	// For now, return an error indicating EC support needs token-specific implementation

	// Verify this is an EC key
	attributes := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
	}

	attrs, err := c.ctx.GetAttributeValue(c.session, keyHandle, attributes)
	if err != nil {
		return nil, NewPKCS11Error("failed to get EC key type", err)
	}

	var keyType uint
	for _, attr := range attrs {
		if attr.Type == pkcs11.CKA_KEY_TYPE && len(attr.Value) >= 4 {
			keyType = uint(attr.Value[0]) | uint(attr.Value[1])<<8 | uint(attr.Value[2])<<16 | uint(attr.Value[3])<<24
			break
		}
	}

	if keyType != pkcs11.CKK_EC {
		return nil, NewPKCS11Error("key is not an EC key", nil)
	}

	// Return error indicating EC support needs token-specific implementation
	return nil, NewPKCS11Error(
		"EC key agreement via PKCS#11 requires token-specific implementation. "+
			"Consider using software key extraction if token allows, or implement C_DeriveKey-based ECDH",
		nil,
	)
}

