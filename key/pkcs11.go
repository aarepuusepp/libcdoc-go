//go:build cgo
// +build cgo

package key

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"

	"github.com/aarepuusepp/libcdoc-go/v2/cert"
	"github.com/miekg/pkcs11"
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
		_ = ctx.Finalize()
		return nil, NewPKCS11Error("failed to get slot list", err)
	}

	if len(slots) == 0 {
		_ = ctx.Finalize()
		return nil, NewPKCS11Error("no slots with tokens found", nil)
	}

	// Use configured slot or first available
	var slot uint
	if config.Slot >= len(slots) {
		slot = slots[0]
	} else {
		slot = slots[config.Slot]
	}

	// Open session
	session, err := ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		_ = ctx.Finalize()
		return nil, NewPKCS11Error("failed to open PKCS#11 session", err)
	}

	// Login
	err = ctx.Login(session, pkcs11.CKU_USER, config.PIN)
	if err != nil {
		_ = ctx.CloseSession(session)
		_ = ctx.Finalize()
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
	// Get first matching key
	objects, _, err := c.ctx.FindObjects(c.session, 1)
	finalErr := c.ctx.FindObjectsFinal(c.session)
	if err != nil {
		return 0, NewPKCS11Error("failed to find private key", err)
	}
	if finalErr != nil {
		return 0, NewPKCS11Error("failed to finalize private key search", finalErr)
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
	// Get first matching certificate
	objects, _, err := c.ctx.FindObjects(c.session, 1)
	finalErr := c.ctx.FindObjectsFinal(c.session)
	if err != nil {
		return nil, NewPKCS11Error("failed to find certificate", err)
	}
	if finalErr != nil {
		return nil, NewPKCS11Error("failed to finalize certificate search", finalErr)
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

// FindMatchedKeyPair locates the certificate equal to recipient and its paired private key via CKA_ID.
func (c *PKCS11Context) FindMatchedKeyPair(recipient *x509.Certificate) (pkcs11.ObjectHandle, *x509.Certificate, error) {
	if recipient == nil {
		return 0, nil, NewPKCS11Error("recipient certificate is required", nil)
	}

	certs, err := c.listTokenCertificates()
	if err != nil {
		return 0, nil, err
	}

	for _, entry := range certs {
		if !bytesEqual(entry.cert.Raw, recipient.Raw) {
			continue
		}
		keyHandle, err := c.findPrivateKeyByID(entry.keyID)
		if err != nil {
			return 0, nil, err
		}
		return keyHandle, entry.cert, nil
	}

	return 0, nil, NewPKCS11Error("no matching certificate and private key found on token", nil)
}

type tokenCertificate struct {
	cert  *x509.Certificate
	keyID []byte
}

func (c *PKCS11Context) listTokenCertificates() ([]tokenCertificate, error) {
	attributes := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
	}

	if err := c.ctx.FindObjectsInit(c.session, attributes); err != nil {
		return nil, NewPKCS11Error("failed to initialize certificate search", err)
	}
	defer func() { _ = c.ctx.FindObjectsFinal(c.session) }()

	var out []tokenCertificate
	for {
		objects, _, err := c.ctx.FindObjects(c.session, 16)
		if err != nil {
			return nil, NewPKCS11Error("failed to find certificates", err)
		}
		if len(objects) == 0 {
			break
		}
		for _, handle := range objects {
			attrs, err := c.ctx.GetAttributeValue(c.session, handle, []*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
				pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
			})
			if err != nil {
				continue
			}
			var certBytes, keyID []byte
			for _, attr := range attrs {
				switch attr.Type {
				case pkcs11.CKA_VALUE:
					certBytes = attr.Value
				case pkcs11.CKA_ID:
					keyID = append([]byte(nil), attr.Value...)
				}
			}
			if len(certBytes) == 0 {
				continue
			}
			certificate, err := cert.ParseCertificate(certBytes)
			if err != nil {
				continue
			}
			out = append(out, tokenCertificate{cert: certificate, keyID: keyID})
		}
	}
	return out, nil
}

func (c *PKCS11Context) findPrivateKeyByID(keyID []byte) (pkcs11.ObjectHandle, error) {
	if len(keyID) == 0 {
		return 0, NewPKCS11Error("matching certificate has no CKA_ID", nil)
	}
	attributes := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
	}
	if len(keyID) > 0 {
		attributes = append(attributes, pkcs11.NewAttribute(pkcs11.CKA_ID, keyID))
	}

	if err := c.ctx.FindObjectsInit(c.session, attributes); err != nil {
		return 0, NewPKCS11Error("failed to initialize private key search", err)
	}
	objects, _, err := c.ctx.FindObjects(c.session, 2)
	finalErr := c.ctx.FindObjectsFinal(c.session)
	if err != nil {
		return 0, NewPKCS11Error("failed to find private key", err)
	}
	if finalErr != nil {
		return 0, NewPKCS11Error("failed to finalize private key search", finalErr)
	}
	if len(objects) != 1 {
		return 0, NewPKCS11Error("expected exactly one private key for certificate CKA_ID", nil)
	}
	return objects[0], nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
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
// The private key stays on the token; only the derived session secret is exported.
func (c *PKCS11Context) DecryptEC(keyHandle pkcs11.ObjectHandle, ephemeralPublicKey *ecdsa.PublicKey) ([]byte, error) {
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

	publicPoint, secretLen, err := encodeECDHPublicPoint(ephemeralPublicKey)
	if err != nil {
		return nil, err
	}

	params := pkcs11.NewECDH1DeriveParams(pkcs11.CKD_NULL, nil, publicPoint)
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDH1_DERIVE, params)}
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_GENERIC_SECRET),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, false),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, secretLen),
	}

	derivedHandle, err := c.ctx.DeriveKey(c.session, mech, keyHandle, template)
	if err != nil {
		return nil, NewPKCS11Error("failed to derive EC shared secret", err)
	}
	defer func() { _ = c.ctx.DestroyObject(c.session, derivedHandle) }()

	derivedAttrs, err := c.ctx.GetAttributeValue(c.session, derivedHandle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
	})
	if err != nil {
		return nil, NewPKCS11Error("failed to read derived EC shared secret", err)
	}
	if len(derivedAttrs) == 0 || len(derivedAttrs[0].Value) == 0 {
		return nil, NewPKCS11Error("derived EC shared secret is empty", nil)
	}

	defer clear(derivedAttrs[0].Value)
	return leftPadSecret(derivedAttrs[0].Value, secretLen), nil
}

func encodeECDHPublicPoint(pub *ecdsa.PublicKey) ([]byte, int, error) {
	if pub == nil || pub.Curve == nil || pub.X == nil || pub.Y == nil {
		return nil, 0, NewPKCS11Error("EC peer public key is incomplete", nil)
	}
	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return nil, 0, NewPKCS11Error("EC peer public key is not on curve", nil)
	}
	secretLen := (pub.Curve.Params().BitSize + 7) / 8
	if secretLen <= 0 {
		return nil, 0, NewPKCS11Error("unsupported EC curve", nil)
	}
	return elliptic.Marshal(pub.Curve, pub.X, pub.Y), secretLen, nil
}

func leftPadSecret(secret []byte, size int) []byte {
	if len(secret) == size {
		out := make([]byte, len(secret))
		copy(out, secret)
		return out
	}
	if len(secret) > size {
		out := make([]byte, size)
		copy(out, secret[len(secret)-size:])
		return out
	}
	out := make([]byte, size)
	copy(out[size-len(secret):], secret)
	return out
}
