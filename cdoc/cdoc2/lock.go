package cdoc2

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"

	"github.com/aarepuusepp/libcdoc-go/v2/internal"
)

// LockType represents the type of lock/recipient
type LockType int

const (
	LockTypeUnknown      LockType = iota
	LockTypePublicKey             // RSA or ECC public key
	LockTypeServer                // Key server (Smart-ID/Mobile-ID)
	LockTypeSymmetricKey          // Symmetric key
	LockTypePassword              // Password-based (PBKDF2)
	LockTypeKeyShares             // Smart-ID / Mobile-ID key shares
)

// PKType represents the public key type
type PKType int

const (
	PKTypeUnknown PKType = iota
	PKTypeRSA
	PKTypeECC
)

// Lock represents a recipient lock in CDOC2
type Lock struct {
	Type         LockType
	PKType       PKType
	Label        string
	EncryptedFMK []byte

	// For PUBLIC_KEY and SERVER types
	RecipientKey  []byte // Public key (RSA or ECC)
	KeyMaterial   []byte // Encrypted KEK (RSA) or ephemeral public key (ECC)
	ServerID      string // For SERVER type
	TransactionID string // For SERVER type

	// For SYMMETRIC_KEY type
	Salt []byte

	// For PASSWORD type
	PasswordSalt []byte
	KDFIter      int32 // PBKDF2 iterations

	// For KEY_SHARES type
	KeyShares   []KeyShare
	SharesSalt  []byte
	RecipientID string

	// For certificate matching
	Certificate *x509.Certificate
}

// Capsule concrete types for parsed header mapping
type RSAPublicKeyCapsule struct {
	RecipientPublicKey []byte
	EncryptedKEK       []byte
}

func (RSAPublicKeyCapsule) Type() string { return "RSA" }

type ECCPublicKeyCapsule struct {
	RecipientPublicKey []byte
	SenderPublicKey    []byte
}

func (ECCPublicKeyCapsule) Type() string { return "ECC" }

type SymmetricKeyCapsule struct {
	Salt []byte
}

func (SymmetricKeyCapsule) Type() string { return "SYMMETRIC" }

type PBKDF2Capsule struct {
	Salt         []byte
	PasswordSalt []byte
	Iterations   int32
}

func (PBKDF2Capsule) Type() string { return "PBKDF2" }

type KeyServerCapsule struct {
	RecipientKey  []byte
	PKType        PKType
	KeyServerID   string
	TransactionID string
}

func (KeyServerCapsule) Type() string { return "KEYSERVER" }

type KeyShare struct {
	URL           string
	TransactionID string
}

type KeySharesCapsule struct {
	Shares        []KeyShare
	Salt          []byte
	RecipientType byte
	Scheme        byte
	RecipientID   string
}

func (KeySharesCapsule) Type() string { return "KEYSHARES" }

// HasSameKey checks if the lock's recipient key matches the provided public key
func (l *Lock) HasSameKey(otherKey []byte) bool {
	if len(l.RecipientKey) != len(otherKey) {
		return false
	}
	for i := range l.RecipientKey {
		if l.RecipientKey[i] != otherKey[i] {
			return false
		}
	}
	return true
}

// MatchesCertificate checks if the lock matches the given certificate
func (l *Lock) MatchesCertificate(cert *x509.Certificate) (bool, error) {
	if cert == nil {
		return false, nil
	}

	certKey, err := extractPublicKeyBytesForLock(l, cert)
	if err != nil {
		return false, err
	}

	return l.HasSameKey(certKey), nil
}

func extractPublicKeyBytesForLock(l *Lock, cert *x509.Certificate) ([]byte, error) {
	switch pubKey := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if l != nil && l.Type == LockTypePublicKey && l.PKType == PKTypeECC {
			return cert.RawSubjectPublicKeyInfo, nil
		}
		enc, err := EncodeECKeyServerRecipient(pubKey)
		if err != nil {
			return nil, internal.NewParseError(err.Error(), err)
		}
		return enc.TLSPoint, nil
	default:
		if _, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			return cert.RawSubjectPublicKeyInfo, nil
		}
		return nil, internal.NewParseError(
			"unsupported public key type",
			nil,
		)
	}
}

// IsRSA returns true if the lock uses RSA public key
func (l *Lock) IsRSA() bool {
	return l.Type == LockTypePublicKey && l.PKType == PKTypeRSA
}

// IsECC returns true if the lock uses ECC public key
func (l *Lock) IsECC() bool {
	return l.Type == LockTypePublicKey && l.PKType == PKTypeECC
}
