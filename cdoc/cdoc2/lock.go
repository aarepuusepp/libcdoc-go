package cdoc2

import (
	"crypto/ecdsa"
    "crypto/rsa"
	"crypto/x509"
	"fmt"

	"github.com/aarepuusepp/libcdoc-go/v2/internal"
)

// LockType represents the type of lock/recipient
type LockType int

const (
	LockTypeUnknown LockType = iota
	LockTypePublicKey      // RSA or ECC public key
	LockTypeServer         // Key server (Smart-ID/Mobile-ID)
	LockTypeSymmetricKey   // Symmetric key
	LockTypePassword       // Password-based (PBKDF2)
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
	RecipientKey    []byte // Public key (RSA or ECC)
	KeyMaterial     []byte // Encrypted KEK (RSA) or ephemeral public key (ECC)
	ServerID        string // For SERVER type
	TransactionID   string // For SERVER type

	// For SYMMETRIC_KEY type
	Salt []byte

	// For PASSWORD type
	PasswordSalt []byte
	KDFIter      int32 // PBKDF2 iterations

	// For certificate matching
	Certificate *x509.Certificate // Optional: parsed certificate for matching
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
    URL          string
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

	// Try to extract public key from certificate and compare
	certKey, err := extractPublicKeyBytes(cert)
	if err != nil {
		return false, err
	}

	return l.HasSameKey(certKey), nil
}

// extractPublicKeyBytes extracts the public key bytes from a certificate
// For RSA: DER-encoded public key
// For ECC: TLS 1.3 format (0x04 + X + Y coordinates)
func extractPublicKeyBytes(cert *x509.Certificate) ([]byte, error) {
	switch pubKey := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		// ECC: TLS 1.3 format - 0x04 prefix + X (48 bytes) + Y (48 bytes) for secp384r1
		if pubKey.Curve.Params().BitSize != 384 {
			return nil, internal.NewParseError(
				fmt.Sprintf("unsupported curve bit size: %d (only secp384r1 supported)", pubKey.Curve.Params().BitSize),
				nil,
			)
		}
		
		keySize := 48 // secp384r1 coordinate size
		result := make([]byte, 1+keySize*2)
		result[0] = 0x04 // Uncompressed point format
		
		// Convert X and Y to bytes (big-endian, padded to keySize)
		xBytes := pubKey.X.Bytes()
		yBytes := pubKey.Y.Bytes()
		
		copy(result[1+keySize-len(xBytes):1+keySize], xBytes)
		copy(result[1+keySize*2-len(yBytes):1+keySize*2], yBytes)
		
		return result, nil
	default:
        // RSA: return SubjectPublicKeyInfo DER bytes
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

