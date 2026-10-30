package cdoc2

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"

	xpbkdf2 "golang.org/x/crypto/pbkdf2"

	"github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2/keyserver"
	"github.com/aarepuusepp/libcdoc-go/v2/crypto"
	"github.com/aarepuusepp/libcdoc-go/v2/internal"
)

// Ensure keyserver package is available for KeyServerAction types
var _ = keyserver.Client{}

// PKCS11TokenInterface is a minimal interface for PKCS#11 token operations needed by CDOC2
// This avoids circular imports (cdoc2 cannot import cdoc package)
type PKCS11TokenInterface interface {
	// DecryptRSA decrypts RSA-encrypted data using the PKCS#11 token
	DecryptRSA(encryptedKey []byte) ([]byte, error)
	// DecryptECSharedSecret performs ECDH key agreement and returns the shared secret
	// For CDOC2, we only need the shared secret (not the full transport key unwrapping like CDOC 1.x)
	DecryptECSharedSecret(ephemeralPublicKey *ecdsa.PublicKey) ([]byte, error)
}

// ExtractFMKFromLock extracts the File Master Key (FMK) from a lock
// This handles RSA, ECC, Symmetric Key, Password, and Key Server recipients.
// For Symmetric: symmetricKey must be provided. For Password: password must be provided.
// For Key Server: action must be a *KeyServerAction (defined in reader.go)
// For PKCS#11: pkcs11Token must be a PKCS11TokenInterface (e.g., *PKCS11Token)
func ExtractFMKFromLock(lock Lock, privateKey interface{}, symmetricKey []byte, password string, action *KeyServerAction, pkcs11Token PKCS11TokenInterface) ([]byte, error) {
	return ExtractFMKFromLockWithShares(lock, privateKey, symmetricKey, password, action, nil, pkcs11Token)
}

// ExtractFMKFromLockWithShares additionally supports supplied N-of-N key shares.
func ExtractFMKFromLockWithShares(lock Lock, privateKey interface{}, symmetricKey []byte, password string, action *KeyServerAction, sharesAction *KeySharesAction, pkcs11Token PKCS11TokenInterface) ([]byte, error) {
	var kek []byte
	var err error

	switch lock.Type {
	case LockTypePublicKey:
		if lock.IsRSA() {
			// RSA: KEK is encrypted with recipient public key
			if pkcs11Token != nil {
				// Use PKCS#11 token to decrypt KEK
				kek, err = pkcs11Token.DecryptRSA(lock.KeyMaterial)
				if err != nil {
					return nil, internal.NewDecryptionError("failed to decrypt RSA KEK with PKCS#11 token", err)
				}
			} else {
				rsaKey, ok := privateKey.(*rsa.PrivateKey)
				if !ok {
					return nil, internal.NewDecryptionError("private key is not RSA", nil)
				}
				kek, err = crypto.DecryptRSA(lock.KeyMaterial, rsaKey)
				if err != nil {
					return nil, internal.NewDecryptionError("failed to decrypt RSA KEK", err)
				}
			}
		} else if lock.IsECC() {
			// ECC: ECDH(recipient_priv, sender_pub) => sharedSecret
			// Sender public key is DER-encoded SubjectPublicKeyInfo
			pubAny, err := x509.ParsePKIXPublicKey(lock.KeyMaterial)
			if err != nil {
				return nil, internal.NewDecryptionError("invalid ECC sender public key", err)
			}
			ecPub, ok := pubAny.(*ecdsa.PublicKey)
			if !ok {
				return nil, internal.NewDecryptionError("sender public key is not ECC", nil)
			}

			var sharedSecret []byte
			if pkcs11Token != nil {
				// Use PKCS#11 token for ECDH key agreement
				// For CDOC2, we only need the shared secret (not full transport key like CDOC 1.x)
				// Note: This may not work with all tokens - see PKCS11_EC_LIMITATION.md
				sharedSecret, err = pkcs11Token.DecryptECSharedSecret(ecPub)
				if err != nil {
					return nil, internal.NewDecryptionError("failed ECDH key agreement with PKCS#11 token (may require token-specific implementation)", err)
				}
			} else {
				ecPriv, ok := privateKey.(*ecdsa.PrivateKey)
				if !ok {
					return nil, internal.NewDecryptionError("private key is not ECC", nil)
				}
				sharedSecret, err = crypto.ECDHKeyAgreement(ecPriv, ecPub)
				if err != nil {
					return nil, err
				}
			}

			// kek_pm = HKDF-Extract-SHA512(KEKPREMASTER, sharedSecret)
			kekPm := crypto.HKDFExtractSHA512([]byte(KEKPREMASTER), sharedSecret)
			// info = KEK + "XOR" + recipient_key + key_material
			info := []byte(GetSaltForExpandWithKeyMaterial(lock.RecipientKey, lock.KeyMaterial))
			kek, err = crypto.HKDFExpandSHA512(kekPm, info, KeyLen)
			if err != nil {
				return nil, internal.NewDecryptionError("failed to derive ECC KEK", err)
			}
		} else {
			return nil, internal.NewDecryptionError("unsupported public key type", nil)
		}

	case LockTypeSymmetricKey:
		// Symmetric key: kek_pm = HKDF-Extract(SALT, symmetricKey); kek = HKDF-Expand(kek_pm, info, 32)
		if len(symmetricKey) == 0 {
			return nil, internal.NewDecryptionError("symmetric key required for symmetric lock type", nil)
		}
		info := []byte(GetSaltForExpand(lock.Label))
		kekPm := crypto.HKDFExtract(lock.Salt, symmetricKey)
		kek, err = crypto.HKDFExpand(kekPm, info, KeyLen)
		if err != nil {
			return nil, internal.NewDecryptionError("failed to derive KEK from symmetric key", err)
		}

	case LockTypePassword:
		if password == "" {
			return nil, internal.NewDecryptionError("password required for password lock type", nil)
		}
		// PBKDF2(password, password_salt, iterations) -> kek_pm
		kekPm := xpbkdf2.Key([]byte(password), lock.PasswordSalt, int(lock.KDFIter), KeyLen, sha256.New)
		// Then HKDF-Extract(salt, kek_pm) -> kek_pm2
		kekPm2 := crypto.HKDFExtract(lock.Salt, kekPm)
		// Then HKDF-Expand(kek_pm2, info, 32) -> kek
		info := []byte(GetSaltForExpand(lock.Label))
		kek, err = crypto.HKDFExpand(kekPm2, info, KeyLen)
		if err != nil {
			return nil, internal.NewDecryptionError("failed to derive KEK from password", err)
		}

	case LockTypeServer:
		// Key server: requires network interaction
		if action == nil || action.KeyServerClient == nil {
			return nil, internal.NewDecryptionError("key server client not provided", nil)
		}
		if action.KeyServerConfig.FetchURL == "" {
			return nil, internal.NewDecryptionError("key server fetch URL not configured", nil)
		}

		// Fetch key material from key server using transaction ID
		keyMaterial, err := action.KeyServerClient.FetchKeyWithContext(context.Background(), action.KeyServerConfig, lock.TransactionID)
		if err != nil {
			return nil, internal.NewDecryptionError("failed to fetch key from key server", err)
		}

		// Use the fetched key material based on lock PKType (same logic as PUBLIC_KEY)
		switch lock.PKType {
		case PKTypeRSA:
			// RSA: key material is encrypted KEK
			rsaKey, ok := privateKey.(*rsa.PrivateKey)
			if !ok {
				return nil, internal.NewDecryptionError("private key is not RSA", nil)
			}
			kek, err = crypto.DecryptRSA(keyMaterial, rsaKey)
			if err != nil {
				return nil, internal.NewDecryptionError("failed to decrypt KEK from key server", err)
			}
		case PKTypeECC:
			// ECC: key material is sender public key (ephemeral)
			ecPriv, ok := privateKey.(*ecdsa.PrivateKey)
			if !ok {
				return nil, internal.NewDecryptionError("private key is not ECC", nil)
			}
			// keyMaterial is DER-encoded SubjectPublicKeyInfo (sender public key)
			pubAny, err := x509.ParsePKIXPublicKey(keyMaterial)
			if err != nil {
				return nil, internal.NewDecryptionError("invalid ECC sender public key from key server", err)
			}
			ecPub, ok := pubAny.(*ecdsa.PublicKey)
			if !ok {
				return nil, internal.NewDecryptionError("sender public key from key server is not ECC", nil)
			}
			sharedSecret, err := crypto.ECDHKeyAgreement(ecPriv, ecPub)
			if err != nil {
				return nil, err
			}
			// kek_pm = HKDF-Extract-SHA512(KEKPREMASTER, sharedSecret)
			kekPm := crypto.HKDFExtractSHA512([]byte(KEKPREMASTER), sharedSecret)
			// info = KEK + "XOR" + recipient_key + key_material
			info := []byte(GetSaltForExpandWithKeyMaterial(lock.RecipientKey, keyMaterial))
			kek, err = crypto.HKDFExpandSHA512(kekPm, info, KeyLen)
			if err != nil {
				return nil, internal.NewDecryptionError("failed to derive ECC KEK from key server", err)
			}
		default:
			return nil, internal.NewDecryptionError("unsupported key type for key server", nil)
		}

	case LockTypeKeyShares:
		if sharesAction == nil || len(sharesAction.ShareBytes) != sharesAction.MinRequired {
			return nil, internal.NewDecryptionError("key shares not provided (N-of-N requires all shares)", nil)
		}
		kek, err = DeriveKEKFromKeyShares(lock.SharesSalt, lock.RecipientID, sharesAction.ShareBytes, sharesAction.MinRequired)
		if err != nil {
			return nil, err
		}

	default:
		return nil, internal.NewDecryptionError("unsupported lock type", nil)
	}

	if len(kek) != KeyLen {
		return nil, internal.NewDecryptionError("KEK must be 32 bytes", nil)
	}

	fmk := XOREncrypt(lock.EncryptedFMK, kek)
	for i := range kek {
		kek[i] = 0
	}
	return fmk, nil
}
