# PKCS#11 EC Support Limitation - Technical Explanation

## Overview

The PKCS#11 implementation in `cdoc1-go` currently **fully supports RSA decryption** but has **limited EC (Elliptic Curve) support**. This document explains the technical reasons why EC decryption via PKCS#11 is challenging and requires token-specific implementation.

## How CDOC EC Decryption Works (Software Implementation)

CDOC 1.1 EC recipient decryption follows this process:

```
1. Extract ephemeral public key from CDOC XML (sent by encryptor)
2. Perform ECDH key agreement:
   - Input: Private key (on token/HSM) + Ephemeral public key (from CDOC)
   - Output: Shared secret (X coordinate of elliptic curve point)
3. Derive wrap key via ConcatKDF:
   - Input: Shared secret + AlgorithmID + PartyUInfo + PartyVInfo
   - Output: 32-byte AES-256 key
4. Unwrap transport key using AES-KW-256:
   - Input: Wrapped key (from CDOC) + Wrap key (from step 3)
   - Output: Content encryption key (32-byte AES-256 key)
5. Decrypt content using AES-256-GCM
```

**Code Reference:**
```319:350:cdoc/decrypter.go
// decryptECTransportKey decrypts EC transport key
func (d *Decrypter) decryptECTransportKey(recipient *xmlenc.ECRecipient) ([]byte, error) {
	privKey, ok := d.privateKey.ECPrivateKey()
	if !ok {
		return nil, internal.NewDecryptionError("private key is not EC", nil)
	}

	// Perform ECDH key agreement
	sharedSecret, err := crypto.ECDHKeyAgreement(privKey, recipient.GetEphemeralPublicKey())
	if err != nil {
		return nil, internal.NewDecryptionError("failed ECDH key agreement", err)
	}

	// Derive wrap key via ConcatKDF
	wrapKey, err := crypto.ConcatKDF(
		sharedSecret,
		recipient.GetAlgorithmID(),
		recipient.GetPartyUInfo(),
		recipient.GetPartyVInfo(),
	)
	if err != nil {
		return nil, internal.NewDecryptionError("failed ConcatKDF", err)
	}

	// Unwrap transport key
	encryptedKey, err := recipient.GetEncryptedKey()
	if err != nil {
		return nil, internal.NewDecryptionError("failed to decode encrypted key", err)
	}

	return crypto.UnwrapAES256(encryptedKey, wrapKey)
}
```

**ECDH Key Agreement Implementation:**
```41:59:crypto/ec.go
// ECDHKeyAgreement performs ECDH key agreement and returns the shared secret
func ECDHKeyAgreement(privKey *ecdsa.PrivateKey, pubKey *ecdsa.PublicKey) ([]byte, error) {
	if privKey.Curve != pubKey.Curve {
		return nil, internal.NewEncryptionError(
			"private and public keys are on different curves",
			nil,
		)
	}

	// ECDH shared secret = private key * public key point
	x, _ := privKey.Curve.ScalarMult(pubKey.X, pubKey.Y, privKey.D.Bytes())

	// Convert shared point X coordinate to bytes
	sharedSecret := make([]byte, (privKey.Curve.Params().BitSize+7)/8)
	xBytes := x.Bytes()
	copy(sharedSecret[len(sharedSecret)-len(xBytes):], xBytes)

	return sharedSecret, nil
}
```

## Why RSA Works with PKCS#11

**RSA Decryption via PKCS#11 is straightforward:**

1. **Direct PKCS#11 Operation**: PKCS#11 provides `C_Decrypt` which performs RSA decryption directly on the token
2. **Standard Mechanism**: `CKM_RSA_PKCS` is universally supported
3. **Input/Output**: Encrypted data in → Decrypted data out (no complex key derivation needed)

**Code Reference:**
```214:231:key/pkcs11.go
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
```

**Why this works:**
- The RSA private key never leaves the token
- Decryption happens entirely on the HSM
- Result is the decrypted transport key (ready to use)

## Why EC is Challenging with PKCS#11

**EC decryption requires a multi-step process that PKCS#11 doesn't directly support:**

### Problem 1: No Direct "ECDH + ConcatKDF + AES-KW Unwrap" Operation

PKCS#11 provides these EC-related operations separately, but not in combination:

1. **`C_DeriveKey` with `CKM_ECDH1_DERIVE`**: Performs ECDH key agreement
   - **BUT**: Tokens vary in how they handle the output (shared secret)
   - **BUT**: Different tokens use different key derivation methods
   - **BUT**: ConcatKDF is not a standard PKCS#11 mechanism

2. **`C_UnwrapKey`**: Can unwrap keys using various mechanisms
   - **BUT**: Requires a pre-derived wrap key
   - **BUT**: AES-KW mechanism support varies

### Problem 2: Private Key Extraction Restrictions

**The software approach requires access to the private key value:**

```go
// Software ECDH needs: privKey.D (the private scalar)
x, _ := privKey.Curve.ScalarMult(pubKey.X, pubKey.Y, privKey.D.Bytes())
```

**With PKCS#11:**
- Many tokens **don't allow reading private key values** (security feature)
- Private keys are marked as `CKA_SENSITIVE = true` and `CKA_EXTRACTABLE = false`
- Attempting to read `CKA_VALUE` returns an error
- This is by design - HSM security is based on keys never leaving the device

**Code Reference:**
```232:270:key/pkcs11.go
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
```

### Problem 3: Token-Specific Variations

**Different HSMs handle EC key derivation differently:**

1. **Utimaco HSMs**:
   - Support `CKM_ECDH1_DERIVE` but may require specific parameters
   - May support `CKM_ECDH1_COFACTOR_DERIVE` (cofactor variant)
   - Wrap key derivation may need to be done in software after getting shared secret

2. **Thales HSMs**:
   - Similar ECDH support but parameter format may differ
   - Key derivation function parameters may need specific encoding

3. **SoftHSM2** (testing environment):
   - Supports ECDH but implementation details differ
   - May allow key extraction for testing (real HSMs won't)

4. **Smart Cards** (e.g., Estonian ID cards):
   - Often have strict limitations
   - May only support specific curves
   - Key extraction typically disabled

### Problem 4: ConcatKDF is Not a PKCS#11 Standard Mechanism

**CDOC uses ConcatKDF (Concatenation Key Derivation Function) with SHA-512:**

```63:85:crypto/ec.go
// ConcatKDF performs ConcatKDF key derivation using SHA-512
// Parameters are concatenated as: AlgorithmID | PartyUInfo | PartyVInfo
func ConcatKDF(sharedSecret []byte, algorithmID []byte, partyUInfo []byte, partyVInfo []byte) ([]byte, error) {
	// ConcatKDF requires SHA-512 with 32-byte output
	outputLength := 32

	// Concatenate parameters
	concatenated := make([]byte, 0, len(algorithmID)+len(partyUInfo)+len(partyVInfo))
	concatenated = append(concatenated, algorithmID...)
	concatenated = append(concatenated, partyUInfo...)
	concatenated = append(concatenated, partyVInfo...)

	// Hash shared secret with concatenated parameters
	h := sha512.New()
	h.Write(sharedSecret)
	h.Write(concatenated)
	hash := h.Sum(nil)

	// Return first 32 bytes
	if len(hash) < outputLength {
		return nil, internal.NewEncryptionError("hash output too short", nil)
	}

	return hash[:outputLength], nil
}
```

**PKCS#11 does not provide ConcatKDF as a standard mechanism:**
- Standard mechanisms: `CKM_PKCS5_PBKD2`, `CKM_X9_42_DH_DERIVE`, etc.
- **ConcatKDF is from SP 800-56A (NIST)** but not part of PKCS#11 standard
- Must be implemented in software **after** getting shared secret from token

## Required Implementation Approaches

To support EC decryption via PKCS#11, one of these approaches is needed:

### Approach 1: Use C_DeriveKey for ECDH (Preferred)

**If the token supports extractable shared secrets:**

1. Use `C_DeriveKey` with `CKM_ECDH1_DERIVE` mechanism
2. Provide ephemeral public key as `EC_POINT` parameter
3. Extract derived key (shared secret) from token
4. Perform ConcatKDF in software
5. Perform AES-KW unwrap in software or via token

**Challenges:**
- Token must allow extracting the shared secret
- Ephemeral public key must be encoded correctly for the token
- Some tokens derive a key object, not raw bytes
- Parameter encoding varies by vendor

### Approach 2: Extract Private Key (Not Secure)

**If the token allows it (typically only for testing):**

1. Read `CKA_VALUE` attribute (private key scalar)
2. Perform ECDH in software (like current software implementation)
3. Continue with ConcatKDF and unwrap

**Challenges:**
- **Security risk**: Private key leaves the HSM (defeats the purpose)
- Most production HSMs **don't allow this**
- Only suitable for testing/development

### Approach 3: Token-Specific Implementation

**For specific HSM vendors, use their APIs:**

1. **Utimaco**: May have custom ECDH functions or parameter requirements
2. **Thales**: Similar vendor-specific handling
3. **Custom tokens**: May require proprietary APIs beyond PKCS#11

**Implementation would require:**
- Vendor-specific documentation
- Testing with actual hardware
- Maintenance for each supported vendor

## Current Workaround: PKCS#12 for EC

**For EC recipients, use PKCS#12 keystores instead:**

- PKCS#12 files can be created from software keys
- Private keys are extracted and processed in software
- Full EC support via software implementation

**This works because:**
```47:81:cdoc/pkcs12_token.go
// DecryptEC performs ECDH key agreement and decrypts an EC-encrypted transport key
func (t *PKCS12Token) DecryptEC(ephemeralPublicKey *ecdsa.PublicKey, algorithmID []byte, partyUInfo []byte, partyVInfo []byte, encryptedKey []byte) ([]byte, error) {
	if t.keyEntry == nil || t.keyEntry.PrivateKey == nil {
		return nil, internal.NewDecryptionError("no private key in PKCS#12 token", nil)
	}

	privKey, ok := t.keyEntry.PrivateKey.ECPrivateKey()
	if !ok {
		return nil, internal.NewDecryptionError("private key is not EC", nil)
	}

	// Perform ECDH key agreement (same logic as decryptECTransportKey)
	sharedSecret, err := crypto.ECDHKeyAgreement(privKey, ephemeralPublicKey)
	if err != nil {
		return nil, internal.NewDecryptionError("failed ECDH key agreement", err)
	}

	// Derive wrap key via ConcatKDF
	wrapKey, err := crypto.ConcatKDF(
		sharedSecret,
		algorithmID,
		partyUInfo,
		partyVInfo,
	)
	if err != nil {
		return nil, internal.NewDecryptionError("failed ConcatKDF", err)
	}

	// Unwrap transport key using AES-KW-256
	dataKey, err := crypto.UnwrapAES256(encryptedKey, wrapKey)
	if err != nil {
		return nil, internal.NewDecryptionError("failed to unwrap transport key", err)
	}

	return dataKey, nil
}
```

## Summary

| Operation | RSA (PKCS#11) | EC (PKCS#11) | EC (Software/PKCS#12) |
|-----------|---------------|--------------|----------------------|
| **Private Key Access** | Not needed (decrypt on token) | Not allowed (security) | Allowed (extracted) |
| **Key Agreement** | N/A (direct decrypt) | `C_DeriveKey` varies | Software ECDH works |
| **Key Derivation** | N/A | ConcatKDF not in PKCS#11 | Software ConcatKDF works |
| **Key Unwrap** | N/A | AES-KW varies | Software AES-KW works |
| **Implementation** | ✅ Universal | ⚠️ Token-specific | ✅ Universal |

**Why RSA works:**
- Single PKCS#11 operation (`C_Decrypt`)
- Standard mechanism (`CKM_RSA_PKCS`)
- No key derivation needed

**Why EC doesn't work (currently):**
- Requires multi-step process (ECDH → ConcatKDF → AES-KW)
- Private keys often not extractable
- ConcatKDF not a PKCS#11 standard
- Token-specific variations in ECDH handling

**Recommended approach for EC:**
- Use PKCS#12 for EC keys (software-based, fully supported)
- Or implement token-specific EC support per HSM vendor
- Or use tokens that allow private key extraction (not recommended for production)

