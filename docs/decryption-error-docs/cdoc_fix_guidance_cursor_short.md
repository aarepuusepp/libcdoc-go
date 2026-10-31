> Historical investigation/development record. Commands, versions and completion claims describe that record, not the current release. Use [current README](../../README.md) for supported setup and API boundaries.

# Cursor.AI Task Brief — Fix CDOC 1.1 ECC Container Generation in Go

## Goal

Fix the Go CDOC library so it generates **interoperable Estonian CDOC 1.1 ECC encrypted containers**.

The current generated file `encrypted.cdoc` cannot be decrypted, while the reference file `TEST.cdoc` works. Both encrypt the same payload and target the same recipient certificate.

Your task is to correct the library implementation so the generated container matches the reference behavior and can be decrypted by standard CDOC-compatible implementations.

---

## Main Findings

### 1. `PartyUInfo` is encoded incorrectly

This is the most likely direct cause of decryption failure.

#### Current broken behavior

The generated container uses:

- `PublicKey = 0x04 || X || Y`
- `PartyUInfo = 0x00 || X || Y`

#### Expected behavior

The working reference container uses:

- `PublicKey = 0x04 || X || Y`
- `PartyUInfo = 0x00 || 0x04 || X || Y`

So the uncompressed EC point prefix byte `0x04` is missing from `PartyUInfo`.

#### Why this matters

`PartyUInfo` is used as an input to the ECC key derivation process (`ECDH-ES` + `ConcatKDF`).
If it is encoded differently from the expected format, the derived key-encryption key (KEK) is wrong, so the wrapped file key cannot be unwrapped during decryption.

#### What to change

In `cdoc/composer.go`, stop using different byte layouts for:

- XML `PublicKey`
- `PartyUInfo`

Create a single helper that returns the EC public key as a full **uncompressed point**:

- `0x04 || X || Y`

Use that same byte array for both:

- base64-encoded `PublicKey`
- hex-encoded `PartyUInfo` prefixed with `00`

#### Patch direction

```go
func encodeECPublicKeyUncompressed(pubKey ecdsa.PublicKey) ([]byte, error) {
    xBytes := pubKey.X.Bytes()
    yBytes := pubKey.Y.Bytes()

    raw := make([]byte, 96)
    copy(raw[48-len(xBytes):48], xBytes)
    copy(raw[96-len(yBytes):], yBytes)

    return append([]byte{0x04}, raw...), nil
}
```

Then:

```go
pubBytes, err := encodeECPublicKeyUncompressed(ephemeralPrivKey.PublicKey)
if err != nil {
    return nil, err
}

publicKeyBase64 := base64.StdEncoding.EncodeToString(pubBytes)
partyUInfoHex := "00" + hex.EncodeToString(pubBytes)
```

---

### 2. `ConcatKDF()` is not implemented according to XMLENC / NIST SP 800-56A

This is another serious interoperability problem.

#### Current problem

The existing code in `crypto/ec.go` appears to derive the KEK using a simplified digest construction similar to:

```text
SHA-512(sharedSecret || AlgorithmID || PartyUInfo || PartyVInfo)
```

That is not the proper XML Encryption 1.1 / NIST SP 800-56A ConcatKDF construction.

#### Required behavior

Implement ConcatKDF in the standard form:

```text
H(counter || Z || OtherInfo)
```

Where:

- `counter` is a 4-byte big-endian value starting at `1`
- `Z` is the ECDH shared secret
- `OtherInfo` is the structured context data

#### Also fix the digest selection

If the XML metadata says the digest is `sha384`, then the KDF must actually use **SHA-384**, not SHA-512.

#### What to change

Rework `ConcatKDF()` so that it:

1. Uses the digest declared by XML metadata
2. Builds `OtherInfo` correctly
3. Computes one or more blocks with:

```text
H(counter || Z || OtherInfo)
```

4. Truncates output to the needed KEK size
   - AES-256 Key Wrap => 32 bytes

#### Implementation outline

```go
func ConcatKDF(hash func() hash.Hash, z []byte, otherInfo []byte, keyDataLen int) []byte {
    hashLen := hash().Size()
    reps := (keyDataLen + hashLen - 1) / hashLen

    var result []byte
    for counter := 1; counter <= reps; counter++ {
        h := hash()

        var ctr [4]byte
        binary.BigEndian.PutUint32(ctr[:], uint32(counter))

        h.Write(ctr[:])
        h.Write(z)
        h.Write(otherInfo)

        result = append(result, h.Sum(nil)...)
    }

    return result[:keyDataLen]
}
```

---

## Secondary Differences

These differences were also observed, but they do **not** appear to be the main direct cause of decryption failure:

- `Recipient` string format differs from the reference container
- `orig_file` `EncryptionProperty` is missing in the generated file
- XML prolog differs or is missing

These should be reviewed for compatibility and metadata completeness, but priority should be:

1. Fix `PartyUInfo`
2. Fix `ConcatKDF`

---

## Files to Update

Focus on these files from the Go archive:

- `cdoc/composer.go`
- `crypto/ec.go`

---

## Required Validation After Fix

After implementing the changes, validate the following:

### Container structure checks

For a P-384 recipient:

- decoded `PublicKey` length is `97` bytes
- decoded `PartyUInfo` length is `98` bytes
- `PartyUInfo[1:] == decodedPublicKey`
- decoded `PublicKey[0] == 0x04`
- decoded `PartyUInfo[0] == 0x00`

### Functional checks

1. Generate a new CDOC container using the same recipient cert and same test file.
2. Verify the generated container decrypts successfully with the target CDOC implementation.
3. Compare XML recipient metadata against the working `TEST.cdoc` container.
4. Add automated tests for ECC recipient generation and KDF determinism.

---

## Expected Outcome

After the fixes:

- ECC recipient metadata must be encoded correctly
- the KEK must be derived interoperably
- the wrapped file key must be decryptable by standard CDOC tooling
- the generated CDOC container must decrypt successfully

---

## Implementation Priority

1. Fix `PartyUInfo` encoding
2. Fix `ConcatKDF` implementation
3. Add tests
4. Review secondary metadata differences

---

## Instruction to Cursor.AI

Please update the Go implementation to make the ECC CDOC 1.1 generation interoperable with the working reference container.

Do not only patch the symptom. Refactor the public key encoding path so the same canonical EC point representation is reused consistently across:

- XML `PublicKey`
- `PartyUInfo`
- any KDF-related input construction

Also re-implement the KDF in a standards-compliant way and add regression tests that would fail if the old broken encoding is reintroduced.
