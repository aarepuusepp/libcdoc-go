# CDOC 1.1 ECC Interoperability Fix Checklist and Acceptance Criteria

## Purpose

This document is a compact implementation checklist for fixing the discovered interoperability issues in the Go-based CDOC 1.1 container writer.

Use this as an execution guide for making code changes, validating the output, and confirming that newly generated `.cdoc` files can be decrypted by existing CDOC-compatible tooling.

---

## Scope

The fixes in scope are:

1. Correct `PartyUInfo` encoding for ECC recipients.
2. Correct `ConcatKDF` implementation to match XML Encryption 1.1 / NIST SP 800-56A expectations.
3. Align XML metadata with known-good container structure where practical.
4. Add regression tests that compare generated output structure against expected invariants.

---

## Implementation Checklist

### 1. Fix ECC public key encoding consistency

#### Problem

The generated container uses inconsistent encodings for:
- `KeyAgreement/OriginatorKeyInfo/KeyValue/ECKeyValue/PublicKey`
- `AgreementMethod/KA-Nonce`-related KDF input via `PartyUInfo`

Observed issue:
- `PublicKey` contains uncompressed EC point format: `0x04 || X || Y`
- `PartyUInfo` is built as `0x00 || X || Y`
- Expected form is: `0x00 || 0x04 || X || Y`

#### Required change

Create one canonical helper for uncompressed EC public key encoding and reuse it everywhere.

#### Done when

- A single function returns `0x04 || X || Y` for P-384 public keys.
- `PublicKey` base64-encodes that exact byte array.
- `PartyUInfo` becomes `"00" + hex(0x04 || X || Y)`.
- No code path builds `PartyUInfo` from `X || Y` only.

---

### 2. Replace the current KDF with a standards-aligned ConcatKDF

#### Problem

Current `ConcatKDF()` logic is not aligned with XML Encryption 1.1 ConcatKDF expectations.

Observed concerns:
- It appears to hash a concatenated blob directly.
- It uses SHA-512 regardless of the declared `DigestMethod`.
- It does not clearly implement the `counter || Z || OtherInfo` pattern.

#### Required change

Implement ConcatKDF according to the XML Encryption 1.1-compatible model:

- Respect the digest algorithm declared in XML.
- Build `OtherInfo` from the expected fields.
- Use iterative hash blocks with counter prefix.
- Truncate to requested key length.

#### Minimum expected behavior

For this CDOC 1.1 ECC profile:
- The digest used by the KDF must match the declared digest method in XML.
- The KDF input must include the ECDH shared secret `Z`.
- `PartyUInfo` and `PartyVInfo` must be included in the correct binary form.
- Output length must match the AES Key Wrap key size.

#### Done when

- `ConcatKDF()` is parameterized by digest algorithm.
- The code uses standards-shaped KDF input construction.
- Derived KEK length matches the wrapping algorithm requirement.
- A generated container decrypts successfully with the target CDOC decrypter.

---

### 3. Keep XML values internally consistent

#### Problem

Some XML values are structurally different from the working reference container.

Examples:
- `Recipient` formatting differs.
- `orig_file` encryption property may be missing.
- XML prolog may be omitted.

These are not the primary cryptographic failure, but should be normalized where possible for interoperability and easier comparison.

#### Required change

Review XML generation and align with the known-good reference format where practical.

#### Done when

- `EncryptionProperties` contain all expected metadata fields used by the ecosystem, if available.
- `Recipient` formatting is stable and compatible with consumers.
- XML output is deterministic enough for structure-level comparisons.

---

### 4. Add byte-level and XML-level regression tests

#### Required tests

Add tests for the following invariants.

##### ECC public key encoding test

Verify that encoded P-384 public key is:
- 97 bytes total
- byte `0` is `0x04`
- remaining 96 bytes are `X || Y`

##### PartyUInfo construction test

Verify that:
- `PartyUInfo` begins with `0x00`
- the next byte is `0x04`
- total size matches `1 + 97 = 98 bytes`

##### XML consistency test

Generate a container and verify:
- `PublicKey` decodes to 97 bytes
- `PartyUInfo` decodes from hex to 98 bytes
- `PartyUInfo[1:] == PublicKeyBytes`

##### KDF determinism test

Given fixed inputs:
- private key
- peer public key
- algorithm ID
- partyUInfo
- partyVInfo

Verify:
- the KDF output is deterministic
- output length is correct
- digest selection affects output as expected

##### End-to-end interoperability test

Generate a container with the Go library and confirm that it can be decrypted by the target external decrypter.

---

## Acceptance Criteria

A fix is accepted only if all conditions below are satisfied.

### Functional acceptance

- A newly generated `.cdoc` created by the Go library decrypts successfully in the target CDOC decryption tool.
- The decrypted payload exactly matches the original plaintext file contents.
- The same recipient certificate works for both the reference container and the Go-generated container.

### Structural acceptance

- `PublicKey` is base64-decoded to `0x04 || X || Y`.
- `PartyUInfo` is hex-decoded to `0x00 || 0x04 || X || Y`.
- KDF output length matches the AES Key Wrap algorithm key length.
- XML digest declaration and actual KDF digest are the same.

### Regression acceptance

- Unit tests cover EC point encoding.
- Unit tests cover `PartyUInfo` construction.
- Unit tests cover KDF derivation.
- Integration tests cover container generation and decryption.
- Existing working functionality remains green.

---

## Suggested Work Order

1. Fix EC public key encoding helper.
2. Fix `PartyUInfo` generation.
3. Regenerate a test container and compare against known-good structure.
4. Replace KDF with a standards-aligned implementation.
5. Re-test decryption.
6. Normalize metadata and XML differences.
7. Add regression tests.
8. Freeze a golden test fixture.

---

## Suggested Code Refactoring Tasks

- Introduce a single helper:
  - `encodeECPublicKeyUncompressed(pub ecdsa.PublicKey) []byte`
- Introduce a KDF abstraction:
  - `deriveKEK(sharedSecret, algorithmID, partyUInfo, partyVInfo, digest, keyLen)`
- Separate:
  - XML serialization
  - cryptographic derivation
  - recipient metadata formatting
- Add fixtures from:
  - known-good CDOC
  - generated CDOC after fix

---

## Verification Procedure

### Manual verification

1. Generate a new `.cdoc` with the updated Go library.
2. Unpack the ZIP/XML structure if needed.
3. Decode and inspect:
   - `PublicKey`
   - `PartyUInfo`
   - digest algorithm declaration
4. Attempt decryption using the same certificate/private key used for the reference file.
5. Compare the recovered file with the original `TEST.txt`.

### Binary sanity checks

- `PublicKey` must start with `04`
- `PartyUInfo` must start with `0004`
- `PartyUInfo` length must be exactly one byte longer than `PublicKey`

---

## Non-Goals

The following are useful but not required for initial acceptance:

- Perfect byte-for-byte equality with the reference container.
- Identical recipient display-name formatting.
- Identical XML whitespace or attribute ordering.

The goal is interoperability and standards compliance, not binary cloning of a reference implementation.

---

## Deliverables Expected From Cursor

1. Code changes in the relevant Go files.
2. New or updated unit tests.
3. One generated test container proving the fix.
4. A short implementation summary listing:
   - files changed
   - root cause fixed
   - tests added
   - remaining compatibility risks

---

## Final Definition of Done

The task is done only when:

- the Go library generates a valid CDOC 1.1 ECC container,
- the container decrypts successfully in the target consumer,
- the cryptographic implementation is internally consistent,
- and the fix is protected by regression tests.
