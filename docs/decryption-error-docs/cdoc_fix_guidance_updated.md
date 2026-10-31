> Historical investigation/development record. Commands, versions and completion claims describe that record, not the current release. Use [current README](../../README.md) for supported setup and API boundaries.

# CDOC 1.1 Decryption Failure Analysis and Remediation Guide (Updated)

## Purpose

This document summarizes the currently identified interoperability defects in the custom Go-based CDOC 1.1 container implementation and provides concrete remediation guidance. It is intended to be used as implementation input for Cursor.AI or another coding agent.

The primary objective is to make the generated `.cdoc` container decrypt successfully in DigiDoc4 and remain structurally compatible with the Estonian CDOC 1.1 format.

---

## Current Status

The updated container is now recognized by DigiDoc4 as a valid encrypted container, which means some earlier structural issues have been corrected. However, decryption still fails.

This strongly suggests that the remaining defect is now in the cryptographic interoperability path rather than in basic XML/container recognition.

---

## Confirmed / Strongly Indicated Issues

### 1. `PartyUInfo` encoding was previously incorrect

## Problem

The earlier implementation constructed `PartyUInfo` from the ephemeral EC public key coordinates as:

- `00 || X || Y`

but the interoperable form expected by the working reference container is:

- `00 || 04 || X || Y`

where `0x04` is the standard EC uncompressed point prefix.

## Impact

This breaks the `ConcatKDF` input and causes derivation of the wrong key-encryption key (KEK), which then causes unwrap/decryption failure.

## Status

This appears to be fixed in the updated container.

## Required implementation rule

Use the same uncompressed EC point bytes for:
- the XML `PublicKey` field
- the `PartyUInfo` value, prefixed with `00`

That means:
- `PublicKey = 04 || X || Y`
- `PartyUInfo = 00 || 04 || X || Y`

---

### 2. AES Key Wrap uses the wrong initial value (new primary blocking issue)

## Problem

The current AES Key Wrap implementation in `crypto/aeskw.go` appears to use this initial value (AIV):

```text
A6 59 59 A6 00 00 00 00
```

For CDOC 1.1 ECC recipient handling with `kw-aes256`, the wrapped content encryption key must use standard RFC 3394 AES Key Wrap, whose 64-bit initial register value is:

```text
A6 A6 A6 A6 A6 A6 A6 A6
```

## Why this matters

If DigiDoc4 unwraps the `EncryptedKey` using standard RFC 3394 semantics, but the container was wrapped using a non-standard AIV, unwrap will fail even if:
- the ephemeral EC key is correct
- `PartyUInfo` is correct
- the KDF output is correct

This matches the current observed behavior:
- container opens as a recognized `.cdoc`
- decryption still fails

## Required fix

In `crypto/aeskw.go`, change the AES-KW initial value to the RFC 3394 default:

```go
A := []byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}
```

Apply the same value in both:
- `WrapAES256()`
- `UnwrapAES256()` integrity validation

## Do not rely on local roundtrip tests only

A local test that does:
- wrap using your implementation
- unwrap using your implementation

is not sufficient for interoperability validation.

If both methods use the same incorrect AIV, local tests still pass while DigiDoc4 fails.

## Required tests

Add known-answer tests using official RFC 3394 test vectors.

---

### 3. `ConcatKDF` implementation must be standards-compliant

## Problem

The implementation in `crypto/ec.go` was previously identified as likely non-compliant with XML Encryption 1.1 / NIST SP 800-56A ConcatKDF expectations.

The suspicious behavior was:
- hashing `sharedSecret || AlgorithmID || PartyUInfo || PartyVInfo` directly
- using a fixed hash behavior inconsistent with declared `DigestMethod`
- not clearly implementing the expected counter-based concatenation KDF structure

## Impact

Even if AES-KW is fixed, a non-standard KDF can still generate a wrong KEK and cause unwrap failure.

## Required implementation rule

Ensure the KDF follows the expected XML Encryption 1.1 / ConcatKDF structure, including:
- the digest algorithm declared in XML (for example `sha384`) must actually be used
- the internal format must follow counter-based ConcatKDF construction
- `AlgorithmID`, `PartyUInfo`, `PartyVInfo`, and any required supplementary fields must be encoded exactly as expected by the format/profile

## Action

Review and rewrite `ConcatKDF()` if there is any ambiguity. Do not keep a simplified or custom derivation function.

---

### 4. Metadata / XML consistency issues

## Observed differences

Earlier differences between the generated container and the working reference container included:
- missing `orig_file` encryption property
- different `Recipient` string formatting
- XML serialization differences

## Impact

These are less likely to be the direct cause of decryption failure than the key agreement / KDF / key-wrap path, but they may still affect compatibility with some clients.

## Required rule

Match the reference container as closely as practical for:
- encryption properties
- recipient display/name fields
- XML element ordering, namespaces, and serialization consistency

These should be treated as compatibility hardening tasks.

---

## Recommended Remediation Order

Implement the fixes in this order:

1. **AES Key Wrap RFC 3394 correction**
   - Replace the custom/incorrect AIV with the standard RFC 3394 IV.
   - Add official AES-KW vector tests.

2. **Full `ConcatKDF` validation and correction**
   - Ensure the digest actually matches the XML `DigestMethod`.
   - Ensure counter-based ConcatKDF behavior is correct.
   - Ensure `PartyUInfo` and `PartyVInfo` are encoded exactly as required.

3. **Regression-verify `PartyUInfo` handling**
   - Keep `PartyUInfo = 00 || 04 || X || Y`.
   - Ensure `PublicKey` and `PartyUInfo` are built from the same uncompressed point bytes.

4. **Metadata and XML compatibility cleanup**
   - Preserve `orig_file` property.
   - Normalize recipient metadata formatting if needed.
   - Compare generated XML against a known-good container.

---

## Concrete Implementation Tasks

### Task A — Fix AES-KW initial value

Update `crypto/aeskw.go`:

- Replace any non-standard AES-KW initial register value with:

```go
[]byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}
```

- Ensure unwrap validation checks against the same value.

### Task B — Add AES-KW interoperability tests

Add tests that validate:
- wrap against RFC 3394 known-answer vectors
- unwrap against RFC 3394 known-answer vectors
- failure on wrong integrity register value

### Task C — Audit and fix `ConcatKDF`

Review `crypto/ec.go` and verify:
- digest selection comes from XML-declared algorithm
- counter-based derivation exists and is correctly implemented
- output length matches AES-256 KEK requirement
- `AlgorithmID`, `PartyUInfo`, `PartyVInfo` are encoded consistently

### Task D — Lock in `PartyUInfo` correctness

Verify the code path that builds the ephemeral key material:
- `PublicKey` must contain `04 || X || Y`
- `PartyUInfo` must contain `00 || 04 || X || Y`
- no code path may generate `00 || X || Y`

### Task E — Compare against reference `.cdoc`

Build a binary/XML comparison tool or test helper that compares the generated container to a known-good reference container at least for:
- recipient crypto parameters
- `PublicKey`
- `PartyUInfo`
- KDF algorithm identifiers
- wrapped key length
- AES-GCM parameters
- encryption properties

---

## Acceptance Criteria

The work is complete only when all of the following are true:

### Functional acceptance

- A newly generated `.cdoc` file decrypts successfully in DigiDoc4.
- The decrypted payload matches the original file exactly.
- The same recipient certificate/private key works with both the reference container and the generated container.

### Cryptographic acceptance

- AES Key Wrap implementation matches RFC 3394 behavior.
- AES-KW tests pass against known-answer vectors.
- `ConcatKDF` uses the digest declared in XML.
- `PartyUInfo` contains the EC uncompressed point prefix.

### Interoperability acceptance

- DigiDoc4 recognizes the file as a valid encrypted container.
- DigiDoc4 can decrypt it without fallback/manual repair.
- Generated XML/metadata is not missing compatibility-relevant fields such as `orig_file`.

### Regression acceptance

- Existing valid container generation remains working.
- Unit tests cover:
  - AES-KW wrap/unwrap
  - KDF derivation
  - ephemeral public key encoding
  - XML recipient structure
- Integration tests verify decryption behavior against at least one real DigiDoc4-compatible scenario.

---

## Suggested Debugging Sequence if It Still Fails

If decryption still fails after the AES-KW fix, debug in this exact order:

1. Compare `EncryptedKey` generation path between reference and generated containers.
2. Validate AES-KW using a standalone RFC 3394 vector runner.
3. Validate `ConcatKDF` output using deterministic test inputs.
4. Confirm `DigestMethod` in XML matches the actual hash used in code.
5. Confirm the recipient certificate and private key match the intended decryption keypair.
6. Compare XML recipient block field-by-field against the working container.
7. Validate the content encryption stage (AES-GCM key/IV/tag handling).

---

## Cursor.AI Implementation Prompt

Use this as direct implementation guidance:

> Fix CDOC 1.1 interoperability issues in the Go library. The current container is recognized by DigiDoc4 but decryption fails. Treat the main blocking issue as incorrect AES Key Wrap behavior in `crypto/aeskw.go`: replace any custom AIV with the standard RFC 3394 IV `A6 A6 A6 A6 A6 A6 A6 A6`, and update unwrap integrity validation accordingly. Add RFC 3394 known-answer tests. Then audit and correct `ConcatKDF` in `crypto/ec.go` to be standards-compliant and to use the digest declared in XML. Preserve the already corrected `PartyUInfo` behavior: `PartyUInfo = 00 || 04 || X || Y`, and ensure `PublicKey = 04 || X || Y`. Keep compatibility metadata such as `orig_file`. Add tests and integration checks so the generated `.cdoc` decrypts successfully in DigiDoc4.

---

## Final Priority Summary

The likely issue priority is now:

1. **Incorrect AES-KW initial value** — most likely current blocker
2. **Potential non-standard `ConcatKDF`** — next most likely blocker
3. **Metadata/XML compatibility differences** — lower priority, but still worth aligning

