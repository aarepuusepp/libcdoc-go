<!-- 28d2a784-3c40-4b0f-aae1-406e93f0400b cc4e2e5e-c969-45a4-a3ac-fbd8edca97d1 -->
# CDOC 1.1 Go Library Implementation Plan

## Executive Summary

This plan outlines the implementation of `cdoc1-go`, a Go library for Estonian CDOC 1.0 and 1.1 encryption/decryption. The library supports certificate-based encryption (RSA and EC), excludes PKCS#11/smartcard dependencies, and ensures interoperability with cdoc4j and official DigiDoc clients.

**Technology Stack:** Go ≥1.22, standard library `crypto/*`, `encoding/xml`, minimal dependencies

**License:** MIT/Apache-2.0

**Target Formats:** CDOC 1.0 (AES-128-CBC), CDOC 1.1 (AES-256-GCM)

---

## Architecture Document

### Module Structure

```
cdoc1-go/
├── cdoc/                    # Core library package
│   ├── builder.go           # CDOC encryption builder
│   ├── decrypter.go         # CDOC decryption
│   ├── parser.go            # XML document parser
│   ├── composer.go           # XML document composer
│   └── version.go            # Version detection and validation
├── xmlenc/                  # XML Encryption 1.1 models
│   ├── encrypted_data.go   # EncryptedData element
│   ├── encrypted_key.go     # EncryptedKey element (RSA & EC)
│   ├── agreement_method.go  # ECDH-ES agreement method
│   ├── recipient.go         # Recipient abstraction
│   └── namespaces.go        # XML namespace constants
├── crypto/                  # Cryptographic operations
│   ├── aes.go              # AES-GCM/CBC encryption
│   ├── rsa.go               # RSA PKCS#1 v1.5 operations
│   ├── ec.go                # ECDH-ES + ConcatKDF + AES-KW
│   ├── padding.go           # X.923 and PKCS#7 padding
│   ├── keygen.go            # Key generation utilities
│   └── iv.go                # IV generation
├── cert/                    # Certificate handling
│   ├── parser.go            # X.509 certificate parsing (PEM/DER)
│   ├── validator.go         # Certificate validation (key usage)
│   └── dn.go                # Distinguished name utilities
├── key/                     # Private key handling
│   ├── pem.go               # PEM format parsing
│   ├── pkcs8.go             # PKCS#8 parsing
│   └── key.go               # Private key abstraction
├── internal/                # Internal utilities
│   ├── base64.go            # Base64 encoding/decoding
│   ├── hex.go               # Hex encoding utilities
│   └── errors.go            # Error types and wrapping
└── cmd/
    └── cdoc1/               # CLI tool
        └── main.go
```

### Data Flow: Encryption

1. **Input Validation**

   - Verify at least one data file and recipient certificate
   - Validate certificate key usage (keyEncipherment for RSA, keyAgreement for EC)
   - Parse certificates from PEM/DER

2. **Key Generation**

   - Generate 256-bit (32-byte) AES key using `crypto/rand`
   - Generate ephemeral EC key pair (secp384r1) for EC recipients

3. **Content Encryption (CDOC 1.1)**

   - Generate 12-byte IV using `crypto/rand`
   - Encrypt content with AES-256-GCM (no padding)
   - Base64 encode IV + ciphertext

4. **Transport Key Encryption**

   - **RSA recipients:**
     - Encrypt AES key directly with RSA PKCS#1 v1.5
     - Base64 encode result
   - **EC recipients:**
     - Perform ECDH key agreement (ephemeral private × recipient public)
     - Derive 32-byte key via ConcatKDF(SHA-512): `ConcatKDF(sharedSecret, AlgorithmID|PartyUInfo|PartyVInfo)`
     - Wrap AES key with AES-KW-256
     - Base64 encode wrapped key

5. **XML Generation**

   - Construct `EncryptedData` root with namespace `http://www.w3.org/2001/04/xmlenc#`
   - Add `EncryptionMethod` (CDOC 1.1: `http://www.w3.org/2009/xmlenc11#aes256-gcm`)
   - Create `KeyInfo` containing `EncryptedKey` elements for each recipient
   - Add `CipherData` with Base64-encoded encrypted content
   - Add `EncryptionProperties` metadata (LibraryVersion, DocumentFormat, Filename, OriginalSize, OriginalMimeType)

### Data Flow: Decryption

1. **XML Parsing**

   - Parse XML using `encoding/xml`
   - Extract `EncryptionMethod` to determine CDOC version
   - Parse recipients (RSA or EC based on `EncryptionMethod` algorithm URI)

2. **Recipient Selection**

   - Match provided certificate with recipient certificates (CN or full certificate match)
   - Handle single vs. multiple recipient scenarios

3. **Transport Key Decryption**

   - **RSA:** Decrypt `CipherValue` with private key (RSA PKCS#1 v1.5)
   - **EC:** 
     - Extract ephemeral public key from `OriginatorKeyInfo`
     - Perform ECDH agreement (private key × ephemeral public)
     - Derive wrap key via ConcatKDF
     - Unwrap with AES-KW-256

4. **Content Decryption**

   - Decode Base64 `CipherValue`
   - Extract IV (first 12 bytes for GCM)
   - Decrypt with AES-256-GCM
   - Verify authentication tag

### XML Model (Key Structures)

**EncryptedData:**

```xml
<denc:EncryptedData xmlns:denc="http://www.w3.org/2001/04/xmlenc#" MimeType="...">
  <denc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes256-gcm"/>
  <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <!-- EncryptedKey elements -->
  </ds:KeyInfo>
  <denc:CipherData>
    <denc:CipherValue>...</denc:CipherValue>
  </denc:CipherData>
  <denc:EncryptionProperties>...</denc:EncryptionProperties>
</denc:EncryptedData>
```

**EncryptedKey (RSA):**

```xml
<denc:EncryptedKey Recipient="...">
  <denc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5"/>
  <ds:KeyInfo>
    <ds:X509Data>
      <ds:X509Certificate>...</ds:X509Certificate>
    </ds:X509Data>
  </ds:KeyInfo>
  <denc:CipherData>
    <denc:CipherValue>...</denc:CipherValue>
  </denc:CipherData>
</denc:EncryptedKey>
```

**EncryptedKey (EC):**

```xml
<denc:EncryptedKey Recipient="...">
  <denc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#kw-aes256"/>
  <ds:KeyInfo>
    <denc:AgreementMethod Algorithm="http://www.w3.org/2009/xmlenc11#ECDH-ES">
      <xenc11:KeyDerivationMethod Algorithm="http://www.w3.org/2009/xmlenc11#ConcatKDF">
        <xenc11:ConcatKDFParams AlgorithmID="00..." PartyUInfo="00..." PartyVInfo="00...">
          <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha384"/>
        </xenc11:ConcatKDFParams>
      </xenc11:KeyDerivationMethod>
      <denc:OriginatorKeyInfo>
        <ds:KeyValue>
          <dsig11:ECKeyValue>
            <dsig11:NamedCurve URI="urn:oid:1.3.132.0.34"/>
            <dsig11:PublicKey>...</dsig11:PublicKey>
          </dsig11:ECKeyValue>
        </ds:KeyValue>
      </denc:OriginatorKeyInfo>
      <denc:RecipientKeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>...</ds:X509Certificate>
        </ds:X509Data>
      </denc:RecipientKeyInfo>
    </denc:AgreementMethod>
  </ds:KeyInfo>
  <denc:CipherData>
    <denc:CipherValue>...</denc:CipherValue>
  </denc:CipherData>
</denc:EncryptedKey>
```

### Cryptographic Choices

- **Content Encryption (CDOC 1.1):** AES-256-GCM, 12-byte IV (nonce)
- **Content Encryption (CDOC 1.0):** AES-128-CBC, 16-byte IV, X.923 + PKCS#7 padding
- **RSA:** PKCS#1 v1.5 (RSASSA-PKCS1-v1_5) via `crypto/rsa`
- **EC:** secp384r1 (P-384), ECDH-ES via `crypto/ecdsa` and `crypto/elliptic`
- **KDF:** ConcatKDF with SHA-512 (via `crypto/sha512`)
- **Key Wrapping:** AES-KW-256 (RFC 3394) — requires custom implementation or `golang.org/x/crypto/nistec`/`golang.org/x/crypto/poly1305` for GCM if needed

### Error Model

```go
// Error hierarchy
type CDOCError struct {
    Message string
    Cause   error
}

type ValidationError struct { CDOCError }
type EncryptionError struct { CDOCError }
type DecryptionError struct { CDOCError }
type ParseError struct { CDOCError }
type CertificateError struct { CDOCError }
```

---

## Work Breakdown Structure (WBS)

### Epic 1: Core Infrastructure (Est: 5 days)

**Story 1.1: Project Setup**

- Task 1.1.1: Initialize Go module (`go mod init github.com/aarepuusepp/libcdoc-go`) (0.5d)
- Task 1.1.2: Create package structure and stub files (0.5d)
- Task 1.1.3: Set up CI/CD (GitHub Actions: go test, go vet, gofmt, golint) (1d)
- Task 1.1.4: Configure license files (MIT/Apache-2.0) (0.5d)

**Story 1.2: Error Handling**

- Task 1.2.1: Define error types (`internal/errors.go`) (0.5d)
- Task 1.2.2: Implement error wrapping with context (0.5d)

**Story 1.3: Utilities**

- Task 1.3.1: Base64 utilities (`internal/base64.go`) (0.5d)
- Task 1.3.2: Hex utilities for ConcatKDF (`internal/hex.go`) (0.5d)

**DoD:** Error types defined, CI passing with empty tests, package structure in place

---

### Epic 2: Certificate and Key Handling (Est: 4 days)

**Story 2.1: Certificate Parsing**

- Task 2.1.1: Implement PEM certificate parsing (`cert/parser.go`) (1d)
- Task 2.1.2: Implement DER certificate parsing (1d)
- Task 2.1.3: Extract CN from DN (`cert/dn.go`) (0.5d)

**Story 2.2: Certificate Validation**

- Task 2.2.1: Validate key usage (`cert/validator.go`: keyEncipherment for RSA, keyAgreement for EC) (1d)

**Story 2.3: Private Key Parsing**

- Task 2.3.1: Implement PEM private key parsing (`key/pem.go`) (0.5d)
- Task 2.3.2: Implement PKCS#8 DER parsing (`key/pkcs8.go`) (0.5d)

**DoD:** Can parse PEM/DER certificates and private keys, validate key usage, extract CN

---

### Epic 3: Cryptographic Primitives (Est: 8 days)

**Story 3.1: AES Operations**

- Task 3.1.1: Implement AES-256-GCM encryption (`crypto/aes.go`) (2d)
- Task 3.1.2: Implement AES-256-GCM decryption (1d)
- Task 3.1.3: Implement AES-128-CBC with X.923 + PKCS#7 padding (CDOC 1.0) (2d)
- Task 3.1.4: Implement AES-KW-256 key wrapping (RFC 3394) (2d)
- Task 3.1.5: IV generation (`crypto/iv.go`) (0.5d)
- Task 3.1.6: Key generation (`crypto/keygen.go`) (0.5d)

**Story 3.2: RSA Operations**

- Task 3.2.1: Implement RSA PKCS#1 v1.5 encryption (`crypto/rsa.go`) (1d)
- Task 3.2.2: Implement RSA PKCS#1 v1.5 decryption (0.5d)

**Story 3.3: EC Operations**

- Task 3.3.1: Implement ECDH key agreement for secp384r1 (`crypto/ec.go`) (1d)
- Task 3.3.2: Implement ConcatKDF with SHA-512 (1d)
- Task 3.3.3: Validate EC point on curve (1d)

**Story 3.4: Padding**

- Task 3.4.1: Implement X.923 padding (`crypto/padding.go`) (0.5d)
- Task 3.4.2: Implement PKCS#7 padding (0.5d)

**DoD:** All crypto primitives implemented, unit tests passing, constant-time operations where applicable

---

### Epic 4: XML Encryption Models (Est: 6 days)

**Story 4.1: XML Structures**

- Task 4.1.1: Define `EncryptedData` struct with XML tags (`xmlenc/encrypted_data.go`) (1d)
- Task 4.1.2: Define `EncryptedKey` struct for RSA (`xmlenc/encrypted_key.go`) (1d)
- Task 4.1.3: Define EC `AgreementMethod` structures (`xmlenc/agreement_method.go`) (2d)
- Task 4.1.4: Define `Recipient` interfaces and implementations (`xmlenc/recipient.go`) (1d)
- Task 4.1.5: Define namespace constants (`xmlenc/namespaces.go`) (0.5d)
- Task 4.1.6: Define `EncryptionProperties` structure (0.5d)

**DoD:** All XML structures defined with correct tags, can marshal/unmarshal basic structures

---

### Epic 5: XML Parser (Est: 5 days)

**Story 5.1: Document Parsing**

- Task 5.1.1: Implement CDOC version detection (`cdoc/version.go`) (0.5d)
- Task 5.1.2: Parse `EncryptedData` root (`cdoc/parser.go`) (1d)
- Task 5.1.3: Parse RSA recipients (1d)
- Task 5.1.4: Parse EC recipients (2d)
- Task 5.1.5: Parse metadata (`EncryptionProperties`) (0.5d)

**DoD:** Can parse CDOC 1.0 and 1.1 documents, extract all recipients and metadata

---

### Epic 6: XML Composer (Est: 6 days)

**Story 6.1: Document Generation**

- Task 6.1.1: Implement `EncryptedData` composition (`cdoc/composer.go`) (1d)
- Task 6.1.2: Implement RSA recipient `EncryptedKey` generation (1d)
- Task 6.1.3: Implement EC recipient `EncryptedKey` generation (ECDH-ES + ConcatKDF params) (2d)
- Task 6.1.4: Implement metadata (`EncryptionProperties`) generation (0.5d)
- Task 6.1.5: XML formatting and encoding (UTF-8, proper indentation) (0.5d)
- Task 6.1.6: Validate XML output against reference documents (1d)

**DoD:** Can generate CDOC 1.0 and 1.1 documents, XML matches cdoc4j output structure

---

### Epic 7: Encryption API (Est: 5 days)

**Story 7.1: Builder Pattern**

- Task 7.1.1: Implement `Builder` struct with fluent API (`cdoc/builder.go`) (1d)
- Task 7.1.2: Implement data file handling (streaming support) (1d)
- Task 7.1.3: Implement recipient certificate handling (1d)
- Task 7.1.4: Implement encryption orchestration (key gen → content encryption → transport key encryption → XML generation) (2d)

**DoD:** Can encrypt files using builder API, supports multiple recipients (RSA + EC mixed)

---

### Epic 8: Decryption API (Est: 5 days)

**Story 8.1: Decrypter Implementation**

- Task 8.1.1: Implement `Decrypter` struct (`cdoc/decrypter.go`) (1d)
- Task 8.1.2: Implement recipient selection logic (single vs. multiple) (1d)
- Task 8.1.3: Implement decryption orchestration (XML parse → recipient selection → transport key decryption → content decryption) (2d)
- Task 8.1.4: Handle DDOC payloads (MimeType detection) (1d)

**DoD:** Can decrypt CDOC documents with certificate-based private keys

---

### Epic 9: Testing (Est: 10 days)

**Story 9.1: Unit Tests**

- Task 9.1.1: Test certificate parsing (PEM/DER) (1d)
- Task 9.1.2: Test crypto primitives (AES-GCM, RSA, ECDH, ConcatKDF, AES-KW) (2d)
- Task 9.1.3: Test padding (X.923, PKCS#7) (0.5d)
- Task 9.1.4: Test XML parsing (`xmlenc` package) (1d)
- Task 9.1.5: Test XML composition (1d)
- Task 9.1.6: Test builder API (1d)
- Task 9.1.7: Test decrypter API (1d)

**Story 9.2: Integration Tests**

- Task 9.2.1: Create test fixtures (certificates, keys, sample files) (1d)
- Task 9.2.2: End-to-end encryption tests (CDOC 1.0 and 1.1, RSA and EC) (1d)
- Task 9.2.3: End-to-end decryption tests (1d)

**Story 9.3: Interoperability Tests**

- Task 9.3.1: Encrypt with cdoc1-go, decrypt with cdoc4j (both directions) (1.5d)
- Task 9.3.2: Test with official DigiDoc client-generated CDOC files (1d)
- Task 9.3.3: Validate XML structure matches cdoc4j output (0.5d)

**Story 9.4: Property-Based Testing**

- Task 9.4.1: Property tests for encryption/decryption round-trip (1d)
- Task 9.4.2: Property tests for padding (0.5d)

**Story 9.5: Fuzzing**

- Task 9.5.1: Fuzz XML parser (1d)
- Task 9.5.2: Fuzz certificate parsing (0.5d)

**DoD:** Unit test coverage ≥80%, all integration tests passing, interoperability with cdoc4j confirmed

---

### Epic 10: CLI Tool (Est: 3 days)

**Story 10.1: CLI Implementation**

- Task 10.1.1: Implement `cdoc1 encrypt` command (`cmd/cdoc1/main.go`) (1d)
- Task 10.1.2: Implement `cdoc1 decrypt` command (1d)
- Task 10.1.3: Add help text and error messages (0.5d)
- Task 10.1.4: Test CLI with sample files (0.5d)

**DoD:** CLI can encrypt/decrypt files, used for manual testing and CI validation

---

## Test Plan

### Unit Test Coverage Targets

- `crypto/`: 90%+ (critical security code)
- `cert/`, `key/`: 85%+
- `xmlenc/`: 85%+
- `cdoc/`: 80%+
- Overall: ≥80%

### Integration Test Scenarios

1. Encrypt single file (RSA recipient) → decrypt
2. Encrypt single file (EC recipient) → decrypt
3. Encrypt multiple files (RSA + EC recipients) → decrypt
4. Encrypt DDOC file → decrypt and verify structure
5. Handle invalid certificates (wrong key usage)
6. Handle invalid private keys

### Interoperability Test Matrix

| Source        | Target | Format | Recipient Type | Status |

|--------------|--------|--------|----------------|--------|

| cdoc1-go      | cdoc4j | 1.1    | RSA            | [ ]    |

| cdoc1-go      | cdoc4j | 1.1    | EC             | [ ]    |

| cdoc4j        | cdoc1-go | 1.1    | RSA            | [ ]    |

| cdoc4j        | cdoc1-go | 1.1    | EC             | [ ]    |

| cdoc1-go      | cdoc4j | 1.0    | RSA            | [ ]    |

| DigiDoc Client | cdoc1-go | 1.1    | RSA            | [ ]    |

### Property-Based Tests (using `gopter` or `quick`)

- Encryption/decryption round-trip preserves data
- Padding adds/removes correct number of bytes
- EC key agreement produces same shared secret

### Fuzzing Targets

- XML parser (`cdoc/parser.go`)
- Certificate parser (`cert/parser.go`)
- Hex decoding (`internal/hex.go`)

---

## Risk Register

| Risk | Impact | Probability | Mitigation |

|------|--------|-------------|------------|

| AES-KW-256 implementation complexity | High | Medium | Use `golang.org/x/crypto` if available, or implement RFC 3394 with extensive tests |

| ConcatKDF parameter encoding mismatch | High | Medium | Compare byte-by-byte with cdoc4j reference implementation |

| XML namespace/attribute differences | Medium | Medium | Validate against cdoc4j XML output, use same formatting |

| EC point validation edge cases | Medium | Low | Implement comprehensive EC point validation, test with invalid points |

| Certificate parsing edge cases (malformed PEM/DER) | Low | Medium | Robust error handling, fuzz testing |

| Performance issues with large files | Low | Low | Use streaming I/O, benchmark against cdoc4j |

---

## Milestone Plan

### Milestone 1: Foundation (Week 1-2)

**Scope:** Epic 1, Epic 2, Epic 3 (crypto primitives)

**Acceptance:** All crypto primitives implemented and unit tested, certificate/key parsing working

### Milestone 2: XML Infrastructure (Week 3)

**Scope:** Epic 4, Epic 5, Epic 6

**Acceptance:** Can parse and generate CDOC 1.0 and 1.1 XML structures

### Milestone 3: Core APIs (Week 4)

**Scope:** Epic 7, Epic 8

**Acceptance:** Encryption and decryption APIs functional, basic integration tests passing

### Milestone 4: Testing & Interop (Week 5-6)

**Scope:** Epic 9

**Acceptance:** Unit coverage ≥80%, interop tests passing with cdoc4j

### Milestone 5: CLI & Polish (Week 6)

**Scope:** Epic 10, documentation, final bug fixes

**Acceptance:** CLI tool functional, all tests passing, README complete

---

## Repository Layout

```
cdoc1-go/
├── .github/
│   └── workflows/
│       └── ci.yml                 # CI pipeline (test, lint, fuzz)
├── cmd/
│   └── cdoc1/
│       └── main.go                # CLI tool
├── cdoc/
│   ├── builder.go                 # Encryption builder
│   ├── decrypter.go               # Decryption API
│   ├── parser.go                  # XML document parser
│   ├── composer.go                # XML document composer
│   └── version.go                 # Version detection
├── xmlenc/
│   ├── encrypted_data.go          # EncryptedData XML model
│   ├── encrypted_key.go           # EncryptedKey XML model
│   ├── agreement_method.go        # AgreementMethod (EC) XML model
│   ├── recipient.go               # Recipient interfaces
│   └── namespaces.go              # XML namespace constants
├── crypto/
│   ├── aes.go                     # AES-GCM/CBC operations
│   ├── rsa.go                     # RSA PKCS#1 v1.5
│   ├── ec.go                      # ECDH-ES + ConcatKDF
│   ├── padding.go                 # X.923, PKCS#7 padding
│   ├── keygen.go                  # Key generation
│   └── iv.go                      # IV generation
├── cert/
│   ├── parser.go                  # Certificate parsing (PEM/DER)
│   ├── validator.go               # Certificate validation
│   └── dn.go                      # DN utilities
├── key/
│   ├── pem.go                     # PEM key parsing
│   ├── pkcs8.go                   # PKCS#8 parsing
│   └── key.go                     # Key abstraction
├── internal/
│   ├── base64.go                  # Base64 utilities
│   ├── hex.go                     # Hex utilities
│   └── errors.go                  # Error types
├── testdata/
│   ├── rsa/                       # RSA test certificates/keys
│   ├── ecc/                       # EC test certificates/keys
│   ├── cdoc/                      # Reference CDOC files
│   └── samples/                   # Sample files for encryption
├── docs/
│   ├── architecture.md            # Architecture document (this plan)
│   └── api.md                     # API documentation
├── examples/
│   ├── encrypt.go                 # Encryption example
│   └── decrypt.go                 # Decryption example
├── go.mod
├── go.sum
├── LICENSE
├── README.md
├── CONTRIBUTING.md
└── .gitignore
```

---

## Implementation Notes

1. **AES-KW-256:** Go stdlib doesn't include AES key wrapping. Implement RFC 3394 or use `golang.org/x/crypto/nistec` if compatible.
2. **EC Curve:** Use `crypto/elliptic.P384()` for secp384r1, `crypto/ecdsa` for key operations.
3. **ConcatKDF:** Format: `ConcatKDF(sharedSecret, AlgorithmID|PartyUInfo|PartyVInfo)` where AlgorithmID = "ENCDOC-XML|1.1", PartyUInfo = ephemeral public key bytes, PartyVInfo = recipient certificate bytes. Use SHA-512.
4. **XML Encoding:** Use `encoding/xml` with proper namespace handling. Ensure UTF-8 encoding.
5. **Deterministic Output:** Only IVs and ephemeral keys are random. XML structure and encoding should be deterministic (use consistent formatting).

---

## Next Steps

1. Review and approve this plan
2. Set up repository skeleton (Epic 1)
3. Begin crypto primitive implementation (Epic 3)
4. Establish interop test environment with cdoc4j

### To-dos

- [ ] Initialize Go module, create package structure, set up CI/CD
- [ ] Implement certificate and private key parsing (PEM/DER, PKCS#8)
- [ ] Implement AES-GCM/CBC, RSA PKCS#1 v1.5, ECDH-ES, ConcatKDF, AES-KW-256
- [ ] Define XML Encryption 1.1 structures with correct namespace tags
- [ ] Implement XML parser for CDOC 1.0 and 1.1 documents
- [ ] Implement XML composer for generating CDOC documents
- [ ] Implement builder API for encryption with multi-recipient support
- [ ] Implement decrypter API with recipient selection
- [ ] Write comprehensive unit tests for all packages (≥80% coverage)
- [ ] Implement interoperability tests with cdoc4j (encrypt/decrypt both directions)
- [ ] Implement CLI tool (cdoc1) for encryption and decryption