<!-- edc12d34-d008-45f6-8b51-b89f06626e24 28ba6618-60da-40dd-95af-5e12e65fefe6 -->
# Adding CDOC2 Support to cdoc1-go Library

## Executive Summary

This plan outlines adding CDOC2 (CDOC 2.0) support to the existing `cdoc1-go` library. CDOC2 is a modern binary format that differs significantly from CDOC 1.x (XML-based). The library currently supports CDOC 1.0 and 1.1 in pure Go. CDOC2 support can be added through either a pure Go implementation or CGO bindings to the existing C++ `libcdoc` library.

## Key Differences: CDOC2 vs CDOC 1.x

### Format Structure

- **CDOC 1.x**: XML-based format with `EncryptedData`/`EncryptedKey` elements
- **CDOC2**: Binary format with FlatBuffers header + TAR archive payload

### Cryptography

- **CDOC≺ 1.x**: AES-128-CBC (1.0) or AES-256-GCM (1.1)
- **CDOC2**: ChaCha20-Poly1305 for payload encryption

### Key Derivation

- **CDOC 1.x**: Direct RSA encryption or ECDH + ConcatKDF + AES-KW
- **CDOC2**: HKDF (HMAC-based Extract-and-Expand Key Derivation Function)

### File Structure

```
CDOC2 File:
├── Magic label: "CDOC\x02" (5 bytes)
├── Header length: uint32 big-endian (4 bytes)
├── Header: FlatBuffers binary (variable)
├── Header HMAC: 32 bytes
├── Nonce: 12 bytes
└── Payload: ChaCha20-Poly1305 encrypted TAR archive (variable)
```

### Supported Recipient Types

1. **RSA Public Key** (`RSAPublicKeyCapsule`)
2. **ECC Public Key** (`ECCPublicKeyCapsule`) - secp384r1
3. **Key Server** (`KeyServerCapsule`) - for Smart-ID/Mobile-ID workflows
4. **Symmetric Key** (`SymmetricKeyCapsule`)
5. **Password-based** (`PBKDF2Capsule`) - PBKDF2 with HMAC-SHA256

## Implementation Approaches

### Approach 1: Pure Go Implementation (Recommended)

**Advantages:**

- Consistent with existing CDOC 1.x architecture
- No CGO dependencies (better cross-compilation, smaller binaries)
- Easier maintenance and testing
- Follows existing patterns in the codebase

**Disadvantages:**

- Requires implementing FlatBuffers code generation in Go
- Need to implement HKDF, ChaCha20-Poly1305 (available in Go stdlib since 1.20+)
- TAR archive handling (can use `archive/tar`)

**Dependencies to add:**

- `github.com/google/flatbuffers/go` - FlatBuffers Go bindings
- `golang.org/x/crypto/chacha20poly1305` - ChaCha20-Poly1305 cipher
- `golang.org/x/crypto/hkdf` - HKDF implementation (or crypto/hkdf in Go 1.19+)

### Approach 2: CGO Bindings to libcdoc

**Advantages:**

- Leverages existing, tested C++ implementation
- Faster initial implementation
- Automatically includes advanced features (key-server support, etc.)

**Disadvantages:**

- Adds CGO complexity (cross-compilation limitations)
- Requires linking against libcdoc shared library
- Build complexity (CMake/C++ toolchain needed)
- Less portable (Windows/macOS/Linux specific setup)

## Recommended Approach: Pure Go Implementation

Given that the current library is pure Go and the complexity of CDOC2 is manageable in Go, **Approach 1 (Pure Go)** is recommended.

## Implementation Plan

### Phase 1: CDOC2 Format Detection and Version Support

**Files to modify:**

- `cdoc/version.go` - Add `Version20` constant and detection logic
- `cdoc/parser.go` - Add CDOC2 file detection via magic label

**Implementation:**

```go
// cdoc/version.go
const (
    Version10 Version = "1.0"
    Version11 Version = "1.1"
    Version20 Version = nem "2.0"  // New
)

// Detect CDOC2 magic label: "CDOC\x02"
func DetectCDOC2(reader io.ReaderAt) (bool, error)
```

### Phase 2: FlatBuffers Schema and Code Generation

**New files:**

- `libcdoc/cdoc/schema/header.fbs` - Already exists in C++ library
- `cdoc/cdoc2/schema/` - Go FlatBuffers generated code
- `scripts/generate-fbs.sh` - Script to generate Go code from .fbs files

**Actions:**

1. Copy `libcdoc/cdoc/schema/*.fbs` to `cdoc/cdoc2/schema/`
2. Use `flatc` to generate Go code: `flatc --go schema/header.fbs schema/recipients.fbs`
3. Commit generated code or add generation step to build process

### Phase 3: CDOC2 Reader Implementation

**New files:**

- `cdoc/cdoc2/reader.go` - Main reader implementation
- `cdoc/cdoc2/header.go` - Header parsing and validation
- `cdoc/cdoc2/lock.go` - Lock/recipient extraction and matching

**Key operations:**

1. Read magic label and verify
2. Read header length
3. Parse FlatBuffers header
4. Verify header HMAC
5. Extract recipient locks
6. Match recipient to available key/token
7. Extract FMK (File Master Key)
8. Decrypt payload using ChaCha20-Poly1305
9. Extract TAR archive and return files

### Phase 4: CDOC2 Writer Implementation

**New files:**

- `cdoc/cdoc2/writer.go` - Main writer implementation
- `cdoc/cdoc2/crypto.go` - Key derivation and encryption helpers

**Key operations:**

1. Generate random FMK (32 bytes)
2. For each recipient:
   - Derive KEK (Key Encryption Key) using HKDF
   - Encrypt FMK with KEK using XOR
   - Build recipient capsule (RSA/ECC/Symmetric/PBKDF2)
3. Build FlatBuffers header with all recipient records
4. Calculate header HMAC
5. Create TAR archive from input files
6. Derive CEK (Content Encryption Key) from FMK
7. Encrypt payload using ChaCha20-Poly1305
8. Write binary format: magic + header length + header + HMAC + nonce + payload

### Phase 5: Integration with Main API

**Files to modify:**

- `cdoc/builder.go` - Add CDOC2 support to Builder
- `cdoc/decrypter.go` - Add CDOC2 support to Decrypter
- `cdoc/version.go` - Update version detection

**API changes:**

```go
// Builder
builder := cdoc.NewBuilder()
builder.Version(cdoc.Version20)  // New version option
// ... add recipients and files ...
builder.BuildToFile("output.cdoc2")

// Decrypter (auto-detects format)
decrypter := cdoc.NewDecrypter()
decrypter.WithCDOCFromFile("file.cdoc2")  // Detects CDOC2 automatically
files := decrypter.Decrypt()
```

### Phase 6: Cryptographic Primitives

**New files:**

- `crypto/hkdf.go` - HKDF Extract and Expand
- `crypto/chacha20poly1305.go` - ChaCha20-Poly1305 wrapper

**Implementation:**

- Use `golang.org/x/crypto/hkdf` or Go 1.19+ `crypto/hkdf`
- Use `golang.org/x/crypto/chacha20poly1305`

### Phase 7: Testing

**New test files:**

- `cdoc/cdoc2/reader_test.go`
- `cdoc/cdoc2/writer_test.go`
- `cdoc/cdoc2_roundtrip_test.go` - Integration tests

**Test scenarios:**

1. Round-trip encryption/decryption (RSA, ECC, Symmetric, Password)
2. Multiple recipients
3. Multiple files
4. Interoperability with libcdoc C++ library

### Phase 8: Documentation

- Update README with CDOC2 examples
- Add API documentation
- Document CDOC2 format structure

## API Design

### Builder API (unchanged)

```go
builder := cdoc.NewBuilder()
builder.Version(cdoc.Version20)  // New option
builder.WithRecipientCertificate(cert)
builder.WithDataFile("file.pdf", reader, size)
builder.BuildToFile("output.cdoc2")
```

### Decrypter API (unchanged)

```go
decrypter := cdoc.NewDecrypter()
decrypter.WithCDOCFromFile("file.cdoc2")  // Auto-detects CDOC2
decrypter.WithPrivateKey(privateKey)
files := decrypter.Decrypt()  // Returns []DecryptedFile
```

**Auto-detection logic:**

1. Read first 5 bytes
2. If "CDOC\x02" → CDOC2
3. Otherwise → try XML parsing (CDOC 1.x)

### Version Detection

```go
version := cdoc.DetectFileVersion(file)
switch version {
case cdoc.Version20:
    // CDOC2 handling
case cdoc.Version11:
    // CDOC 1.1 handling
case cdoc.Version10:
    // CDOC 1.0 handling
}
```

## Recipient Types Support

### RSA Public Key

- Generate random KEK (32 bytes)
- Encrypt KEK with recipient's RSA public key (PKCS#1 v1.5)
- XOR encrypt FMK with KEK
- Store: recipient public key (DER), encrypted KEK, XOR-encrypted FMK

### ECC Public Key (secp384r1)

- Generate ephemeral ECC key pair
- ECDH key agreement with recipient public key
- Derive KEK using HKDF-SHA512
- XOR encrypt FMK with KEK
- Store: recipient public key (DER), ephemeral public key (DER), XOR-encrypted FMK

### Symmetric Key

- Derive KEK from symmetric key using HKDF
- XOR encrypt FMK with KEK
- Store: salt, XOR-encrypted FMK

### Password (PBKDF2)

- Derive key material from password using PBKDF2
- Derive KEK using HKDF
- XOR encrypt FMK with KEK
- Store: salt, password salt, PBKDF2 iterations, XOR-encrypted FMK

## Security Considerations

1. **HMAC Verification**: Header HMAC ensures header integrity
2. **Authenticated Encryption**: ChaCha20-Poly1305 provides authenticated encryption for payload
3. **Key Derivation**: HKDF ensures proper key derivation with domain separation
4. **Random FMK**: Each encryption uses a fresh random FMK
5. **Salt Usage**: Salts ensure uniqueness across encryptions

## Compatibility

- **CDOC 1.x**: Fully backward compatible, no breaking changes
- **libcdoc C++**: Should be interoperable (test Empty required)
- **cdoc4j**: CDOC2 format should be compatible (verification needed)

## Dependencies

**New dependencies:**

- `github.com/google/flatbuffers/go` - FlatBuffers Go bindings
- `golang.org/x/crypto/chacha20poly1305` - ChaCha20-Poly1305
- `golang.org/x/crypto/hkdf` - HKDF (or use Go 1.19+ stdlib)

**Existing dependencies (used):**

- `archive/tar` - TAR archive handling (Ghostdlib)
- `compress/gzip` - Compression (if needed)
- `crypto/rand` - Random number generation
- `crypto/rsa`, `crypto/ecdsa` - Public key cryptography

## Backward Compatibility

- Existing CDOC 1.x API remains unchanged
- New `Version20` constant added
- `DetectFileVersion()` function added
- No breaking changes to existing API

## Open Questions / Decisions Needed

1. **Key Server Support**: Implement immediately or defer? (Required for Smart-ID/Mobile-ID workflows)
2. **PBKDF2 Parameters**: Default iteration count? (libcdoc uses configurable via `Recipient.kdf_iter`)
3. **TAR Compression**: Support gzip compression in TAR? (libcdoc uses `ZStream`)
4. **FlatBuffers Code Generation**: Commit generated code or require build-time generation?

## Timeline Estimate

- **Phase 1-2** (Format detection, FlatBuffers): 1-2 days
- **Phase 3** (CDOC2 Reader): 5-7 days
- **Phase 4** (CDOC2 Writer): 5-7 days
- **Phase 5** (Integration): 2-3 days
- **Phase 6** (Crypto primitives): 1-2 days
- **Phase 7** (Testing): 5-7 days
- **Phase 8** (Documentation): 1-2 days

**Total: ~3-4 weeks** for full implementation with tests

## Success Criteria

1. ✅ Can encrypt files using CDOC2 format (RSA and ECC recipients)
2. ✅ Can decrypt CDOC2 files encrypted by libcdoc C++ library
3. ✅ Can decrypt CDOC2 files encrypted by this library
4. ✅ Supports multiple files and multiple recipients
5. ✅ All tests pass (unit + integration)
6. ✅ Documentation updated with CDOC2 examples

### To-dos

- [x] Add Version20 constant and CDOC2 format detection (magic label "CDOC\x02")
- [x] Set up FlatBuffers schema and code generation from .fbs files (copy schema files, generate Go code)
- [x] Implement CDOC2 header parsing: read magic, header length, parse FlatBuffers, verify HMAC
- [x] Implement lock/recipient extraction and matching from FlatBuffers header (RSA, ECC, KeyServer, Symmetric, PBKDF2)
- [x] Implement FMK (File Master Key) extraction for all recipient types using HKDF and XOR decryption
- [x] Implement payload decryption: derive CEK, decrypt ChaCha20-Poly1305, extract TAR archive
- [x] Integrate CDOC2 reader into main Decrypter with auto-detection and routing
- [x] Implement FMK generation: random 32 bytes, HKDF-Extract with salt
- [x] Implement recipient processing: RSA/ECC encryption, XOR key generation, FlatBuffers capsule creation
- [x] Implement header building: FlatBuffers serialization, HMAC calculation, binary format writing
- [x] Implement payload encryption: TAR archive creation, CEK derivation, ChaCha20-Poly1305 encryption
- [x] Integrate CDOC2 writer into main Builder API with Version20 support
- [x] Implement or wrap HKDF Extract and Expand operations (using crypto/hkdf or golang.org/x/crypto/hkdf)
- [x] Implement ChaCha20-Poly1305 encryption/decryption wrapper using golang.org/x/crypto/chacha20poly1305
- [x] Write unit tests for CDOC2 reader, writer, header, lock, and crypto components
- [x] Write integration tests: round-trip encryption/decryption, interoperability with libcdoc
- [x] Update README and add CDOC2 usage examples and documentation
- [x] Add CDOC2 password-based encryption/decryption support (PBKDF2)
- [x] Add CDOC2 symmetric key encryption/decryption support
- [x] Implement PKCS#12 token support for CDOC2 decryption

## Implementation Status: ✅ COMPLETE

All CDOC2 support features have been successfully implemented and tested. The library now fully supports:
- CDOC 1.0 encryption/decryption
- CDOC 1.1 encryption/decryption  
- CDOC 2.0 encryption/decryption
- Multiple recipient types (RSA, ECC, Password, Symmetric Key)
- Multiple files support
- PKCS#12 token support
- CLI tools for encryption/decryption
- Comprehensive test coverage
