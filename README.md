# libcdoc-go

[![Go Reference](https://pkg.go.dev/badge/github.com/aarepuusepp/libcdoc-go/v2.svg)](https://pkg.go.dev/github.com/aarepuusepp/libcdoc-go/v2)

Go library for Estonian CDOC encryption/decryption supporting CDOC 1.0, 1.1, and 2.0 formats.

**Version:** 2.0.4

## Features

### CDOC 1.0 & 1.1 Support
- **CDOC 1.0**: AES-128-CBC encryption with RSA recipients
- **CDOC 1.1**: AES-256-GCM encryption with RSA and EC recipients
- **Certificate-based**: Uses X.509 certificates (PEM/DER) and private keys (PEM/PKCS#8)
- **Multiple recipients**: Support for multiple recipients with mixed RSA/EC certificates
- **Interoperable**: Compatible with cdoc4j and official DigiDoc clients

### CDOC 2.0 Support (NEW)
- **Modern binary format**: FlatBuffers-based header with ChaCha20-Poly1305 payload encryption
- **Multiple recipient types**:
  - Certificate-based (RSA/ECC public keys)
  - Password-based (PBKDF2 with configurable iterations)
  - Symmetric key-based (256-bit keys)
- **Efficient**: TAR archive packaging with zlib compression
- **Secure**: HMAC-verified headers and authenticated encryption
- **Automatic format detection**: Seamlessly handles both CDOC 1.x and CDOC 2.0 formats

## Requirements

- Go ≥ 1.22

## Installation

### From Public Repository

```bash
go get github.com/aarepuusepp/libcdoc-go/v2@v2.0.4
```

For backend builds that should resolve the library from the public Go module
proxy, do not use a local `replace` directive. The consuming module should have
only a normal requirement:

```go
require github.com/aarepuusepp/libcdoc-go/v2 v2.0.4
```

Then run:

```bash
go mod tidy
go mod download github.com/aarepuusepp/libcdoc-go/v2@v2.0.4
```

## Publishing a New Version to the Public Go Proxy

The module path is `github.com/aarepuusepp/libcdoc-go/v2`, so every public
release must be available from a public Git repository at
`https://github.com/aarepuusepp/libcdoc-go` and must use a semantic version tag
that starts with `v2.`.

1. Ensure the GitHub repository is public:

```bash
git ls-remote https://github.com/aarepuusepp/libcdoc-go.git refs/heads/main
```

This command must work without credentials. If it asks for authentication, make
the GitHub repository public before publishing the version.

2. Commit the release changes:

```bash
git status --short
git add README.md go.mod go.sum cdoc crypto key cert internal xmlenc
git commit -m "Release v2.0.4"
```

3. Create and push the `v2` semantic version tag:

```bash
git tag -a v2.0.4 -m "v2.0.4"
git push github main
git push github v2.0.4
```

4. Warm and verify the public Go proxy:

```bash
GOPROXY=https://proxy.golang.org GONOPROXY= GONOSUMDB= \
  go mod download github.com/aarepuusepp/libcdoc-go/v2@v2.0.4
```

The proxy metadata should also be reachable directly:

```text
https://proxy.golang.org/github.com/aarepuusepp/libcdoc-go/v2/@v/v2.0.4.info
```

5. Update consumers, for example `digisign-encrypt-go`, by removing any local
`replace github.com/aarepuusepp/libcdoc-go/v2 => ...` directive and requiring
the published version:

```bash
go get github.com/aarepuusepp/libcdoc-go/v2@v2.0.4
go mod tidy
go test ./...
```

### Using Locally Without Publishing

For testing and local development without publishing to a public repository, see the [Windows Testing Guide](docs/WINDOWS_TESTING_GUIDE.md) for detailed instructions on:

- Using the library on Windows
- Setting up local development with `replace` directives
- Using Go workspaces for multi-module development
- Setting up private Git repositories
- Quick testing examples

**Quick Start (Local Path):**

1. Create your test application:
```bash
mkdir my-app && cd my-app
go mod init my-app
```

2. Add to your `go.mod`:
```go
require github.com/aarepuusepp/libcdoc-go/v2 v2.0.4
replace github.com/aarepuusepp/libcdoc-go/v2 => C:\path\to\libcdoc-go
```

3. Run `go mod tidy` and start coding!

## Quick Start

### CDOC 1.x Encryption and Decryption

```go
package main

import (
    "github.com/aarepuusepp/libcdoc-go/v2/cdoc"
)

func main() {
    // Encryption
    cert, _ := loadCertificate("recipient_cert.pem") // *x509.Certificate
    builder := cdoc.NewBuilder().
        Version(cdoc.Version11). // or Version10
        WithRecipientCertificate(cert).
        WithDataFile("document.pdf", fileReader, fileSize).
        BuildToFile("document.cdoc")
    
    // Decryption
    key, _ := key.ParsePrivateKey(keyBytes) // *key.PrivateKey
    files, _ := cdoc.NewDecrypter().
        WithPrivateKey(key).
        WithCDOCFromFile("document.cdoc").
        Decrypt()
}
```

### CDOC 2.0 Encryption

CDOC 2.0 supports multiple recipient types. The library automatically detects the format during decryption.

#### Certificate-Based Encryption (CDOC 2.0)

```go
package main

import (
    "crypto/x509"
    "github.com/aarepuusepp/libcdoc-go/v2/cdoc"
)

func main() {
    cert, _ := loadCertificate("recipient_cert.pem") // *x509.Certificate
    
    builder := cdoc.NewBuilder().
        Version(cdoc.Version20).
        WithRecipientCertificate(cert).
        WithDataFile("document.pdf", fileReader, fileSize).
        BuildToFile("document.cdoc2")
}
```

#### Password-Based Encryption (CDOC 2.0)

```go
package main

import (
    "bytes"
    "github.com/aarepuusepp/libcdoc-go/v2/cdoc"
)

func main() {
    password := "my-secure-password"
    
    builder := cdoc.NewBuilder().
        Version(cdoc.Version20).
        WithPassword(password). // Default: 100,000 iterations
        // Or with custom iterations:
        // WithPasswordAndIterations(password, 200000).
        WithDataFile("secret.pdf", fileReader, fileSize).
        BuildToFile("document.cdoc2")
}
```

#### Symmetric Key-Based Encryption (CDOC 2.0)

```go
package main

import (
    "crypto/rand"
    "github.com/aarepuusepp/libcdoc-go/v2/cdoc"
)

func main() {
    // Generate or use a 256-bit (32-byte) symmetric key
    symmetricKey := make([]byte, 32)
    rand.Read(symmetricKey)
    
    builder := cdoc.NewBuilder().
        Version(cdoc.Version20).
        WithSymmetricKey(symmetricKey).
        WithDataFile("document.pdf", fileReader, fileSize).
        BuildToFile("document.cdoc2")
}
```

#### Multiple Recipient Types (CDOC 2.0)

```go
package main

import (
    "crypto/rand"
    "github.com/aarepuusepp/libcdoc-go/v2/cdoc"
)

func main() {
    cert, _ := loadCertificate("recipient_cert.pem")
    password := "shared-password"
    symmetricKey := make([]byte, 32)
    rand.Read(symmetricKey)
    
    // Encrypt with multiple recipient types
    builder := cdoc.NewBuilder().
        Version(cdoc.Version20).
        WithRecipientCertificate(cert).
        WithPassword(password).
        WithSymmetricKey(symmetricKey).
        WithDataFile("document.pdf", fileReader, fileSize).
        BuildToFile("document.cdoc2")
    
    // Any of the recipients can decrypt:
    // - Certificate + private key
    // - Password
    // - Symmetric key
}
```

### CDOC 2.0 Decryption

The decrypter automatically detects CDOC 1.x vs CDOC 2.0 format.

#### Certificate-Based Decryption

```go
package main

import (
    "github.com/aarepuusepp/libcdoc-go/v2/cdoc"
    "github.com/aarepuusepp/libcdoc-go/v2/key"
)

func main() {
    privKey, _ := key.ParsePrivateKey(keyBytes) // *key.PrivateKey
    
    files, _ := cdoc.NewDecrypter().
        WithPrivateKey(privKey).
        WithCDOCFromFile("document.cdoc2").
        Decrypt()
    
    // files contains []DecryptedFile with Name and Content
    for _, file := range files {
        // Process file.Name and file.Content
    }
}
```

#### Password-Based Decryption

```go
package main

import (
    "github.com/aarepuusepp/libcdoc-go/v2/cdoc"
)

func main() {
    password := "my-secure-password"
    
    files, _ := cdoc.NewDecrypter().
        WithPassword(password).
        WithCDOCFromFile("document.cdoc2").
        Decrypt()
}
```

#### Symmetric Key-Based Decryption

```go
package main

import (
    "github.com/aarepuusepp/libcdoc-go/v2/cdoc"
)

func main() {
    symmetricKey := []byte{...} // The same 32-byte key used for encryption
    
    files, _ := cdoc.NewDecrypter().
        WithSymmetricKey(symmetricKey).
        WithCDOCFromFile("document.cdoc2").
        Decrypt()
}
```

### Automatic Format Detection

The library automatically detects CDOC format (1.0, 1.1, or 2.0) during decryption:

```go
files, _ := cdoc.NewDecrypter().
    WithPrivateKey(privateKey).
    WithCDOCFromFile("document.cdoc"). // Could be CDOC 1.0, 1.1 or 2.0
    Decrypt() // Automatically detects and handles the format
```

### Multiple Files (CDOC 2.0)

CDOC 2.0 supports packaging multiple files in a single container:

```go
builder := cdoc.NewBuilder().
    Version(cdoc.Version20).
    WithRecipientCertificate(cert).
    WithDataFile("file1.txt", file1Reader, file1Size).
    WithDataFile("file2.pdf", file2Reader, file2Size).
    WithDataFile("subdir/file3.dat", file3Reader, file3Size).
    BuildToFile("archive.cdoc2")

// Decryption returns all files
files, _ := decrypter.Decrypt()
for _, file := range files {
    // file.Name contains the original path
    // file.Content contains the file data
}
```

## API Reference

### Builder Methods (CDOC 2.0)

- `Version(Version20)` - Set CDOC version to 2.0
- `WithRecipientCertificate(*x509.Certificate)` - Add certificate-based recipient
- `WithPassword(string)` - Add password-based recipient (default: 100,000 PBKDF2 iterations)
- `WithPasswordAndIterations(string, int32)` - Add password-based recipient with custom iterations
- `WithSymmetricKey([]byte)` - Add symmetric key recipient (must be 32 bytes)
- `WithDataFile(string, io.Reader, int64)` - Add file to encrypt

### Decrypter Methods (CDOC 2.0)

- `WithPrivateKey(*key.PrivateKey)` - Use private key for certificate-based decryption
- `WithPassword(string)` - Use password for password-based decryption
- `WithSymmetricKey([]byte)` - Use symmetric key for decryption
- `WithCDOCFromFile(string)` - Load CDOC file from path
- `WithCDOC(io.Reader)` - Load CDOC from reader
- `Decrypt()` - Decrypt and return files
- `DecryptToDirectory(string)` - Decrypt and write files to directory

### Format Detection

The library automatically detects CDOC format:
- **CDOC 2.0**: Detected by magic label `"CDOC\x02"` at the start of the file
- **CDOC 1.x**: Detected by XML signature or header structure

No manual format selection is needed - the decrypter handles it automatically.

## CDOC 2.0 Technical Details

### Security Features

- **Payload Encryption**: ChaCha20-Poly1305 authenticated encryption
- **Key Derivation**: HKDF (HMAC-based Key Derivation Function) with SHA-256 for standard local CDOC2
- **Header Integrity**: HMAC-SHA256 verification of header data
- **Key Management**: 
  - RSA: OAEP with SHA-256/MGF1-SHA256 and an empty label (local CDOC2)
  - ECC: ECDH key agreement with ephemeral keys (secp384r1)
  - Password: PBKDF2 with configurable iterations (default: 100,000)
  - Symmetric: HKDF-based key derivation

### File Format Structure

```
CDOC2 File:
├── Magic Label: "CDOC\x02" (5 bytes)
├── Header Length: uint32 (4 bytes, big-endian)
├── Header Data: FlatBuffers serialized header
│   ├── Recipients array
│   │   ├── Capsule (RSA/ECC/Symmetric/PBKDF2/KeyServer/KeyShares)
│   │   ├── Key Label
│   │   ├── Encrypted FMK (XOR encrypted)
│   │   └── FMK Encryption Method
│   └── Payload Encryption Method
├── Header HMAC: SHA-256 HMAC (32 bytes)
├── Nonce: 12 bytes (ChaCha20-Poly1305)
└── Encrypted Payload:
    ├── Compressed TAR archive (zlib)
    └── Contains one or more files
```

### Supported Recipient Types

1. **RSA Public Key**: RSA-encrypted KEK
2. **ECC Public Key**: ECDH key agreement (secp384r1)
3. **Password (PBKDF2)**: Password-derived KEK with configurable iterations
4. **Symmetric Key**: HKDF-derived KEK from shared secret
5. **Key Server** (schema supported, not yet implemented)
6. **Key Shares** (schema supported, not yet implemented)

## License

MIT License



### Local CDOC2 interoperability (2026-10-31)

Local certificate recipients do not require a key transfer server. New containers
use TLS uncompressed EC points (P-256/P-384/P-521), HKDF-SHA256, RSA PKCS#1
public-key encoding with RSA-OAEP-SHA256, and a zlib-compressed TAR payload.
`PrepareClientUnwrap` accepts the certificate read from the inserted card; a
CDOC2 container contains public keys, not necessarily certificates.
Both `FinishClientDecrypt` and direct software/token decryption support this path.
RSA hardware tokens must implement `DecryptRSAOAEP`; older Token implementations
still work for CDOC1. NFC ID-card ECDH uses the same CDOC2 challenge path.

Historical libcdoc-go SPKI/SHA512/PKCS1-v1.5 and gzip files remain readable.
Compatibility is selected by the historical key encoding, never by retrying a
weaker algorithm after an authentication error. Writers emit the standard local
format only. Central key-server and SID/MID profiles are separate and are not
certified by the local interoperability tests.

See `cdoc/testdata/cdoc2-reference/README.md` for independent Open-EID Java
fixtures, public test-key provenance and licenses. `TestCDOC2IndependentReference`
checks exact payload hashes, wrong keys and payload tampering;
`TestCDOC2WriterStandardEncoding` independently decodes new RSA and EC output.
Real-card CDOC2 acceptance in DigiDoc4 and Digisign remains a separate manual test.

CI formatting checks Git-tracked Go sources with `gofmt -s -l`; the previous failed GitHub run
stopped at this check before vet/tests. CI now uses Node24-era checkout/setup-go
and Codecov actions on explicit Ubuntu 24.04 instead of a moving ubuntu-latest.
