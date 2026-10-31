# libcdoc-go

[Go API reference](https://pkg.go.dev/github.com/aarepuusepp/libcdoc-go/v2/cdoc)

**Released version: 2.0.8. Toolchain: Go 1.27.3 or later.**
Go library for CDOC 1.0/1.1 and CDOC 2.0 encryption/decryption.
[Release notes](RELEASE-NOTES.md), [development](CONTRIBUTING.md),
[Windows testing](docs/WINDOWS_TESTING_GUIDE.md),
[implementation boundaries](docs/IMPLEMENTATION_STATUS.md).

## Supported paths

| Path | Implementation and acceptance |
|---|---|
| CDOC 1.0 | XML, AES-128-CBC, RSA recipients; software regression coverage |
| CDOC 1.1 | XML, AES-256-GCM, RSA/EC recipients; software and application card tests |
| Standalone CDOC 2.0 | FlatBuffers, ChaCha20-Poly1305, zlib TAR; RSA/EC, password and symmetric-key APIs |
| CDOC2 Key Capsule | Configured ECC/RSA server flows; mock/integration coverage is not live RIA acceptance |
| SID/MID Key Shares | External proof-profile recovery remains blocked; draft APIs are not production support |

Standard standalone CDOC2 uses uncompressed EC points, HKDF-SHA256, RSA PKCS#1
public-key encoding and RSA-OAEP-SHA256. Writer key labels are nonempty, preserving
explicit labels. Historical SPKI/SHA512/PKCS1-v1.5 and gzip encodings remain readable.
No weaker algorithm is retried after an authentication error.

On 2026-10-31 the user confirmed real-card decryption of corrected P-384 output in
DigiDoc4 4.11.1.5434 and standalone encryption/decryption in Digisign with EID-PD
2.1.10. This does not certify every card/recipient or live central service.
CDOC2 public-key labels do not necessarily include an X.509 certificate.

## Installation

```sh
go get github.com/aarepuusepp/libcdoc-go/v2@v2.0.8
go mod verify
```

Use `/v2` imports. Commit the application's go.mod/go.sum. Published builds need
no sibling checkout or local replace. Software/PKCS#12 builds can disable CGO;
PKCS#11 needs CGO, a matching C compiler and native module. NFC/PACE, browser
consent and PIN UI are supplied by EID-PD, not this library.

## Encrypt a standalone CDOC2 file

Complete program; arguments are certificate, input file and output container.
Recipient/file methods return errors, so they cannot be chained as fluent setters.

```go
package main

import (
    "fmt"
    "os"
    "github.com/aarepuusepp/libcdoc-go/v2/cdoc"
)

func main() {
    if len(os.Args) != 4 {
        fmt.Fprintln(os.Stderr, "usage: encrypt recipient.pem input.txt output.cdoc2")
        os.Exit(2)
    }
    b := cdoc.NewBuilder().Version(cdoc.Version20)
    if err := b.WithRecipientFromPath(os.Args[1]); err != nil { panic(err) }
    if err := b.WithDataFileFromPath(os.Args[2]); err != nil { panic(err) }
    if err := b.BuildToFile(os.Args[3]); err != nil { panic(err) }
}
```

Use Version11/Version10 for XML. Add multiple files/recipients before BuildToFile.
For CDOC2 password/symmetric recipients check errors from WithPassword,
WithPasswordAndIterations and WithSymmetricKey. Never embed real secrets in code.

## Decrypt

Inside an error-returning function:

```go
d := cdoc.NewDecrypter()
if err := d.WithPrivateKeyFromFile("private-key.pem"); err != nil { return err }
if err := d.WithCDOCFromFile("document.cdoc2"); err != nil { return err }
files, err := d.Decrypt()
if err != nil { return err }
for _, file := range files {
    // Authenticated file.Name and file.Content; apply destination policy.
    _ = file
}
```

WithCDOCFromFile/WithPrivateKeyFromFile return errors; WithPrivateKey,
WithCertificate, WithToken, WithPassword and WithSymmetricKey are setters.
Browser card flows use PrepareClientUnwrap and FinishClientDecrypt with a local
reader private-key operation. PIN is never sent to the website/backend.
See [PKCS#11 notes](docs/PKCS11_EC_LIMITATION.md).

## Validation and publishing

```sh
go mod verify
go test ./...
go vet ./...
```

Race checks: enable CGO and a matching compiler, then `go test -race ./...`.
[Independent vectors](cdoc/testdata/cdoc2-reference/README.md) test exact hashes
and tampering. CLI tools are nested modules; build from their own directories.
See [publishing](docs/PUBLISHING.md). VERSION is the source of runtime version.
Existing release tags are immutable; documentation updates do not move them.

MIT license: [LICENSE](LICENSE).

## Nested CLI validation

Run `pwsh -File cli-tools/Test-Modules.ps1` from this repository. The three
nested modules use Go 1.27.3; the two consumers pin published libcdoc-go v2.0.8
without local replacements. The dedicated CI job verifies/tests/vets/builds each
and checks an isolated multi-file roundtrip plus wrong-key rejection. The root
`go test ./...` alone does not enter nested Go modules. CLI --version reports
the linked library's embedded version rather than a stale CLI constant.
