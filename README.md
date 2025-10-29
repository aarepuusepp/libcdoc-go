# cdoc1-go

Go library for Estonian CDOC 1.0 and 1.1 encryption/decryption using certificate-based keys.

## Features

- **CDOC 1.0 support**: AES-128-CBC encryption with RSA recipients
- **CDOC 1.1 support**: AES-256-GCM encryption with RSA and EC recipients
- **Certificate-based**: Uses X.509 certificates (PEM/DER) and private keys (PEM/PKCS#8)
- **Multiple recipients**: Support for multiple recipients with mixed RSA/EC certificates
- **Interoperable**: Compatible with cdoc4j and official DigiDoc clients

## Requirements

- Go ≥ 1.22

## Installation

```bash
go get github.com/yourorg/cdoc1-go
```

## Quick Start

### Encryption

```go
package main

import (
    "os"
    "github.com/yourorg/cdoc1-go/cdoc"
)

func main() {
    cert, _ := cdoc.LoadCertificate("recipient_cert.pem")
    builder := cdoc.NewBuilder()
    builder.WithDataFile("document.pdf").
        WithRecipient(cert).
        BuildToFile("document.cdoc")
}
```

### Decryption

```go
package main

import (
    "github.com/yourorg/cdoc1-go/cdoc"
)

func main() {
    key, _ := cdoc.LoadPrivateKey("private_key.pem")
    decrypter := cdoc.NewDecrypter().
        WithPrivateKey(key).
        WithCDOC("document.cdoc").
        DecryptToDirectory("./output")
}
```

## License

MIT License

