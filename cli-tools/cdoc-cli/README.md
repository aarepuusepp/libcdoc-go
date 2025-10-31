# cdoc CLI Tool

Command-line interface for encrypting and decrypting CDOC documents (part of libcdoc-go).

Supports CDOC 1.0, 1.1, and 2.0 formats.

## Installation

Build from source (from the cli-tools/cdoc-cli directory):
```bash
cd cli-tools/cdoc-cli
go build -o cdoc .
```

Or build from the project root (alternative method):
```bash
cd cli-tools/cdoc-cli
go build -o cdoc.exe .
```

Or install globally (will be available as `cdoc` command):
```bash
go install github.com/aarepuusepp/libcdoc-go/v2/cli-tools/cdoc-cli@latest
```

**Note:** Since `cdoc-cli` has its own `go.mod` file (making it a separate module), it must be built from within the `cli-tools/cdoc-cli` directory or using the `go install` command.

## Usage

### Encrypt Files

Encrypt a single file with a recipient certificate:
```bash
cdoc encrypt -f document.pdf -r cert.pem -o document.cdoc
```

Encrypt multiple files with multiple recipients (comma-separated):
```bash
cdoc encrypt -f file1.txt,file2.txt -r cert1.pem,cert2.pem -o output.cdoc
```

Specify CDOC version (1.0, 1.1, or 2.0, default: 1.1):
```bash
cdoc encrypt -f document.pdf -r cert.pem -c 1.0 -o document.cdoc
cdoc encrypt -f document.pdf -r cert.pem -c 2.0 -o document.cdoc2
```

Encrypt with password (CDOC 2.0 only):
```bash
cdoc encrypt -f document.pdf -p password -c 2.0 -o document.cdoc2
```

Encrypt with symmetric key (CDOC 2.0 only, 32-byte key file):
```bash
cdoc encrypt -f document.pdf -s keyfile.bin -c 2.0 -o document.cdoc2
```

### Decrypt Files

Decrypt a CDOC file using a private key:
```bash
cdoc decrypt -f document.cdoc -k private_key.pem -o ./decrypted/
```

Decrypt with certificate for recipient selection (multiple recipients):
```bash
cdoc decrypt -f document.cdoc -k private_key.pem -c cert.pem -o ./decrypted/
```

Decrypt with password (CDOC 2.0 only):
```bash
cdoc decrypt -f document.cdoc2 -p password -o ./decrypted/
```

Decrypt with symmetric key (CDOC 2.0 only):
```bash
cdoc decrypt -f document.cdoc2 -s keyfile.bin -o ./decrypted/
```

## Options

### Encrypt Options
- `-f, --files`: Input file(s) to encrypt (comma-separated)
- `-r, --recipient-certs`: Recipient certificate(s) (comma-separated, for CDOC 1.0/1.1/2.0)
- `-p, --password`: Password for encryption (CDOC 2.0 only)
- `-s, --symmetric-key`: Symmetric key file (32 bytes, CDOC 2.0 only)
- `-o, --output`: Output CDOC file (default: `<first-input-file>.cdoc` or `.cdoc2` for CDOC 2.0)
- `-c, --cdoc-version`: CDOC version "1.0", "1.1", or "2.0" (default: "1.1")
- `--iterations`: PBKDF2 iterations for password (CDOC 2.0, default: 100000)
- `-h, --help`: Show help

### Decrypt Options
- `-f, --file`: CDOC file to decrypt (required)
- `-k, --key`: Private key file in PEM format (for certificate-based decryption)
- `-p, --password`: Password (for CDOC 2.0 password-based decryption)
- `-s, --symmetric-key`: Symmetric key file (32 bytes, for CDOC 2.0 symmetric key decryption)
- `-c, --cert`: Certificate file for recipient selection (optional, needed for multi-recipient CDOCs)
- `-o, --output`: Output directory (default: current directory)
- `--pkcs12`: PKCS#12 keystore file (.p12 or .pfx)
- `--p12password`: PKCS#12 keystore password
- `--pkcs11`: Use PKCS#11 token for decryption
- `--library`: Path to PKCS#11 library (required for --pkcs11)
- `--pin`: PKCS#11 token PIN (required for --pkcs11)
- `-h, --help`: Show help

## Examples

### Basic Encryption
```bash
# Encrypt a document
cdoc encrypt -f secret.pdf -r recipient_cert.pem

# Output will be: secret.cdoc
```

### Multiple Files and Recipients
```bash
cdoc encrypt -f doc1.pdf,doc2.txt -r cert1.pem,cert2.pem -o bundle.cdoc
```

### Decryption
```bash
# Decrypt to current directory
cdoc decrypt -f secret.cdoc -k my_private_key.pem

# Decrypt to specific directory
cdoc decrypt -f secret.cdoc -k my_private_key.pem -o ./decrypted_files/
```

## Supported Formats

- **CDOC 1.0**: AES-128-CBC, RSA recipients only
- **CDOC 1.1**: AES-256-GCM, RSA and EC recipients
- **CDOC 2.0**: ChaCha20-Poly1305, multiple recipient types (certificate, password, symmetric key)

## Certificate and Key Formats

- Certificates: PEM or DER format (X.509)
- Private Keys: PEM format (PKCS#1 RSA, PKCS#8 RSA/EC)

## Notes

- File name collisions during decryption are handled automatically (appends `_1`, `_2`, etc.)
- The tool is compatible with CDOC files created by `cdoc4j`
- For multi-recipient CDOCs, provide the certificate matching your private key using `-c` flag

