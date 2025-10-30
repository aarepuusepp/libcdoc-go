# Windows Test Example

Comprehensive test application that demonstrates encryption and decryption using the `cdoc1-go` library with CDOC 1.1 format.

## What It Tests

This example performs 8 complete test scenarios:

1. **RSA Encryption**: Encrypts the test PDF file using RSA certificate
2. **RSA Decryption**: Decrypts the RSA-encrypted CDOC using PKCS12 keystore
3. **ECC Encryption**: Encrypts the test PDF file using ECC (Elliptic Curve) certificate
4. **ECC Decryption**: Decrypts the ECC-encrypted CDOC using PKCS12 keystore
5. **Multiple Recipients**: Encrypts with both RSA and ECC recipients in one CDOC file (single file)
6. **Multiple Files**: Encrypts both PDF and DOCX files with RSA certificate
7. **Multiple Files Decryption**: Decrypts a CDOC containing multiple files
8. **Multiple Files + Multiple Recipients**: Encrypts both PDF and DOCX files with both RSA and ECC recipients

## Prerequisites

1. Go 1.22 or later installed
2. The library set up using one of the methods from `docs/WINDOWS_TESTING_GUIDE.md`
3. Test files in place:
   - `testdata/samples/TEST-öäüõÖÄÜÕžšŽŠ-01.pdf` (test PDF with Estonian characters)
   - `testdata/samples/TEST-öäüõÖÄÜÕžšŽŠ-01.docx` (test DOCX with Estonian characters)
   - `testdata/rsa/auth_cert.pem` and `testdata/rsa/rsa.p12` (RSA test certificate and keystore)
   - `testdata/ecc/auth_cert.pem` and `testdata/ecc/ecc.p12` (ECC test certificate and keystore)

## Setup

### Option 1: Using Local Path Replacement

1. Create a `go.mod` in this directory:
```bash
cd examples/windows-test
go mod init windows-test
```

2. Edit `go.mod` to add:
```go
module windows-test

go 1.22

require github.com/yourorg/cdoc1-go v0.0.0

replace github.com/yourorg/cdoc1-go => ../../
```

3. Run `go mod tidy`

### Option 2: Using Go Workspace

1. From the root directory, initialize workspace:
```bash
cd C:\WebROOT\TARKVARA.NEW\Digisign\cdoc1-go
go work init
go work use .
go work use ./examples/windows-test
```

2. In the example directory:
```bash
cd examples/windows-test
go mod init windows-test
go mod tidy
```

## Running the Test

```bash
go run main.go
```

The application will automatically:
- Verify all test files exist
- Encrypt the PDF with RSA certificate → creates `TEST_RSA_encrypted.cdoc`
- Decrypt RSA CDOC → creates `decrypted_rsa/` directory
- Encrypt the PDF with ECC certificate → creates `TEST_ECC_encrypted.cdoc`
- Decrypt ECC CDOC → creates `decrypted_ecc/` directory
- Encrypt with both RSA and ECC recipients → creates `TEST_MULTI_encrypted.cdoc`
- Encrypt both PDF and DOCX files with RSA → creates `TEST_MULTIPLE_FILES_RSA_encrypted.cdoc`
- Decrypt multiple files CDOC → creates `decrypted_multiple_files/` directory
- Encrypt both PDF and DOCX files with RSA + ECC recipients → creates `TEST_MULTIPLE_FILES_MULTI_encrypted.cdoc`

## Expected Output

```
=== cdoc1-go Windows Test Application ===
Testing CDOC 1.1 encryption and decryption with test data

✓ All test files verified

============================================================
Test 1: Encrypt PDF with RSA certificate (CDOC 1.1)
============================================================
✓ Loaded RSA certificate: CN=Test User
✓ Added RSA recipient to builder
✓ Added data file: TEST-öäüõÖÄÜÕžšŽŠ-01.pdf (12345 bytes)
✓ CDOC file created: ./TEST_RSA_encrypted.cdoc (67890 bytes)
✓ RSA encryption successful: ./TEST_RSA_encrypted.cdoc

============================================================
Test 2: Decrypt RSA CDOC with PKCS12 keystore
============================================================
✓ Loaded CDOC file: ./TEST_RSA_encrypted.cdoc
✓ Loaded PKCS12 token: ../../testdata/rsa/rsa.p12
✓ Decrypted 1 file(s)
✓ Wrote decrypted file: ./decrypted_rsa/TEST-öäüõÖÄÜÕžšŽŠ-01.pdf (12345 bytes)
✓ RSA decryption successful: ./decrypted_rsa

... (similar output for ECC and multiple recipients tests)

============================================================
=== All tests passed! Library is working correctly on Windows. ===
============================================================
```

## Generated Files

After running the test, you'll have:

- `TEST_RSA_encrypted.cdoc` - CDOC 1.1 file encrypted with RSA certificate (single file)
- `TEST_ECC_encrypted.cdoc` - CDOC 1.1 file encrypted with ECC certificate (single file)
- `TEST_MULTI_encrypted.cdoc` - CDOC 1.1 file encrypted with both RSA and ECC recipients (single file)
- `TEST_MULTIPLE_FILES_RSA_encrypted.cdoc` - CDOC 1.1 file with PDF and DOCX encrypted with RSA certificate
- `TEST_MULTIPLE_FILES_MULTI_encrypted.cdoc` - CDOC 1.1 file with PDF and DOCX encrypted with RSA + ECC recipients
- `decrypted_rsa/` - Directory containing decrypted files from RSA CDOC
- `decrypted_ecc/` - Directory containing decrypted files from ECC CDOC
- `decrypted_multiple_files/` - Directory containing both decrypted PDF and DOCX files

## Test Files Location

The application uses relative paths from the `examples/windows-test/` directory:

- PDF file: `../../testdata/samples/TEST-öäüõÖÄÜÕžšŽŠ-01.pdf`
- DOCX file: `../../testdata/samples/TEST-öäüõÖÄÜÕžšŽŠ-01.docx`
- RSA certificate: `../../testdata/rsa/auth_cert.pem`
- RSA keystore: `../../testdata/rsa/rsa.p12`
- ECC certificate: `../../testdata/ecc/auth_cert.pem`
- ECC keystore: `../../testdata/ecc/ecc.p12`

**PKCS12 Password**: All test keystores use password `"test"` (hardcoded in the application).

## Troubleshooting

- **"cannot find package"**: Make sure you've set up the `replace` directive or workspace correctly
- **"test file not found"**: Verify that test files are in the expected `testdata/` directories
- **"certificate parse error"**: Check that certificate files are valid PEM format
- **"PKCS12 error"**: Verify keystore password is correct (should be "test" for test keystores)
- **"decryption failed"**: Ensure the CDOC file matches the keystore (RSA CDOC needs RSA keystore, etc.)

## Features Demonstrated

- ✅ CDOC 1.1 encryption with RSA certificates
- ✅ CDOC 1.1 encryption with ECC certificates
- ✅ Multiple recipients support (RSA + ECC in same CDOC)
- ✅ Multiple files encryption (PDF + DOCX in same CDOC)
- ✅ Multiple files with multiple recipients
- ✅ PKCS12 keystore decryption
- ✅ File handling with special characters (Estonian characters: öäüõÖÄÜÕžšŽŠ)
- ✅ Complete encryption → decryption workflow for single and multiple files
- ✅ Error handling and verification
