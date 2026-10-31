# CDOC Test Application

Comprehensive test application that demonstrates encryption and decryption using the `libcdoc-go` library with CDOC 1.1 and 2.0 formats.

## What It Tests

This example performs 16 complete test scenarios:

### CDOC 1.1 Tests:
1. **RSA Encryption**: Encrypts the test PDF file using RSA certificate
2. **RSA Decryption**: Decrypts the RSA-encrypted CDOC using PKCS12 keystore
3. **ECC Encryption**: Encrypts the test PDF file using ECC (Elliptic Curve) certificate
4. **ECC Decryption**: Decrypts the ECC-encrypted CDOC using PKCS12 keystore
5. **Multiple Recipients**: Encrypts with both RSA and ECC recipients in one CDOC file (single file)
6. **Multiple Files**: Encrypts both PDF and DOCX files with RSA certificate
7. **Multiple Files Decryption**: Decrypts a CDOC containing multiple files
8. **Multiple Files + Multiple Recipients**: Encrypts both PDF and DOCX files with both RSA and ECC recipients

### CDOC 2.0 Tests:
9. **RSA Encryption**: Encrypts the test PDF file using RSA certificate (CDOC 2.0)
10. **RSA Decryption**: Decrypts the RSA-encrypted CDOC 2.0 using PKCS12 keystore
11. **ECC Encryption**: Encrypts the test PDF file using ECC certificate (CDOC 2.0)
12. **ECC Decryption**: Decrypts the ECC-encrypted CDOC 2.0 using PKCS12 keystore
13. **Password Encryption**: Encrypts the test PDF file using password (CDOC 2.0)
14. **Password Decryption**: Decrypts the password-encrypted CDOC 2.0
15. **Multiple Files RSA**: Encrypts both PDF and DOCX files with RSA certificate (CDOC 2.0)
16. **Multiple Files RSA Decryption**: Decrypts multiple files RSA CDOC 2.0

## Prerequisites

1. Go 1.27.3 or later installed (root module requirement)
2. The library set up using one of the methods from `docs/WINDOWS_TESTING_GUIDE.md`
3. Test files in place:
   - `testdata/samples/TEST-öäüõÖÄÜÕžšŽŠ-01.pdf` (test PDF with Estonian characters)
   - `testdata/samples/TEST-öäüõÖÄÜÕžšŽŠ-01.docx` (test DOCX with Estonian characters)
   - `testdata/rsa/auth_cert.pem` and `testdata/rsa/rsa.p12` (RSA test certificate and keystore)
   - `testdata/ecc/auth_cert.pem` and `testdata/ecc/ecc.p12` (ECC test certificate and keystore)

## Setup

Use Go 1.27.3+. This nested module requires published libcdoc-go/v2 v2.0.8;
no local replace/workspace is needed. From cli-tools/cdoc-test run:

```sh
go mod verify
go test -mod=readonly ./...
go vet -mod=readonly ./...
go build -mod=readonly .
```

The example application's synthetic fixture paths are relative to this directory.
It writes example output here; use a disposable checkout for running the full demo.
For automated isolated checks use `pwsh -File cli-tools/Test-Modules.ps1` from
the repository root. That gate tests/builds all three modules, checks CLI version,
compares a multi-file/unicode CDOC2 roundtrip and requires wrong-key rejection.

## Running the Test

```bash
cd cli-tools/cdoc-test
go run main.go
```

The application will automatically:
- Verify all test files exist
- Run all 16 test scenarios (CDOC 1.1 and 2.0)
- Create encrypted CDOC files (.cdoc for 1.1, .cdoc2 for 2.0)
- Decrypt the files and verify they work correctly

## Expected Output

```
=== libcdoc-go Test Application ===
Testing CDOC 1.1 and 2.0 encryption and decryption with test data

✓ All test files verified

============================================================
Test 1: Encrypt PDF with RSA certificate (CDOC 1.1)
============================================================
...
============================================================
Test 9: Encrypt PDF with RSA certificate (CDOC 2.0)
============================================================
...
============================================================
=== All tests passed! Library is working correctly on Windows. ===
============================================================
```

## Generated Files

After running the test, you'll have:

### CDOC 1.1 Files:
- `TEST_RSA_encrypted.cdoc` - CDOC 1.1 file encrypted with RSA certificate
- `TEST_ECC_encrypted.cdoc` - CDOC 1.1 file encrypted with ECC certificate
- `TEST_MULTI_encrypted.cdoc` - CDOC 1.1 file encrypted with both RSA and ECC recipients
- `TEST_MULTIPLE_FILES_RSA_encrypted.cdoc` - CDOC 1.1 file with PDF and DOCX encrypted with RSA certificate
- `TEST_MULTIPLE_FILES_MULTI_encrypted.cdoc` - CDOC 1.1 file with PDF and DOCX encrypted with RSA + ECC recipients

### CDOC 2.0 Files:
- `TEST_RSA_encrypted.cdoc2` - CDOC 2.0 file encrypted with RSA certificate
- `TEST_ECC_encrypted.cdoc2` - CDOC 2.0 file encrypted with ECC certificate
- `TEST_PASSWORD_encrypted.cdoc2` - CDOC 2.0 file encrypted with password
- `TEST_MULTIPLE_FILES_RSA_encrypted.cdoc2` - CDOC 2.0 file with PDF and DOCX encrypted with RSA certificate

### Decrypted Directories:
- `decrypted_*` directories containing decrypted files from various CDOC files

## Test Files Location

The application uses relative paths from the `cli-tools/cdoc-test/` directory:

- PDF file: `../../testdata/samples/TEST-öäüõÖÄÜÕžšŽŠ-01.pdf`
- DOCX file: `../../testdata/samples/TEST-öäüõÖÄÜÕžšŽŠ-01.docx`
- RSA certificate: `../../testdata/rsa/auth_cert.pem`
- RSA keystore: `../../testdata/rsa/rsa.p12`
- ECC certificate: `../../testdata/ecc/auth_cert.pem`
- ECC keystore: `../../testdata/ecc/ecc.p12`

**PKCS12 Password**: All test keystores use password `"test"` (hardcoded in the application).

**CDOC 2.0 Password**: Password-based encryption uses password `"test-password-123"`.

## Troubleshooting

- **"cannot find package"**: Make sure you've set up the `replace` directive correctly
- **"test file not found"**: Verify that test files are in the expected `testdata/` directories
- **"certificate parse error"**: Check that certificate files are valid PEM format
- **"PKCS12 error"**: Verify keystore password is correct (should be "test" for test keystores)
- **"decryption failed"**: Ensure the CDOC file matches the keystore (RSA CDOC needs RSA keystore, etc.)

## Features Demonstrated

### CDOC 1.1:
- ✅ CDOC 1.1 encryption with RSA certificates
- ✅ CDOC 1.1 encryption with ECC certificates
- ✅ Multiple recipients support (RSA + ECC in same CDOC)
- ✅ Multiple files encryption (PDF + DOCX in same CDOC)
- ✅ Multiple files with multiple recipients
- ✅ PKCS12 keystore decryption

### CDOC 2.0:
- ✅ CDOC 2.0 encryption with RSA certificates
- ✅ CDOC 2.0 encryption with ECC certificates
- ✅ CDOC 2.0 password-based encryption
- ✅ CDOC 2.0 password-based decryption
- ✅ Multiple files encryption (CDOC 2.0)
- ✅ PKCS12 keystore decryption (CDOC 2.0)

### General:
- ✅ File handling with special characters (Estonian characters: öäüõÖÄÜÕžšŽŠ)
- ✅ Complete encryption → decryption workflow for single and multiple files
- ✅ Error handling and verification
