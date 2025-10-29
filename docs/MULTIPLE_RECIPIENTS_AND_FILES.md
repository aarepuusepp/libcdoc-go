# Multiple Recipients and Files Support

## Overview

The CDOC library fully supports **multiple recipients (certificates)** and **multiple files** during encryption. This document explains how to use these features.

## Multiple Recipients (Certificates)

### Supported

✅ **Full support for multiple recipients**

Each recipient certificate gets its own `EncryptedKey` element in the CDOC document. Any recipient with the corresponding private key can decrypt the document.

### Usage Examples

#### Example 1: Multiple Recipients with Builder API

```go
package main

import (
    "bytes"
    "github.com/yourorg/cdoc1-go/cdoc"
    "github.com/yourorg/cdoc1-go/cert"
)

func encryptWithMultipleRecipients() {
    builder := cdoc.NewBuilder()
    builder.Version(cdoc.Version11)
    
    // Add single data file
    builder.WithDataFile("document.pdf", fileReader, fileSize)
    
    // Add multiple recipients
    cert1, _ := cert.ParseCertificate(cert1Reader)
    cert2, _ := cert.ParseCertificate(cert2Reader)
    
    builder.WithRecipientCertificate(cert1)
    builder.WithRecipientCertificate(cert2)
    // ... add more recipients as needed
    
    var output bytes.Buffer
    builder.BuildToWriter(&output)
    
    // Output: CDOC with 2 EncryptedKey elements
    // Both recipients can decrypt independently
}
```

#### Example 2: Using File Paths

```go
builder := cdoc.NewBuilder()
builder.Version(cdoc.Version11)
builder.WithDataFile("data.txt", contentReader, size)

// Add recipients from files
builder.WithRecipientFromPath("recipient1.pem")
builder.WithRecipientFromPath("recipient2.pem")
builder.WithRecipientFromPath("recipient3.pem")

builder.BuildToFile("output.cdoc")
```

### Implementation Details

**How it works:**
1. Each call to `WithRecipientCertificate()` adds a certificate to the recipients slice
2. During encryption, an `EncryptedKey` element is created for each recipient
3. Each `EncryptedKey` contains:
   - Encrypted transport key (specific to that recipient's public key)
   - Recipient certificate
   - Encryption method (RSA or EC based on certificate type)

**Decryption:**
- Only one recipient's private key is needed to decrypt
- The decrypter automatically selects the matching recipient based on the provided certificate/key
- All recipients share the same encrypted content; each has their own key transport

### Test Verification

```go
// TestGeneration_CDOC11_MultipleRecipients verifies:
// - Encryption with 2 recipients succeeds
// - First recipient can decrypt
// - Second recipient can decrypt
// - Both get the same content
```

## Multiple Files

### Supported

✅ **Full support for multiple files (DDOC format)**

When multiple files are encrypted, they are packaged in a **DDOC (Data Document Container)** XML structure.

### Usage Examples

#### Example 1: Multiple Files with Builder API

```go
package main

import (
    "bytes"
    "github.com/yourorg/cdoc1-go/cdoc"
    "os"
)

func encryptMultipleFiles() {
    builder := cdoc.NewBuilder()
    builder.Version(cdoc.Version11)
    
    // Add multiple files
    file1, _ := os.Open("document1.pdf")
    defer file1.Close()
    builder.WithDataFile("document1.pdf", file1, file1Size)
    
    file2, _ := os.Open("document2.pdf")
    defer file2.Close()
    builder.WithDataFile("document2.pdf", file2, file2Size)
    
    // Add recipient
    builder.WithRecipientCertificate(cert)
    
    var output bytes.Buffer
    builder.BuildToWriter(&output)
    
    // Output: CDOC with DDOC MIME type
    // Contains encrypted DDOC XML with both files
}
```

#### Example 2: Using File Paths

```go
builder := cdoc.NewBuilder()
builder.Version(cdoc.Version11)

// Add multiple files from paths
builder.WithDataFileFromPath("file1.txt")
builder.WithDataFileFromPath("file2.txt")
builder.WithDataFileFromPath("file3.txt")

builder.WithRecipientCertificate(cert)
builder.BuildToFile("output.cdoc")
```

#### Example 3: Decrypting Multiple Files

```go
decrypter := cdoc.NewDecrypter()
decrypter.WithCDOC(cdocReader)
decrypter.WithPrivateKey(privateKey)
decrypter.WithCertificate(cert)

// Decrypt - returns all files
decryptedFiles, err := decrypter.Decrypt()
if err != nil {
    log.Fatal(err)
}

// Process all decrypted files
for _, file := range decryptedFiles {
    fmt.Printf("File: %s, Size: %d bytes\n", file.Name, len(file.Content))
    // ... save or process file.Content
}
```

### Implementation Details

**How it works:**
1. When `len(dataFiles) > 1`, the composer creates a DDOC XML structure
2. DDOC XML structure:
   ```xml
   <SignedDoc xmlns="http://www.sk.ee/DigiDoc/v1.3.0#" 
              format="DIGIDOC-XML" version="1.3">
     <DataFile Filename="file1.txt" ...>
       [base64 content]
     </DataFile>
     <DataFile Filename="file2.txt" ...>
       [base64 content]
     </DataFile>
   </SignedDoc>
   ```
3. The entire DDOC XML is encrypted as a single payload
4. MIME type is set to `http://www.sk.ee/DigiDoc/v1.3.0/digidoc.xsd`

**Decryption:**
1. Decrypter checks MIME type
2. If DDOC MIME type, calls `ParseDDOC()` to extract all files
3. Returns array of all `DecryptedFile` objects

### Test Verification

```go
// TestGeneration_CDOC11_RSA_WithDDOC verifies:
// - Encryption of 2 files creates DDOC structure
// - Decryption extracts both files correctly
// - File names and content match original
```

## Combined: Multiple Recipients AND Multiple Files

### Supported

✅ **Full support for both simultaneously**

You can encrypt multiple files for multiple recipients in a single CDOC document.

### Usage Example

```go
builder := cdoc.NewBuilder()
builder.Version(cdoc.Version11)

// Add multiple files
builder.WithDataFileFromPath("contract.pdf")
builder.WithDataFileFromPath("invoice.pdf")
builder.WithDataFileFromPath("attachment.txt")

// Add multiple recipients
builder.WithRecipientCertificate(recipient1Cert)
builder.WithRecipientCertificate(recipient2Cert)
builder.WithRecipientCertificate(recipient3Cert)

builder.BuildToFile("shared.cdoc")

// Result:
// - Single CDOC document
// - Contains 3 files (in DDOC format)
// - Encrypted for 3 recipients
// - Any of the 3 recipients can decrypt and get all 3 files
```

### CDOC Structure

```
EncryptedData
├── EncryptionMethod (AES-256-GCM or AES-128-CBC)
├── KeyInfo
│   ├── EncryptedKey (Recipient 1)
│   ├── EncryptedKey (Recipient 2)
│   └── EncryptedKey (Recipient 3)
└── CipherData
    └── [Encrypted DDOC XML containing all files]
```

## API Reference

### Builder Methods for Recipients

```go
// Add recipient from reader
func (b *Builder) WithRecipient(certReader io.Reader) error

// Add recipient from file path
func (b *Builder) WithRecipientFromPath(filepath string) error

// Add recipient from parsed certificate
func (b *Builder) WithRecipientCertificate(certificate *x509.Certificate) error
```

**Note:** All three methods can be called multiple times to add multiple recipients.

### Builder Methods for Files

```go
// Add file from reader
func (b *Builder) WithDataFile(name string, content io.Reader, size int64) *Builder

// Add file from file path
func (b *Builder) WithDataFileFromPath(filepath string) error
```

**Note:** Both methods can be called multiple times to add multiple files.

## Limitations and Restrictions

### CDOC 1.0
- ✅ Multiple files: Supported (DDOC format)
- ✅ Multiple recipients: Supported (RSA only)
- ❌ EC recipients: Not supported (CDOC 1.0 only supports RSA)

### CDOC 1.1
- ✅ Multiple files: Supported (DDOC format)
- ✅ Multiple recipients: Supported
- ✅ RSA recipients: Supported
- ✅ EC recipients: Supported

## Examples from Tests

### Test: Multiple Recipients

```12:292:cdoc/generation_test.go
// TestGeneration_CDOC11_MultipleRecipients tests generation with multiple recipients
func TestGeneration_CDOC11_MultipleRecipients(t *testing.T) {
	privKey1, cert1 := createTestRSACertWithKey(t)
	privKey2, cert2 := createTestRSACertWithKey(t)

	testContent := "multiple recipients test"
	testFileName := "test.txt"

	// Encrypt with both recipients
	builder := NewBuilder()
	builder.Version(Version11)
	builder.WithDataFile(testFileName, strings.NewReader(testContent), int64(len(testContent)))

	if err := builder.WithRecipientCertificate(cert1); err != nil {
		t.Fatalf("Failed to add first recipient: %v", err)
	}
	if err := builder.WithRecipientCertificate(cert2); err != nil {
		t.Fatalf("Failed to add second recipient: %v", err)
	}

	var encryptedOutput bytes.Buffer
	if err := builder.BuildToWriter(&encryptedOutput); err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// Decrypt with first recipient
	decrypter1 := NewDecrypter()
	decrypter1.WithCDOC(bytes.NewReader(encryptedOutput.Bytes()))
	decrypter1.WithPrivateKey(&key.PrivateKey{Key: privKey1})
	decrypter1.WithCertificate(cert1)

	decryptedFiles1, err := decrypter1.Decrypt()
	if err != nil {
		t.Fatalf("Failed to decrypt with first recipient: %v", err)
	}

	if len(decryptedFiles1) != 1 {
		t.Fatalf("Expected 1 decrypted file, got %d", len(decryptedFiles1))
	}

	if string(decryptedFiles1[0].Content) != testContent {
		t.Error("Decryption with first recipient failed")
	}

	// Decrypt with second recipient
	decrypter2 := NewDecrypter()
	decrypter2.WithCDOC(bytes.NewReader(encryptedOutput.Bytes()))
	decrypter2.WithPrivateKey(&key.PrivateKey{Key: privKey2})
	decrypter2.WithCertificate(cert2)

	decryptedFiles2, err := decrypter2.Decrypt()
	if err != nil {
		t.Fatalf("Failed to decrypt with second recipient: %v", err)
	}

	if string(decryptedFiles2[0].Content) != testContent {
		t.Error("Decryption with second recipient failed")
	}
}
```

### Test: Multiple Files (DDOC)

```195:232:cdoc/generation_test.go
// TestGeneration_CDOC11_RSA_WithDDOC tests CDOC 1.1 generation with multiple files (DDOC pattern)
func TestGeneration_CDOC11_RSA_WithDDOC(t *testing.T) {
	privKey, cert := createTestRSACertWithKey(t)

	dataFiles := []TestDataFile{
		{
			Name:    "test.txt",
			Content: []byte("some test content"),
			Size:    int64(len("some test content")),
		},
		{
			Name:    "test.txt",
			Content: []byte("other test content"),
			Size:    int64(len("other test content")),
		},
	}

	decryptedFiles := buildAndDecryptToMemory(t, Version11, cert, privKey, dataFiles...)

	// With DDOC support, all files should be extracted
	if len(decryptedFiles) != len(dataFiles) {
		t.Fatalf("Expected %d decrypted files, got %d", len(dataFiles), len(decryptedFiles))
	}

	// Verify all files content matches
	for i := range dataFiles {
		if i < len(decryptedFiles) {
			decryptedContent := string(decryptedFiles[i].Content)
			expectedContent := string(dataFiles[i].Content)
			if decryptedContent != expectedContent {
				t.Errorf("File %d content mismatch.\nExpected: %s\nGot: %s", i, expectedContent, decryptedContent)
			}
			if decryptedFiles[i].Name != dataFiles[i].Name {
				t.Errorf("File %d name mismatch. Expected: %s, Got: %s", i, dataFiles[i].Name, decryptedFiles[i].Name)
			}
		}
	}
}
```

## Summary

| Feature | Support | CDOC 1.0 | CDOC 1.1 |
|---------|---------|----------|----------|
| **Multiple Recipients** | ✅ Yes | ✅ RSA only | ✅ RSA + EC |
| **Multiple Files** | ✅ Yes | ✅ DDOC | ✅ DDOC |
| **Both Together** | ✅ Yes | ✅ Yes | ✅ Yes |
| **Recipient Types** | - | RSA only | RSA, EC |

**Key Points:**
- ✅ Call `WithRecipientCertificate()` multiple times for multiple recipients
- ✅ Call `WithDataFile()` multiple times for multiple files
- ✅ Multiple recipients each get their own `EncryptedKey` element
- ✅ Multiple files are packaged in a DDOC XML structure
- ✅ Any recipient can decrypt and get all files
- ✅ All functionality is tested and verified

