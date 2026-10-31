> Historical implementation proposal. Its CDOC1/multi-file limitations are superseded by [current implementation status](IMPLEMENTATION_STATUS.md). Do not apply this proposal as a current patch.

# Removing CDOC Library Limitations

This document explains how to remove the two known limitations in the CDOC library:
1. **DDOC multi-file decryption**
2. **CDOC 1.0 generation**

## Limitation 1: DDOC Multi-File Decryption

### Current Behavior

Currently, when a CDOC contains multiple files (DDOC format), the decryption only extracts the first file. The encrypted content actually contains a DDOC XML structure with multiple `<DataFile>` elements, but the current implementation doesn't parse this structure.

### How It Works

When multiple files are encrypted:

1. **Encryption**: The files are embedded in a DDOC XML structure (not a ZIP file)
2. **MIME Type**: Set to `http://www.sk.ee/DigiDoc/v1.3.0/digidoc.xsd` (DDOCMimeType)
3. **DDOC Structure**: Contains a `<SignedDoc>` root with multiple `<DataFile>` elements:

```xml
<SignedDoc xmlns="http://www.sk.ee/DigiDoc/v1.3.0#" format="DIGIDOC-XML" version="1.3">
  <DataFile Filename="file1.txt" ContentType="application/octet-stream">
    <Base64Value>...</Base64Value>
  </DataFile>
  <DataFile Filename="file2.txt" ContentType="application/octet-stream">
    <Base64Value>...</Base64Value>
  </DataFile>
</SignedDoc>
```

### Implementation Steps

#### Step 1: Create DDOC Parser (`cdoc/ddoc_parser.go`)

```go
package cdoc

import (
    "encoding/base64"
    "encoding/xml"
    "io"
)

// DDOCSignedDoc represents the root element of a DDOC structure
type DDOCSignedDoc struct {
    XMLName  xml.Name   `xml:"SignedDoc"`
    Format   string     `xml:"format,attr"`
    Version  string     `xml:"version,attr"`
    DataFiles []DDOCDataFile `xml:"DataFile"`
}

// DDOCDataFile represents a file in DDOC structure
type DDOCDataFile struct {
    Filename    string `xml:"Filename,attr"`
    ContentType string `xml:"ContentType,attr"`
    Base64Value string `xml:"Base64Value"`
}

// ParseDDOC parses a DDOC XML structure and extracts all files
func ParseDDOC(data []byte) ([]DecryptedFile, error) {
    var signedDoc DDOCSignedDoc
    if err := xml.Unmarshal(data, &signedDoc); err != nil {
        return nil, internal.NewDecryptionError("failed to parse DDOC XML", err)
    }

    var files []DecryptedFile
    for _, df := range signedDoc.DataFiles {
        content, err := base64.StdEncoding.DecodeString(df.Base64Value)
        if err != nil {
            return nil, internal.NewDecryptionError("failed to decode base64 content", err)
        }

        files = append(files, DecryptedFile{
            Name:    df.Filename,
            Content: content,
        })
    }

    return files, nil
}
```

#### Step 2: Update `Decrypt` Method (`cdoc/decrypter.go`)

Modify the `Decrypt` method to check MIME type and parse DDOC when needed:

```go
func (d *Decrypter) Decrypt() ([]DecryptedFile, error) {
    // ... existing code to get encryptedContent and dataKey ...

    // Decrypt content
    var plaintext []byte
    var err error
    if version == Version11 {
        plaintext, err = d.decryptContent11(encryptedContent, dataKey)
    } else {
        plaintext, err = d.decryptContent10(encryptedContent, dataKey)
    }
    if err != nil {
        return nil, err
    }

    // Check if this is DDOC (multiple files)
    mimeType := parser.GetMimeType()
    if mimeType == DDOCMimeType {
        // Parse DDOC XML structure
        return ParseDDOC(plaintext)
    }

    // Single file - extract from EncryptionProperties
    filename := parser.GetFilename()
    if filename == "" {
        filename = "decrypted_file"
    }

    return []DecryptedFile{
        {
            Name:    filename,
            Content: plaintext,
        },
    }, nil
}
```

#### Step 3: Update Encryption for Multiple Files (`cdoc/composer.go`)

When encrypting multiple files, create DDOC XML structure:

```go
func (c *Composer) createDDOCXML() ([]byte, error) {
    var buf bytes.Buffer
    encoder := xml.NewEncoder(&buf)
    
    // Write XML declaration
    buf.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
    
    // Start SignedDoc element
    if err := encoder.EncodeToken(xml.StartElement{
        Name: xml.Name{Local: "SignedDoc"},
        Attr: []xml.Attr{
            {Name: xml.Name{Local: "xmlns"}, Value: "http://www.sk.ee/DigiDoc/v1.3.0#"},
            {Name: xml.Name{Local: "format"}, Value: "DIGIDOC-XML"},
            {Name: xml.Name{Local: "version"}, Value: "1.3"},
        },
    }); err != nil {
        return nil, err
    }

    // Add each data file
    for _, dataFile := range c.dataFiles {
        content, err := io.ReadAll(dataFile.Content)
        if err != nil {
            return nil, err
        }
        
        base64Content := base64.StdEncoding.EncodeToString(content)
        
        if err := encoder.EncodeToken(xml.StartElement{
            Name: xml.Name{Local: "DataFile"},
            Attr: []xml.Attr{
                {Name: xml.Name{Local: "Filename"}, Value: dataFile.Name},
                {Name: xml.Name{Local: "ContentType"}, Value: "application/octet-stream"},
            },
        }); err != nil {
            return nil, err
        }
        
        if err := encoder.EncodeToken(xml.CharData(base64Content)); err != nil {
            return nil, err
        }
        
        if err := encoder.EncodeToken(xml.EndElement{Name: xml.Name{Local: "DataFile"}}); err != nil {
            return nil, err
        }
    }

    // Close SignedDoc
    if err := encoder.EncodeToken(xml.EndElement{Name: xml.Name{Local: "SignedDoc"}}); err != nil {
        return nil, err
    }
    
    if err := encoder.Flush(); err != nil {
        return nil, err
    }

    return buf.Bytes(), nil
}

func (c *Composer) compose11(w io.Writer) error {
    mimeType := "application/octet-stream"
    var contentToEncrypt []byte
    var err error

    if len(c.dataFiles) > 1 {
        mimeType = DDOCMimeType
        // Create DDOC XML structure
        contentToEncrypt, err = c.createDDOCXML()
        if err != nil {
            return internal.NewEncryptionError("failed to create DDOC XML", err)
        }
    } else if len(c.dataFiles) == 1 {
        // Single file - read directly
        contentToEncrypt, err = io.ReadAll(c.dataFiles[0].Content)
        if err != nil {
            return internal.NewEncryptionError("failed to read data file", err)
        }
    }

    // ... rest of encryption logic ...
}
```

### Testing

Update `TestGeneration_CDOC11_RSA_WithDDOC` to verify all files are extracted:

```go
func TestGeneration_CDOC11_RSA_WithDDOC(t *testing.T) {
    // ... setup ...
    
    decryptedFiles := buildAndDecryptToMemory(t, Version11, cert, privKey, dataFiles...)

    if len(decryptedFiles) != len(dataFiles) {
        t.Fatalf("Expected %d decrypted files, got %d", len(dataFiles), len(decryptedFiles))
    }

    // Verify each file
    for i, df := range dataFiles {
        if decryptedFiles[i].Name != df.Name {
            t.Errorf("File %d: Expected name %s, got %s", i, df.Name, decryptedFiles[i].Name)
        }
        if string(decryptedFiles[i].Content) != string(df.Content) {
            t.Errorf("File %d: Content mismatch", i)
        }
    }
}
```

---

## Limitation 2: CDOC 1.0 Generation

### Current Behavior

CDOC 1.0 generation is not implemented. The `compose10` method returns an error.

### Differences from CDOC 1.1

| Feature | CDOC 1.0 | CDOC 1.1 |
|---------|----------|----------|
| Content Encryption | AES-128-CBC | AES-256-GCM |
| Key Size | 128 bits (16 bytes) | 256 bits (32 bytes) |
| IV Size | 16 bytes | 12 bytes |
| Padding | X.923 | None (GCM is authenticated) |
| Algorithm URI | `http://www.w3.org/2001/04/xmlenc#aes128-cbc` | `http://www.w3.org/2009/xmlenc11#aes256-gcm` |
| Transport Key | RSA PKCS#1 v1.5 only | RSA or EC |

### Implementation Steps

#### Step 1: Update Key Generation (`cdoc/composer.go`)

```go
func (c *Composer) generateDataKey() error {
    var keySize int
    if c.version == Version10 {
        keySize = 16 // AES-128
    } else {
        keySize = 32 // AES-256
    }

    key, err := crypto.GenerateAESKey(keySize)
    if err != nil {
        return internal.NewEncryptionError("failed to generate data key", err)
    }
    c.dataKey = key
    return nil
}
```

#### Step 2: Implement `compose10` Method (`cdoc/composer.go`)

```go
func (c *Composer) compose10(w io.Writer) error {
    // Generate AES-128 key
    if err := c.generateDataKey(); err != nil {
        return err
    }

    // Determine MIME type
    mimeType := "application/octet-stream"
    var contentToEncrypt []byte
    var err error

    if len(c.dataFiles) > 1 {
        mimeType = DDOCMimeType
        contentToEncrypt, err = c.createDDOCXML()
        if err != nil {
            return internal.NewEncryptionError("failed to create DDOC XML", err)
        }
    } else if len(c.dataFiles) == 1 {
        contentToEncrypt, err = io.ReadAll(c.dataFiles[0].Content)
        if err != nil {
            return internal.NewEncryptionError("failed to read data file", err)
        }
    }

    // Generate IV (16 bytes for CBC)
    iv, err := crypto.GenerateIV(16)
    if err != nil {
        return internal.NewEncryptionError("failed to generate IV", err)
    }

    // Apply X.923 padding
    paddedContent, err := crypto.AddX923Padding(bytes.NewReader(contentToEncrypt), int64(len(contentToEncrypt)))
    if err != nil {
        return internal.NewEncryptionError("failed to add padding", err)
    }

    // Encrypt with AES-128-CBC
    ciphertext, err := crypto.EncryptAESCBC(paddedContent, c.dataKey, iv)
    if err != nil {
        return internal.NewEncryptionError("failed to encrypt content", err)
    }

    // Prepend IV (IV || ciphertext)
    encryptedContent := append(iv, ciphertext...)

    // Build EncryptedData structure
    encryptedData := &xmlenc.EncryptedData{
        MimeType: mimeType,
        EncryptionMethod: xmlenc.EncryptionMethod{
            Algorithm: string(URI_AES128CBC), // CDOC 1.0 uses AES-128-CBC
        },
        KeyInfo: xmlenc.KeyInfo{},
        CipherData: xmlenc.CipherData{
            CipherValue: internal.EncodeBase64(encryptedContent),
        },
    }

    // Build recipients (only RSA for CDOC 1.0)
    var encryptedKeys []xmlenc.EncryptedKey
    for _, recipientCert := range c.recipients {
        if !cert.IsRSACertificate(recipientCert) {
            return internal.NewEncryptionError(
                "CDOC 1.0 only supports RSA recipients",
                nil,
            )
        }

        encryptedKey, err := c.createRecipientEncryptedKey10(recipientCert)
        if err != nil {
            return err
        }
        encryptedKeys = append(encryptedKeys, *encryptedKey)
    }
    encryptedData.KeyInfo.EncryptedKeys = encryptedKeys

    // Add metadata
    props := c.buildEncryptionProperties()
    encryptedData.EncryptionProperties = props

    // Write XML
    encoder := xml.NewEncoder(w)
    encoder.Indent("", "  ")
    if err := encoder.Encode(encryptedData); err != nil {
        return internal.NewEncryptionError("failed to encode XML", err)
    }

    return nil
}

// createRecipientEncryptedKey10 creates an EncryptedKey for CDOC 1.0 (RSA only)
func (c *Composer) createRecipientEncryptedKey10(recipientCert *x509.Certificate) (*xmlenc.EncryptedKey, error) {
    cn := cert.ExtractCN(recipientCert)

    // CDOC 1.0 only supports RSA
    publicKey, ok := recipientCert.PublicKey.(*rsa.PublicKey)
    if !ok {
        return nil, internal.NewEncryptionError("certificate must be RSA for CDOC 1.0", nil)
    }

    // Encrypt transport key with RSA PKCS#1 v1.5
    encryptedKeyBytes, err := crypto.EncryptRSA(c.dataKey, publicKey)
    if err != nil {
        return nil, internal.NewEncryptionError("failed to encrypt transport key", err)
    }

    // Encode certificate
    certBytes := recipientCert.Raw
    certBase64 := internal.EncodeBase64(certBytes)

    encryptedKey := &xmlenc.EncryptedKey{
        EncryptionMethod: xmlenc.EncryptionMethod{
            Algorithm: string(URI_RSA_1_5),
        },
        KeyInfo: xmlenc.KeyInfo{
            X509Data: xmlenc.X509Data{
                X509Certificate: certBase64,
            },
        },
        CarriedKeyName: cn,
        CipherData: xmlenc.CipherData{
            CipherValue: internal.EncodeBase64(encryptedKeyBytes),
        },
    }

    return encryptedKey, nil
}
```

#### Step 3: Update Algorithm URI Constants (`cdoc/version.go`)

Ensure URI_AES128CBC is defined:

```go
const (
    // ... existing constants ...
    URI_AES128CBC AlgorithmURI = "http://www.w3.org/2001/04/xmlenc#aes128-cbc"
)
```

#### Step 4: Update Builder to Support CDOC 1.0

Ensure the builder can set version to 1.0:

```go
func (b *Builder) Version(version Version) *Builder {
    b.version = version
    return b
}
```

### Testing

Add test for CDOC 1.0 generation:

```go
func TestGeneration_CDOC10_RSA_SingleFile(t *testing.T) {
    privKey, cert := createTestRSACertWithKey(t)

    testContent := "test data content"
    testFileName := "test.txt"

    dataFile := TestDataFile{
        Name:    testFileName,
        Content: []byte(testContent),
        Size:    int64(len(testContent)),
    }

    decryptedFiles := buildAndDecryptToMemory(t, Version10, cert, privKey, dataFile)

    if len(decryptedFiles) != 1 {
        t.Fatalf("Expected 1 decrypted file, got %d", len(decryptedFiles))
    }

    decryptedContent := string(decryptedFiles[0].Content)
    if decryptedContent != testContent {
        t.Errorf("Content mismatch.\nExpected: %s\nGot: %s", testContent, decryptedContent)
    }
}
```

---

## Implementation Priority

### Phase 1: DDOC Multi-File Decryption (Higher Priority)
1. Create `ddoc_parser.go` with `ParseDDOC` function
2. Update `Decrypt` method to check MIME type and parse DDOC
3. Update `compose11` to create DDOC XML when multiple files
4. Update tests to verify multiple file extraction

### Phase 2: CDOC 1.0 Generation
1. Implement `compose10` method with AES-128-CBC
2. Implement `createRecipientEncryptedKey10` (RSA only)
3. Add X.923 padding support
4. Update key generation for 128-bit keys
5. Add tests for CDOC 1.0 round-trip

---

## Summary

**DDOC Multi-File Decryption:**
- Parse DDOC XML structure from decrypted content
- Extract all `<DataFile>` elements
- Return all files in `DecryptedFile` array

**CDOC 1.0 Generation:**
- Use AES-128-CBC instead of AES-256-GCM
- Generate 128-bit keys
- Apply X.923 padding before encryption
- Support RSA recipients only
- Use appropriate algorithm URIs

Both features are straightforward to implement following the patterns established in CDOC 1.1 and the reference implementations in cdoc4j.

