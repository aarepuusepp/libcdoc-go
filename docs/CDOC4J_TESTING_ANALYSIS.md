> Historical investigation/development record. Commands, versions and completion claims describe that record, not the current release. Use [current README](../README.md) for supported setup and API boundaries.

# CDOC4J Testing Analysis

## Overview

This document analyzes how `cdoc4j` tests CDOC container generation and how we can apply similar patterns in our Go library.

## CDOC4J Test Structure

### 1. Test Resources Location

**CDOC Test Files:**
- Location: `src/test/resources/cdoc/`
- Files include:
  - `valid_cdoc10.cdoc` - CDOC 1.0 with RSA single file
  - `valid_cdoc10_withDDOC.cdoc` - CDOC 1.0 with multiple files
  - `valid_cdoc10_withMultipleRecipients.cdoc` - CDOC 1.0 with multiple recipients
  - `valid_cdoc11_RSA.cdoc` - CDOC 1.1 with RSA recipient
  - `valid_cdoc11_ECC.cdoc` - CDOC 1.1 with EC recipient
  - `valid_cdoc11_RSA_withDDOC.cdoc` - CDOC 1.1 RSA with multiple files
  - `valid_cdoc11_ECC_withDDOC.cdoc` - CDOC 1.1 EC with multiple files
  - `valid_cdoc11_withMultipleRecipients.cdoc` - CDOC 1.1 with multiple recipients
  - Invalid variants for error testing

**Certificates (embedded in JAR or test resources):**
- `/rsa/auth_cert.pem` - RSA authentication certificate (with keyEncipherment key usage)
- `/rsa/sign_cert.pem` - RSA signing certificate (without keyEncipherment)
- `/ecc/auth_cert.pem` - EC authentication certificate (with keyAgreement key usage)
- `/ecc/sign_cert.pem` - EC signing certificate (without keyAgreement)
- `/rsa/rsa.p12` - PKCS#12 file containing RSA private key for decryption testing

### 2. Builder Testing Pattern (CDOC11BuilderTest)

**Common Test Pattern:**
```java
@Test
void buildCDOC11_withRSACertificate_toByteArray_withSingleFile_shouldSucceed() {
    DataFile dataFile = new DataFile(testFileName, "test data content".getBytes());
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    CDOCBuilder.version(version)
            .withDataFile(dataFile)
            .withRecipient(rsaAuthCertificate)
            .buildToOutputStream(baos);
    
    assertEquals(3658, baos.size());  // Exact size assertion
    assertStreamClosed(dataFile.getContent());
    assertStreamClosed(rsaAuthCertificate);
}
```

**Key Observations:**
1. **Size Assertions**: Tests assert exact output size (e.g., 3658 bytes for RSA, 7998 for EC)
2. **Stream Management**: Verifies that input streams are closed after use
3. **Multiple Output Targets**: Tests `buildToFile`, `buildToOutputStream`, `buildToByteArray`
4. **Validation Tests**: Tests missing recipients, missing data files, invalid certificates
5. **Multiple Recipients**: Tests with multiple recipients in single CDOC
6. **DDOC Pattern**: Tests with multiple files (DDOC = Data Document Container)

**Test Categories:**
- ✅ Validation (missing recipient, missing data file, invalid certificate)
- ✅ Single file encryption (RSA, EC)
- ✅ Multiple files (DDOC pattern)
- ✅ Multiple recipients
- ✅ Output to file, byte array, output stream
- ✅ Empty file handling
- ✅ Large file handling (95MB)

### 3. Decrypter Testing Pattern (CDOC11DecrypterTest)

**Common Test Pattern:**
```java
@Test
void decryptValidCDOC11_RSA_withSingleFile_shouldSucceed() {
    PKCS12Token token = new PKCS12Token(
        Files.newInputStream(Paths.get("src/test/resources/rsa/rsa.p12")), 
        "test"
    );
    
    List<File> dataFiles = new CDOCDecrypter()
            .withToken(token)
            .withCDOC(Files.newInputStream(Paths.get("src/test/resources/cdoc/valid_cdoc11_RSA.cdoc")))
            .decrypt(new File("target/testdata"));
    
    assertSame(1, dataFiles.size());
    assertFileDataFileContent(dataFiles.get(0), "lorem2.txt", expectedContent);
}
```

**Key Observations:**
1. **PKCS#12 Tokens**: Uses PKCS#12 files for private keys in tests
2. **Content Assertion**: Verifies exact content matches expected content
3. **File Name Assertion**: Verifies decrypted file names match expected names
4. **DDOC Support**: Tests decryption of multiple files
5. **Multiple Recipients**: Tests recipient selection

### 4. Round-Trip Testing Pattern

**buildAndDecryptToMemory Helper:**
```java
private List<DataFile> buildAndDecryptToMemory(DataFile... dataFiles) {
    InputStream cert = getClass().getResourceAsStream("/rsa/auth_cert.pem");
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    
    // Encrypt
    CDOCBuilder.version(version)
            .withDataFiles(Arrays.asList(dataFiles))
            .withRecipient(cert)
            .buildToOutputStream(baos);
    
    // Decrypt
    PKCS12Token token = new PKCS12Token(
        Files.newInputStream(Paths.get("src/test/resources/rsa/rsa.p12")), 
        "test"
    );
    ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
    List<DataFile> decryptedFiles = new CDOCDecrypter()
            .withToken(token)
            .withCDOC(bais)
            .decrypt();
    
    return decryptedFiles;
}
```

**Key Pattern:**
1. **Helper Method**: Reusable method that encrypts and decrypts in one go
2. **Memory-Based**: Uses in-memory streams (ByteArrayOutputStream/InputStream)
3. **Content Verification**: Compares input and output content
4. **Stream Cleanup**: Ensures streams are properly closed

### 5. Parser Testing Pattern (CDOCParserTest)

**Test Pattern:**
```java
@Test
void getDataFileNamesSuccessful_cdoc11_withOneDataFile() {
    FileInputStream cdocStream = new FileInputStream("src/test/resources/cdoc/valid_cdoc11_ECC.cdoc");
    List<String> dataFileNames = CDOCParser.getDataFileNames(cdocStream);
    assertEquals(1, dataFileNames.size());
    assertEquals("lorem1.txt", dataFileNames.get(0));
}
```

**Key Observations:**
1. **File-Based**: Tests use actual CDOC files from resources
2. **Metadata Extraction**: Tests extraction of file names, recipients, version
3. **Invalid Structure**: Tests handling of invalid CDOC structures
4. **XXE Protection**: Tests protection against XML Entity Expansion attacks

## Applying to Go Library

### 1. Test Resources

**Structure:**
```
testdata/
  ├── cdoc/
  │   ├── valid_cdoc10.cdoc
  │   ├── valid_cdoc11_RSA.cdoc
  │   ├── valid_cdoc11_ECC.cdoc
  │   └── ... (copied from cdoc4j)
  ├── rsa/
  │   └── (certificates and keys if needed)
  └── ecc/
      └── (certificates and keys if needed)
```

### 2. Testing Patterns

**A. Parser Tests (Using Real CDOC Files)**
- ✅ Parse actual CDOC files created by cdoc4j
- ✅ Verify version detection
- ✅ Verify recipient extraction
- ✅ Verify metadata extraction (filenames, mime types)
- ✅ Test invalid structures

**B. Generation Tests (Round-Trip)**
- ✅ Encrypt with our builder, decrypt immediately
- ✅ Verify content matches
- ✅ Test multiple recipients
- ✅ Test multiple files (DDOC)
- ✅ Test empty files
- ✅ Verify output size is reasonable

**C. Interoperability Tests**
- ✅ Decrypt CDOCs created by cdoc4j
- ✅ Encrypt CDOCs decryptable by cdoc4j (when cdoc4j is available)
- ✅ Compare output structures

### 3. Key Differences from cdoc4j

**Private Key Handling:**
- cdoc4j: Uses PKCS#12 tokens for decryption tests
- Go Library: Uses PEM/PKCS#8 private key files
- **Solution**: Generate test certificates and keys programmatically

**Certificate Resources:**
- cdoc4j: Certificates embedded in JAR or test resources
- Go Library: Generate certificates on-the-fly or use embedded PEM
- **Solution**: Generate certificates in tests (already implemented)

**Stream Management:**
- cdoc4j: Java streams need explicit closing verification
- Go Library: Go's `io` package handles streams differently
- **Solution**: Less critical, but still good practice to verify

### 4. Implementation Status

**✅ Completed:**
- Parser tests using real CDOC files (`parser_testdata_test.go`)
- Generation tests with round-trip encryption/decryption (`generation_test.go`)
- Test certificate and key generation
- Multiple recipients testing
- Validation testing (missing parameters)

**🔲 To Do:**
- Extract private keys from CDOC test files for full decryption testing
- Interoperability tests with cdoc4j CLI (if available)
- Exact size matching (though sizes may vary due to XML formatting)
- Large file testing (95MB+)

### 5. Test Coverage Goals

**Parser Tests:**
- ✅ All CDOC versions (1.0, 1.1)
- ✅ All recipient types (RSA, EC)
- ✅ Single and multiple files
- ✅ Single and multiple recipients
- ✅ Invalid structures (should fail gracefully)

**Generator Tests:**
- ✅ Round-trip encryption/decryption
- ✅ All recipient types (RSA, EC)
- ✅ Multiple recipients
- ✅ Empty files
- ✅ Validation errors
- ✅ Output size verification

## Summary

The cdoc4j testing approach emphasizes:
1. **Real CDOC Files**: Using actual CDOC containers created by cdoc4j
2. **Round-Trip Testing**: Encrypt → Decrypt → Verify
3. **Exact Assertions**: File sizes, content, metadata
4. **Comprehensive Coverage**: All versions, recipient types, edge cases

Our Go library implements similar patterns:
- ✅ Parser tests with real CDOC files
- ✅ Round-trip generation tests
- ✅ Comprehensive validation
- ✅ Multiple scenarios covered

The main difference is that we generate certificates/keys programmatically rather than using pre-generated test resources, which is actually more flexible and doesn't require external files.

