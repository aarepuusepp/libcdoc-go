# FlatBuffers Schema Files

This directory contains the FlatBuffers schema definitions for CDOC2 format.

## Files

- `recipients.fbs` - Defines recipient capsule types (RSA, ECC, KeyServer, Symmetric, PBKDF2, KeyShares)
- `header.fbs` - Defines the main header structure for CDOC2 files

## Generating Go Code

To generate Go code from these schema files, use the FlatBuffers compiler (`flatc`):

**Windows:**
```batch
cd cdoc\cdoc2\schema
flatc --go recipients.fbs header.fbs
```

**Linux/macOS:**
```bash
cd cdoc/cdoc2/schema
flatc --go recipients.fbs header.fbs
```

Or use the scripts in the `scripts/` directory:
- `scripts/generate-fbs.bat` (Windows)
- `scripts/generate-fbs.sh` (Linux/macOS)

The generated Go files will be created in this directory. They should be committed to version control.

## Installing flatc

**Windows:**
- Download from: https://github.com/google/flatbuffers/releases
- Or install via Chocolatey: `choco install flatbuffers`

**macOS:**
- `brew install flatbuffers`

**Linux:**
- Download from: https://github.com/google/flatbuffers/releases
- Or build from source: https://google.github.io/flatbuffers/flatbuffers_guide_building.html

