#!/bin/bash
# Generate Go code from FlatBuffers schema files
# Requires flatc compiler to be installed and in PATH

cd "$(dirname "$0")/.."

cd cdoc/cdoc2/schema
flatc --go recipients.fbs header.fbs

if [ $? -ne 0 ]; then
    echo "ERROR: Failed to generate FlatBuffers code. Make sure flatc is installed."
    echo "Download from: https://github.com/google/flatbuffers/releases"
    echo "Or install via: brew install flatbuffers (on macOS)"
    exit 1
fi

echo "Successfully generated FlatBuffers Go code in cdoc/cdoc2/schema/"

