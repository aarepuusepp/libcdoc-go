@echo off
REM Generate Go code from FlatBuffers schema files
REM Requires flatc compiler to be installed and in PATH

cd /d %~dp0..

cd cdoc\cdoc2\schema
flatc --go recipients.fbs header.fbs

if errorlevel 1 (
    echo ERROR: Failed to generate FlatBuffers code. Make sure flatc is installed.
    echo Download from: https://github.com/google/flatbuffers/releases
    echo Or install via: choco install flatbuffers (on Windows)
    exit /b 1
)

echo Successfully generated FlatBuffers Go code

