# Windows Testing Guide - Using cdoc1-go Locally

## Windows Compatibility

**Yes, this library works perfectly on Windows!** The library is written in pure Go and uses only cross-platform standard library and third-party packages. There are no platform-specific dependencies that would prevent it from running on Windows.

### Platform Requirements
- **Operating System**: Windows 10/11 (or any Windows version that supports Go)
- **Go Version**: Go ≥ 1.22 (as specified in `go.mod`)
- **No special dependencies**: All dependencies are pure Go and work on Windows

## Using the Library Locally (Without Publishing to Public Repo)

There are several ways to use this library in your Go application without publishing it to a public repository. Choose the method that best fits your workflow.

### Method 1: Local Path Replacement (Recommended for Quick Testing)

This is the easiest method when testing locally.

#### Step 1: Create Your Test Application

Create a new directory for your test application outside the library directory:

```bash
# Create your test application directory
mkdir C:\Projects\my-cdoc-test
cd C:\Projects\my-cdoc-test
```

#### Step 2: Initialize Go Module in Test App

```bash
go mod init my-cdoc-test
```

#### Step 3: Create go.mod with replace Directive

Edit the `go.mod` file in your test application and add a `replace` directive pointing to the local library:

```go
module my-cdoc-test

go 1.22

require github.com/aarepuusepp/libcdoc-go/v2 v0.0.0

replace github.com/aarepuusepp/libcdoc-go/v2 => C:\WebROOT\TARKVARA.NEW\Digisign\cdoc1-go
```

**Important**: Use forward slashes `/` or escaped backslashes `\\` in the path, or Go will handle Windows backslashes automatically if you use the full Windows path format.

#### Step 4: Create Test Application

Create a `main.go` file:

```go
package main

import (
    "fmt"
    "github.com/aarepuusepp/libcdoc-go/v2/cdoc"
    "github.com/aarepuusepp/libcdoc-go/v2/cert"
)

func main() {
    fmt.Println("Testing cdoc1-go library on Windows")
    
    // Example: Load a certificate
    cert, err := cert.LoadCertificate("path/to/certificate.pem")
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        return
    }
    
    fmt.Printf("Certificate loaded: %s\n", cert.Subject.CommonName)
    
    // Create a builder
    builder := cdoc.NewBuilder()
    builder.WithRecipientCertificate(cert)
    
    fmt.Println("Library is working!")
}
```

#### Step 5: Run Your Application

```bash
go mod tidy
go run main.go
```

### Method 2: Go Workspace Mode (Recommended for Development)

Go workspaces allow you to work with multiple local modules simultaneously without publishing.

#### Step 1: Create Workspace Directory

```bash
mkdir C:\Projects\cdoc-workspace
cd C:\Projects\cdoc-workspace
```

#### Step 2: Initialize Workspace

```bash
go work init

# Add the library as a workspace module
go work use C:\WebROOT\TARKVARA.NEW\Digisign\cdoc1-go

# Add your test application
go work use ./my-app
```

#### Step 3: Create Test Application in Workspace

```bash
mkdir my-app
cd my-app
go mod init my-app
```

#### Step 4: Use Library in Your App

In your test application's `go.mod`:

```go
module my-app

go 1.22

require github.com/aarepuusepp/libcdoc-go/v2 v0.0.0
```

Since both modules are in the workspace, Go will automatically use the local version.

#### Step 5: Run Your Application

```bash
go mod tidy
go run main.go
```

### Method 3: Private Git Repository (For Team Collaboration)

If you want to share the library with your team without making it public:

#### Step 1: Set Up Private Git Repo

Push the library to a private Git repository (GitHub, GitLab, Bitbucket, etc.).

#### Step 2: Configure Git Authentication

For GitHub:
```bash
# Use SSH instead of HTTPS
git remote set-url origin git@github.com:yourorg/cdoc1-go.git

# Or configure Git credentials for HTTPS
git config --global credential.helper wincred  # Windows Credential Manager
```

#### Step 3: Use in Your Application

```go
module my-app

go 1.22

require github.com/aarepuusepp/libcdoc-go/v2 v0.1.0
```

#### Step 4: Configure Go for Private Repo

```bash
# For HTTPS with authentication
go env -w GOPRIVATE=github.com/yourorg/*
go env -w GONOPROXY=github.com/yourorg/*
go env -w GONOSUMDB=github.com/yourorg/*

# Configure git credentials (Windows)
git config --global url."https://yourusername:token@github.com/yourorg".insteadOf "https://github.com/yourorg"
```

### Method 4: Relative Path (Simple Local Development)

If your test app is in a subdirectory:

```
C:\Projects\
├── cdoc1-go\          (the library)
└── my-test-app\        (your test app)
```

In your test app's `go.mod`:

```go
module my-test-app

go 1.22

require github.com/aarepuusepp/libcdoc-go/v2 v0.0.0

replace github.com/aarepuusepp/libcdoc-go/v2 => ../cdoc1-go
```

## Testing the Library

### Quick Test: Build the CLI Tool

The library includes a CLI tool you can test immediately:

```powershell
# Navigate to the library directory
cd C:\WebROOT\TARKVARA.NEW\Digisign\cdoc1-go

# Build the CLI tool
go build -o cdoc.exe ./cli-tools/cdoc-cli

# Test encryption (if you have test certificates)
.\cdoc.exe encrypt -f test.pdf -r cert.pem -o test.cdoc

# Test decryption
.\cdoc.exe decrypt -f test.cdoc -k private_key.pem -o ./decrypted
```

### Running Unit Tests

```powershell
# Run all tests
go test ./...

# Run tests with verbose output
go test -v ./...

# Run specific test package
go test -v ./cdoc

# Run with coverage
go test -cover ./...
```

### Example: Simple Test Application

Create a complete example:

```go
package main

import (
    "fmt"
    "log"
    "os"
    "github.com/aarepuusepp/libcdoc-go/v2/cdoc"
    "github.com/aarepuusepp/libcdoc-go/v2/cert"
)

func main() {
    // Test 1: Load certificate
    fmt.Println("Test 1: Loading certificate...")
    certPEM := []byte(`-----BEGIN CERTIFICATE-----
    ... your certificate data ...
    -----END CERTIFICATE-----`)
    
    cert, err := cert.ParseCertificatePEM(certPEM)
    if err != nil {
        log.Fatalf("Failed to parse certificate: %v", err)
    }
    fmt.Printf("✓ Certificate loaded: %s\n", cert.Subject.CommonName)
    
    // Test 2: Create builder
    fmt.Println("\nTest 2: Creating CDOC builder...")
    builder := cdoc.NewBuilder()
    builder.Version(cdoc.Version11)
    builder.WithRecipientCertificate(cert)
    fmt.Println("✓ Builder created successfully")
    
    // Test 3: Add data file
    if len(os.Args) > 1 {
        filename := os.Args[1]
        fmt.Printf("\nTest 3: Adding data file: %s\n", filename)
        
        file, err := os.Open(filename)
        if err != nil {
            log.Fatalf("Failed to open file: %v\n", err)
        }
        defer file.Close()
        
        info, _ := file.Stat()
        builder.WithDataFile(info.Name(), file, info.Size())
        fmt.Println("✓ Data file added successfully")
    }
    
    fmt.Println("\n✓ All tests passed! Library is working on Windows.")
}
```

## Troubleshooting

### Common Issues on Windows

1. **Path Issues**
   - Use forward slashes `/` in `replace` directives or full Windows paths
   - Ensure paths don't contain spaces or special characters, or quote them

2. **Go Module Cache**
   - Clear cache if issues occur: `go clean -modcache`
   - Force module download: `go mod download -x`

3. **Permission Issues**
   - Run PowerShell as Administrator if needed
   - Check file permissions on certificates and keys

4. **PKCS#11 on Windows**
   - PKCS#11 libraries need to be `.dll` files on Windows
   - Place `.dll` files in `C:\Windows\System32` or specify full path

### Verifying Installation

```powershell
# Check Go version
go version

# Check module
go list -m all | Select-String cdoc1-go

# Check if replace directive is working
go mod why github.com/aarepuusepp/libcdoc-go/v2
```

## Next Steps

1. **Choose a method** from above (Method 1 or 2 recommended for quick testing)
2. **Create a test application** using the examples
3. **Test encryption/decryption** with your certificates
4. **Run the test suite** to verify everything works
5. **Build your application** integrating the library

## Additional Resources

- [Go Workspace Mode Documentation](https://go.dev/doc/tutorial/workspaces)
- [Go Modules Documentation](https://go.dev/doc/modules/managing-dependencies)
- Library source code: `C:\WebROOT\TARKVARA.NEW\Digisign\cdoc1-go`

