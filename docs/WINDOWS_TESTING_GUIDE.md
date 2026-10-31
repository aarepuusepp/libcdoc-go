# Windows development and testing — 2.0.8

Use Go 1.27.3+. Run from the repository root in PowerShell:

```powershell
$env:GOWORK = 'off'
$env:CGO_ENABLED = '0'
go mod verify
go test ./...
go vet ./...
```

PKCS#11/race tests need an x64 compiler. Adjust the installed location:

```powershell
$env:CGO_ENABLED = '1'
$env:CC = 'C:\msys64-2\ucrt64\bin\gcc.exe'
$env:PATH = (Split-Path $env:CC) + ';' + $env:PATH
go test -race ./...
go vet ./...
```

Software tests do not need a real card; physical card/DigiDoc4 results are recorded
in [release notes](../RELEASE-NOTES.md). Install in a consuming application with
`go get github.com/aarepuusepp/libcdoc-go/v2@v2.0.8` and commit go.mod/go.sum.
Temporary workspaces/replacements belong to local development only; verify releases
with GOWORK=off and the published version. Never commit local module overrides.

CLI tools have separate go.mod files. Enter cli-tools/cdoc-cli or cli-tools/cdoc-test
before building/running them and review their source-checkout replace directives.
They are developer utilities, not EID-PD installed runtime components.
