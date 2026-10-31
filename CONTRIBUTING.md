# Contributing to libcdoc-go

Use Go 1.27.3+, as required by go.mod. Clone this repository/your fork, create a
branch, and preserve unrelated work. Format changed Go files with gofmt.

```sh
go mod verify
go test ./...
go vet ./...
golangci-lint run
```

With CGO and a matching compiler, also run `go test -race ./...`. Nested CLI
modules have their own builds. Cryptographic changes require independent vectors
or another implementation, not only an internal roundtrip. Keep synthetic/public
fixture provenance and licenses. Do not commit local secrets, PIN/CAN or user CDOCs.

[Windows setup](docs/WINDOWS_TESTING_GUIDE.md), [publishing](docs/PUBLISHING.md).
Preserve the paired Digisign CDOC2 contract lock and external proof-profile blockers.
Mock-only results do not establish live RIA interoperability.

## Nested CLI validation

Run `pwsh -File cli-tools/Test-Modules.ps1` from this repository. The three
nested modules use Go 1.27.3; the two consumers pin published libcdoc-go v2.0.8
without local replacements. The dedicated CI job verifies/tests/vets/builds each
and checks an isolated multi-file roundtrip plus wrong-key rejection. The root
`go test ./...` alone does not enter nested Go modules. CLI --version reports
the linked library's embedded version rather than a stale CLI constant.
