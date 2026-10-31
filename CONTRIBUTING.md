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
