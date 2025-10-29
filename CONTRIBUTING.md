# Contributing to cdoc1-go

Thank you for your interest in contributing to cdoc1-go!

## Development Setup

1. Fork the repository
2. Clone your fork: `git clone https://github.com/yourusername/cdoc1-go.git`
3. Create a branch: `git checkout -b feature/your-feature`
4. Make your changes
5. Run tests: `go test ./...`
6. Ensure formatting: `gofmt -w .`
7. Run linting: `golangci-lint run`
8. Commit your changes: `git commit -am 'Add feature'`
9. Push to your fork: `git push origin feature/your-feature`
10. Create a Pull Request

## Code Style

- Follow standard Go conventions
- Use `gofmt` for formatting
- Run `go vet` before committing
- Write tests for new functionality
- Aim for ≥80% code coverage

## Testing

- Unit tests: `go test ./...`
- Integration tests: `go test -tags=integration ./...`
- Coverage: `go test -cover ./...`

## Reporting Issues

Please use the GitHub issue tracker to report bugs or request features.

