# CI/CLI maintenance validation — 2026-10-31

All three nested modules now declare Go 1.27.3. cdoc-cli and cdoc-test pin
published libcdoc-go/v2 v2.0.8; no local replace is needed. Transitive versions
are resolved from that release, not updated independently past its graph.
cdoc-server-mock has no external module dependency. CLI --version uses the
linked library's embedded Version. Two redundant Println newlines in the demo
were corrected to pass the current Go vet.

Validation performed:

- go mod verify, go test -mod=readonly, go vet -mod=readonly and go build
  -mod=readonly passed in all three nested modules (software/CGO-disabled).
- Test-Modules.ps1 passed the CLI version check, multi-file/unicode CDOC2
  roundtrip with SHA-256 comparison, and wrong-key rejection with no output.
- The cdoc-test demo completed all 16 CDOC1.1/CDOC2 synthetic-fixture scenarios
  in an isolated .local workspace; this is software coverage, not a physical card test.
- Dedicated GitHub CI job runs Test-Modules.ps1 on Ubuntu 24.04, in addition to
  existing root-module tests/lint/fuzz jobs. Root go test alone excludes nested modules.

Paired application CI tags: backend compares libcdoc v2.0.8 and UI v0.0.9;
UI compares backend v2.0.7. UI 0.0.9 regenerates the containerVersion API schema.
Plan/ledger, contract/OpenAPI/Orval parity, fast security regression, 80 UI unit
tests and production build passed locally. No new physical card, SoftHSM or
live central-server test was performed for these maintenance changes.

The existing library v2.0.8 tag is unchanged; CLI/CI source maintenance is on main.
Nested CLI modules have not been independently tagged for go install distribution.
