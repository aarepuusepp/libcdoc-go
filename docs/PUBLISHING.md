# Publishing libcdoc-go

Current module release: v2.0.8. Module path: github.com/aarepuusepp/libcdoc-go/v2.
Bitbucket origin and public GitHub mirror must contain the same release commit/tag.

1. Choose an unused next patch version; update VERSION, README and release notes.
2. Run mod verify, tests, race tests, vet and lint. Stage only reviewed changes.
3. Commit and create an annotated v2 tag for that new version.
4. Push the branch and tag to both origin and github. Never move published tags.
5. From a separate consumer without local replace/workspace, download that exact
   version with Go proxy/checksum verification. Check GitHub CI.
6. Update Digisign/reader go.mod/go.sum and test them. Reader/package versions must
   match. Extension and SDK have independent release versions.

Read/download checks for the existing release:

```sh
git ls-remote github refs/tags/v2.0.8
go mod download github.com/aarepuusepp/libcdoc-go/v2@v2.0.8
go mod verify
```

Documentation commits are pushed without new runtime tags. Test clean source
before packaging; retain machine configuration/data under ignored .local.
