# Multiple recipients and files — libcdoc-go 2.0.8

Use the /v2 module import. Reuse a single Builder, add every recipient and input
before BuildToFile/BuildToWriter, and check errors. All recipients protect the same
payload; each has its own key transport. One matching private key decrypts it.

This complete helper creates a standalone CDOC2 container from certificate and
input paths (use Version11 for XML CDOC1.1):

```go
package example

import "github.com/aarepuusepp/libcdoc-go/v2/cdoc"

func EncryptMany(certificates, inputs []string, output string) error {
    b := cdoc.NewBuilder().Version(cdoc.Version20)
    for _, path := range certificates {
        if err := b.WithRecipientFromPath(path); err != nil { return err }
    }
    for _, path := range inputs {
        if err := b.WithDataFileFromPath(path); err != nil { return err }
    }
    return b.BuildToFile(output)
}
```

WithRecipientCertificate returns an error after validating the certificate.
WithDataFile(name, reader, size) is a Builder setter; use a correct length and
replayable input if performing another build. Filename/path policy remains the
application's responsibility. Keep private keys and personal test files out of Git.

CDOC1 uses XML EncryptedKey recipient elements and embeds multiple files in DDOC
content. CDOC2 uses binary recipient capsules and a zlib TAR payload, and does not
necessarily embed X.509 certificates. Avoid interpreting a label as certificate
validity. See [current README](../README.md) for supported recipients and
[reference tests](../cdoc/testdata/cdoc2-reference/README.md) for independent coverage.

Decrypt returns the files after authentication. Do not expose output on an error.
Full card/browser/central-service compatibility requires its own acceptance test;
an internal multi-recipient roundtrip does not establish that matrix.
