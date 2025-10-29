package cdoc

import (
	"io"
	"os"

	"crypto/x509"

	"github.com/yourorg/cdoc1-go/cert"
	"github.com/yourorg/cdoc1-go/internal"
)

// Builder implements the fluent API for building CDOC encrypted documents
type Builder struct {
	version       Version
	dataFiles     []DataFile
	recipients    []*x509.Certificate
	output        io.Writer
	outputFile    string
}

// NewBuilder creates a new Builder instance
func NewBuilder() *Builder {
	return &Builder{
		version: Version11, // Default to 1.1
	}
}

// Version sets the CDOC version (1.0 or 1.1)
func (b *Builder) Version(version Version) *Builder {
	b.version = version
	return b
}

// WithDataFile adds a data file to encrypt from a reader
func (b *Builder) WithDataFile(name string, content io.Reader, size int64) *Builder {
	b.dataFiles = append(b.dataFiles, DataFile{
		Name:     name,
		Content:  content,
		Size:     size,
		MimeType: "application/octet-stream",
	})
	return b
}

// WithDataFileFromPath adds a data file to encrypt from a file path
func (b *Builder) WithDataFileFromPath(filepath string) error {
	file, err := os.Open(filepath)
	if err != nil {
		return internal.NewValidationError("failed to open file: "+filepath, err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return internal.NewValidationError("failed to stat file: "+filepath, err)
	}

	b.WithDataFile(info.Name(), file, info.Size())
	return nil
}

// WithRecipient adds a recipient certificate from a reader
func (b *Builder) WithRecipient(certReader io.Reader) error {
	certData, err := io.ReadAll(certReader)
	if err != nil {
		return internal.NewCertificateError("failed to read certificate", err)
	}

	certificate, err := cert.ParseCertificate(certData)
	if err != nil {
		return internal.NewCertificateError("failed to parse certificate", err)
	}

	// Validate certificate
	if err := cert.ValidateRecipientCertificate(certificate); err != nil {
		return err
	}

	b.recipients = append(b.recipients, certificate)
	return nil
}

// WithRecipientFromPath adds a recipient certificate from a file path
func (b *Builder) WithRecipientFromPath(filepath string) error {
	file, err := os.Open(filepath)
	if err != nil {
		return internal.NewCertificateError("failed to open certificate file", err)
	}
	defer file.Close()

	return b.WithRecipient(file)
}

// WithRecipientCertificate adds a recipient using an already-parsed certificate
func (b *Builder) WithRecipientCertificate(certificate *x509.Certificate) error {
	// Validate certificate
	if err := cert.ValidateRecipientCertificate(certificate); err != nil {
		return err
	}

	b.recipients = append(b.recipients, certificate)
	return nil
}

// BuildToWriter builds the CDOC document and writes it to the provided writer
func (b *Builder) BuildToWriter(w io.Writer) error {
	if err := b.validateParameters(); err != nil {
		return err
	}

	composer := NewComposer()
	composer.SetVersion(b.version)
	composer.SetRecipients(b.recipients)
	composer.SetDataFiles(b.dataFiles)

	return composer.Compose(w)
}

// BuildToFile builds the CDOC document and writes it to a file
func (b *Builder) BuildToFile(filepath string) error {
	file, err := os.Create(filepath)
	if err != nil {
		return internal.NewEncryptionError("failed to create output file", err)
	}
	defer file.Close()

	return b.BuildToWriter(file)
}

// BuildToOutputStream is an alias for BuildToWriter (for consistency with Java API)
func (b *Builder) BuildToOutputStream(w io.Writer) error {
	return b.BuildToWriter(w)
}

// validateParameters validates that all required parameters are set
func (b *Builder) validateParameters() error {
	if len(b.dataFiles) == 0 {
		return internal.NewValidationError("CDOC must contain at least 1 data file", nil)
	}

	if len(b.recipients) == 0 {
		return internal.NewValidationError("CDOC must contain at least 1 recipient", nil)
	}

	return nil
}
