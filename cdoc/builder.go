package cdoc

import (
	"io"
	"os"

	"crypto/x509"

	c2 "github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2"
	c2keyserver "github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2/keyserver"
	c2keyshares "github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2/keyshares"
	"github.com/aarepuusepp/libcdoc-go/v2/cert"
	"github.com/aarepuusepp/libcdoc-go/v2/internal"
)

// PasswordRecipient holds password and iterations for CDOC 2.0
type PasswordRecipient struct {
	Password   string
	Iterations int32
}

// Builder implements the fluent API for building CDOC encrypted documents
type Builder struct {
	version             Version
	dataFiles           []DataFile
	recipients          []*x509.Certificate
	passwords           []PasswordRecipient
	symmetricKeys       [][]byte
	keyServerRecipients []KeyServerRecipient   // For CDOC 2.0 key server recipients
	authMeansRecipients []AuthMeansRecipient   // Smart-ID / Mobile-ID
	keyServerClient     interface{}            // *cdoc2/keyserver.Client - set via SetKeyServerClient
	keyServerConfigs    map[string]interface{} // map[serverID]*cdoc2/keyserver.KeyServerConfig
	sharesClients       []*c2keyshares.Client
	sharesMinRequired   int
}

// AuthMeansRecipient holds Smart-ID / Mobile-ID recipient configuration.
type AuthMeansRecipient struct {
	EtsiIdentifier string
	Label          string
}

// KeyServerRecipient holds certificate and key server configuration for CDOC 2.0
type KeyServerRecipient struct {
	Certificate *x509.Certificate
	ServerID    string // UUID of the key server
	Label       string // Optional label
	ExpiryTime  uint64 // Optional expiry time (Unix timestamp)
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
	defer func() { _ = file.Close() }()

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
	defer func() { _ = file.Close() }()

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

// WithPassword adds a password-based recipient (CDOC 2.0 only)
func (b *Builder) WithPassword(password string) error {
	if b.version != Version20 {
		return internal.NewValidationError("password recipients are only supported in CDOC 2.0", nil)
	}
	b.passwords = append(b.passwords, PasswordRecipient{Password: password, Iterations: 100000})
	return nil
}

// WithPasswordAndIterations adds a password-based recipient with custom PBKDF2 iterations (CDOC 2.0 only)
func (b *Builder) WithPasswordAndIterations(password string, iterations int32) error {
	if b.version != Version20 {
		return internal.NewValidationError("password recipients are only supported in CDOC 2.0", nil)
	}
	b.passwords = append(b.passwords, PasswordRecipient{Password: password, Iterations: iterations})
	return nil
}

// WithSymmetricKey adds a symmetric key-based recipient (CDOC 2.0 only)
func (b *Builder) WithSymmetricKey(key []byte) error {
	if b.version != Version20 {
		return internal.NewValidationError("symmetric key recipients are only supported in CDOC 2.0", nil)
	}
	if len(key) != 32 {
		return internal.NewValidationError("symmetric key must be 32 bytes (256 bits)", nil)
	}
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)
	b.symmetricKeys = append(b.symmetricKeys, keyCopy)
	return nil
}

// WithKeyServerRecipient adds a certificate recipient that uses a key transfer server (CDOC 2.0 only)
func (b *Builder) WithKeyServerRecipient(cert *x509.Certificate, serverID, label string, expiryTime uint64) error {
	if b.version != Version20 {
		return internal.NewValidationError("key server recipients are only supported in CDOC 2.0", nil)
	}
	if cert == nil {
		return internal.NewValidationError("certificate cannot be nil", nil)
	}
	if serverID == "" {
		return internal.NewValidationError("server ID cannot be empty", nil)
	}
	b.keyServerRecipients = append(b.keyServerRecipients, KeyServerRecipient{
		Certificate: cert,
		ServerID:    serverID,
		Label:       label,
		ExpiryTime:  expiryTime,
	})
	return nil
}

// SetKeyServerClient sets the key server client for CDOC 2.0 encryption
// This must be called before BuildToWriter if using key server recipients
func (b *Builder) SetKeyServerClient(client *c2keyserver.Client) *Builder {
	b.keyServerClient = client
	return b
}

// AddKeyServerConfig adds a key server configuration for CDOC 2.0 encryption
// This must be called before BuildToWriter if using key server recipients
func (b *Builder) AddKeyServerConfig(config c2keyserver.KeyServerConfig) *Builder {
	if b.keyServerConfigs == nil {
		b.keyServerConfigs = make(map[string]interface{})
	}
	b.keyServerConfigs[config.ServerID] = config
	return b
}

// WithAuthMeansRecipient adds a Smart-ID / Mobile-ID recipient (CDOC 2.0 central key-shares).
func (b *Builder) WithAuthMeansRecipient(etsiIdentifier, label string) error {
	if b.version != Version20 {
		return internal.NewValidationError("auth-means recipients are only supported in CDOC 2.0", nil)
	}
	if etsiIdentifier == "" {
		return internal.NewValidationError("ETSI identifier cannot be empty", nil)
	}
	b.authMeansRecipients = append(b.authMeansRecipients, AuthMeansRecipient{
		EtsiIdentifier: etsiIdentifier,
		Label:          label,
	})
	return nil
}

// SetSharesClients configures key-shares servers for auth-means encryption.
func (b *Builder) SetSharesClients(clients []*c2keyshares.Client, minRequired int) *Builder {
	b.sharesClients = clients
	b.sharesMinRequired = minRequired
	return b
}

// BuildToWriter builds the CDOC document and writes it to the provided writer
func (b *Builder) BuildToWriter(w io.Writer) error {
	if err := b.validateParameters(); err != nil {
		return err
	}

	if b.version == Version20 {
		// CDOC 2.0 writer path
		writer := c2.NewWriter(w)

		// Configure key server client and configs if provided
		if b.keyServerClient != nil {
			if client, ok := b.keyServerClient.(*c2keyserver.Client); ok {
				writer.SetKeyServerClient(client)
			}
		}
		if b.keyServerConfigs != nil {
			for _, configInterface := range b.keyServerConfigs {
				if config, ok := configInterface.(c2keyserver.KeyServerConfig); ok {
					writer.AddKeyServerConfig(config)
				}
			}
		}
		if len(b.sharesClients) > 0 {
			writer.SetSharesClients(b.sharesClients, b.sharesMinRequired)
		}

		// Map certificate recipients (regular, not key server)
		for _, rc := range b.recipients {
			if err := writer.AddRecipient(c2.Recipient{Certificate: rc}); err != nil {
				return err
			}
		}
		// Map key server recipients
		for _, ksr := range b.keyServerRecipients {
			if err := writer.AddRecipient(c2.Recipient{
				Certificate: ksr.Certificate,
				ServerID:    ksr.ServerID,
				Label:       ksr.Label,
				ExpiryTime:  ksr.ExpiryTime,
			}); err != nil {
				return err
			}
		}
		for _, amr := range b.authMeansRecipients {
			if err := writer.AddRecipient(c2.Recipient{
				AuthMeansID: amr.EtsiIdentifier,
				Label:       amr.Label,
			}); err != nil {
				return err
			}
		}
		// Map password recipients
		for _, pwd := range b.passwords {
			if err := writer.AddRecipient(c2.Recipient{Password: pwd.Password, KDFIterations: pwd.Iterations}); err != nil {
				return err
			}
		}
		// Map symmetric key recipients
		for _, key := range b.symmetricKeys {
			if err := writer.AddRecipient(c2.Recipient{SymmetricKey: key}); err != nil {
				return err
			}
		}
		if err := writer.BeginEncryption(); err != nil {
			return err
		}
		// Map data files to cdoc2.DataFile
		files := make([]c2.DataFile, 0, len(b.dataFiles))
		for _, df := range b.dataFiles {
			files = append(files, c2.DataFile{
				Name:     df.Name,
				Content:  df.Content,
				Size:     df.Size,
				MimeType: df.MimeType,
			})
		}
		if err := writer.WriteEncryptedData(files); err != nil {
			return err
		}
		return writer.FinishEncryption()
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
	defer func() { _ = file.Close() }()

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

	totalRecipients := len(b.recipients) + len(b.passwords) + len(b.symmetricKeys)
	if b.version == Version20 {
		totalRecipients += len(b.keyServerRecipients) + len(b.authMeansRecipients)
	}
	if totalRecipients == 0 {
		return internal.NewValidationError("CDOC must contain at least 1 recipient", nil)
	}

	return nil
}
