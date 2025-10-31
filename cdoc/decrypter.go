package cdoc

import (
	"io"
	"os"

	"crypto/x509"
    "bytes"

    "github.com/aarepuusepp/libcdoc-go/v2/crypto"
	"github.com/aarepuusepp/libcdoc-go/v2/internal"
	"github.com/aarepuusepp/libcdoc-go/v2/key"
	"github.com/aarepuusepp/libcdoc-go/v2/xmlenc"
    c2 "github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2"
	c2keyserver "github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2/keyserver"
)

// Decrypter implements decryption of CDOC documents
type Decrypter struct {
	cdocReader    io.Reader
	cdocFile      string
	privateKey    *key.PrivateKey
	token         Token              // Optional: token for decryption (PKCS#11, PKCS#12, etc.)
	certificate   *x509.Certificate // Optional: for recipient selection when multiple recipients
	password      string             // For password-based decryption (CDOC 2.0)
	symmetricKey  []byte             // For symmetric key decryption (CDOC 2.0)
	keyServerClient interface{}      // *cdoc2/keyserver.Client - set via SetKeyServerClient
	keyServerConfigs map[string]interface{} // map[serverID]*cdoc2/keyserver.KeyServerConfig
	outputDir     string
	outputWriter  io.Writer
}

// NewDecrypter creates a new Decrypter instance
func NewDecrypter() *Decrypter {
	return &Decrypter{}
}

// WithCDOC sets the CDOC input from a reader
func (d *Decrypter) WithCDOC(reader io.Reader) *Decrypter {
	d.cdocReader = reader
	return d
}

// WithCDOCFromFile sets the CDOC input from a file path
func (d *Decrypter) WithCDOCFromFile(filepath string) error {
	file, err := os.Open(filepath)
	if err != nil {
		return internal.NewDecryptionError("failed to open CDOC file", err)
	}
	d.cdocReader = file
	d.cdocFile = filepath
	return nil
}

// WithPrivateKey sets the private key for decryption
func (d *Decrypter) WithPrivateKey(privKey *key.PrivateKey) *Decrypter {
	d.privateKey = privKey
	return d
}

// WithPrivateKeyFromFile loads a private key from a file path
func (d *Decrypter) WithPrivateKeyFromFile(filepath string) error {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return internal.NewDecryptionError("failed to read private key file", err)
	}

	privKey, err := key.ParsePrivateKey(data)
	if err != nil {
		return internal.NewDecryptionError("failed to parse private key", err)
	}

	d.privateKey = privKey
	return nil
}

// WithCertificate sets an optional certificate for recipient selection
func (d *Decrypter) WithCertificate(cert *x509.Certificate) *Decrypter {
	d.certificate = cert
	return d
}

// WithToken sets a token (PKCS#11, PKCS#12, etc.) for decryption
func (d *Decrypter) WithToken(token Token) *Decrypter {
	d.token = token
	return d
}

// WithPassword sets the password for password-based decryption (CDOC 2.0 only)
func (d *Decrypter) WithPassword(password string) *Decrypter {
	d.password = password
	return d
}

// WithSymmetricKey sets the symmetric key for symmetric key decryption (CDOC 2.0 only)
func (d *Decrypter) WithSymmetricKey(key []byte) *Decrypter {
	d.symmetricKey = make([]byte, len(key))
	copy(d.symmetricKey, key)
	return d
}

// SetKeyServerClient sets the key server client for CDOC 2.0 decryption
func (d *Decrypter) SetKeyServerClient(client interface{}) *Decrypter {
	d.keyServerClient = client
	return d
}

// AddKeyServerConfig adds a key server configuration for CDOC 2.0 decryption
func (d *Decrypter) AddKeyServerConfig(config interface{}) *Decrypter {
	if d.keyServerConfigs == nil {
		d.keyServerConfigs = make(map[string]interface{})
	}
	// config should be keyserver.KeyServerConfig with ServerID field
	if cfg, ok := config.(interface{ GetServerID() string }); ok {
		d.keyServerConfigs[cfg.GetServerID()] = config
	}
	return d
}

// WithPKCS12Token loads a PKCS#12 keystore and creates a token for decryption
// password is the keystore password
// alias is optional - if not provided, the first valid key entry will be used
func (d *Decrypter) WithPKCS12Token(filepath string, password string, alias ...string) error {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return internal.NewDecryptionError("failed to read PKCS#12 file", err)
	}

	keyEntry, err := key.ParsePKCS12(data, password, alias...)
	if err != nil {
		return internal.NewDecryptionError("failed to parse PKCS#12 keystore", err)
	}

	token := NewPKCS12Token(keyEntry)
	d.token = token

	// Automatically set certificate from token
	cert, err := token.GetCertificate()
	if err != nil {
		return internal.NewDecryptionError("failed to get certificate from PKCS#12 token", err)
	}
	d.certificate = cert

	return nil
}

// WithPKCS11Token loads a PKCS#11 token and creates a token for decryption
func (d *Decrypter) WithPKCS11Token(config key.PKCS11Config) error {
	token, err := NewPKCS11Token(config)
	if err != nil {
		return err
	}

	d.token = token

	// Automatically set certificate from token
	cert, err := token.GetCertificate()
	if err != nil {
		token.Close()
		return internal.NewDecryptionError("failed to get certificate from PKCS#11 token", err)
	}
	d.certificate = cert

	return nil
}

// Decrypt decrypts the CDOC and returns decrypted data files
func (d *Decrypter) Decrypt() ([]DecryptedFile, error) {
	if err := d.validateParameters(); err != nil {
		return nil, err
	}

    // Detect CDOC version (2.0 FlatBuffers vs 1.x XML)
    var readerAt io.ReaderAt
    if f, ok := d.cdocReader.(*os.File); ok {
        readerAt = f
    } else if d.cdocFile != "" {
        f, err := os.Open(d.cdocFile)
        if err != nil {
            return nil, internal.NewDecryptionError("failed to reopen CDOC file", err)
        }
        defer f.Close()
        readerAt = f
    } else {
        // Buffer into memory
        data, err := io.ReadAll(d.cdocReader)
        if err != nil {
            return nil, internal.NewDecryptionError("failed to read CDOC data", err)
        }
        br := bytes.NewReader(data)
        readerAt = br
        // Reset cdocReader for later reads if needed
        d.cdocReader = br
    }

    ver, err := DetectFileVersion(readerAt)
    if err != nil {
        return nil, err
    }
    if ver == Version20 {
        return d.decryptCDOC2(readerAt)
    }

    // Parse CDOC 1.x document
    parser := NewParser()
    if err := parser.Parse(d.cdocReader); err != nil {
        return nil, err
    }

	// Get recipients
	recipients, err := parser.GetRecipients()
	if err != nil {
		return nil, err
	}

	// Select recipient
	recipient, err := d.selectRecipient(recipients)
	if err != nil {
		return nil, err
	}

	// Decrypt transport key
	dataKey, err := d.decryptTransportKey(recipient)
	if err != nil {
		return nil, err
	}

	// Decrypt content
	encryptedContent, err := parser.GetEncryptedContent()
	if err != nil {
		return nil, err
	}

	version := parser.GetVersion()
	var plaintext []byte
	if version == Version11 {
		plaintext, err = d.decryptContent11(encryptedContent, dataKey)
	} else {
		plaintext, err = d.decryptContent10(encryptedContent, dataKey)
	}
	if err != nil {
		return nil, err
	}

	// Check if this is DDOC (multiple files)
	mimeType := parser.GetMimeType()
	if mimeType == DDOCMimeType {
		// Parse DDOC XML structure to extract all files
		return ParseDDOC(plaintext)
	}

	// Single file - extract filename from metadata
	filename := parser.GetFilename()
	if filename == "" {
		filename = "decrypted_file"
	}

	return []DecryptedFile{
		{
			Name:    filename,
			Content: plaintext,
		},
	}, nil
}

// decryptCDOC2 handles CDOC 2.0 containers
func (d *Decrypter) decryptCDOC2(r io.ReaderAt) ([]DecryptedFile, error) {
    rdr, err := c2.NewReader(r)
    if err != nil {
        return nil, err
    }
    
    // Configure key server client and configs if provided
    if d.keyServerClient != nil {
        if client, ok := d.keyServerClient.(*c2keyserver.Client); ok {
            rdr.SetKeyServerClient(client)
        }
    }
    if d.keyServerConfigs != nil {
        for _, configInterface := range d.keyServerConfigs {
            if config, ok := configInterface.(c2keyserver.KeyServerConfig); ok {
                rdr.AddKeyServerConfig(config)
            }
        }
    }
    
    if _, err := rdr.ReadHeader(); err != nil {
        return nil, err
    }

    // Map recipients to Locks and select one
    locks, err := rdr.GetLocks()
    if err != nil {
        return nil, err
    }
    if len(locks) == 0 {
        return nil, internal.NewDecryptionError("no recipients in CDOC2 header", nil)
    }

    sel := 0
    if d.certificate != nil {
        // Try to find a lock that matches the certificate
        for i := range locks {
            ok, _ := locks[i].MatchesCertificate(d.certificate)
            if ok {
                sel = i
                break
            }
        }
    } else {
        // Try to find a compatible lock based on decryption method
        for i := range locks {
            lock := locks[i]
            if (d.privateKey != nil || d.token != nil) && (lock.Type == c2.LockTypePublicKey) {
                // If token is set, we'll extract the key from it later, so we can select this lock
                sel = i
                break
            } else if d.password != "" && lock.Type == c2.LockTypePassword {
                sel = i
                break
            } else if d.symmetricKey != nil && lock.Type == c2.LockTypeSymmetricKey {
                sel = i
                break
            }
        }
    }

    // Prepare FMK options from provided key/token/password
    var opts c2.FMKOptions
    if d.token != nil {
        // Extract private key from token for CDOC2
        if pkcs12Token, ok := d.token.(*PKCS12Token); ok {
            if pkcs12Token.keyEntry != nil && pkcs12Token.keyEntry.PrivateKey != nil {
                // Extract RSA or ECC private key from token
                if rsaKey, ok := pkcs12Token.keyEntry.PrivateKey.RSAPrivateKey(); ok {
                    opts.RSAPrivateKey = rsaKey
                } else if ecKey, ok := pkcs12Token.keyEntry.PrivateKey.ECPrivateKey(); ok {
                    opts.ECDSAPrivateKey = ecKey
                } else {
                    return nil, internal.NewDecryptionError("token does not contain RSA or ECC private key", nil)
                }
            } else {
                return nil, internal.NewDecryptionError("token does not contain a private key", nil)
            }
        } else if pkcs11Token, ok := d.token.(*PKCS11Token); ok {
            // PKCS#11 token: use token methods for CDOC2 decryption
            // Store token reference in FMKOptions - ExtractFMKFromLock will use it
            opts.PKCS11Token = pkcs11Token
        } else {
            return nil, internal.NewDecryptionError("token type not yet supported for CDOC2", nil)
        }
    }
    if d.privateKey != nil {
        if rsaKey, ok := d.privateKey.RSAPrivateKey(); ok {
            opts.RSAPrivateKey = rsaKey
        } else if ecKey, ok := d.privateKey.ECPrivateKey(); ok {
            opts.ECDSAPrivateKey = ecKey
        }
    }
    if d.password != "" {
        opts.Password = d.password
    }
    if d.symmetricKey != nil {
        opts.SymmetricKey = d.symmetricKey
    }
    
    // Configure key server action if a key server lock is selected and client/config are available
    selectedLock := locks[sel]
    if selectedLock.Type == c2.LockTypeServer {
        if d.keyServerClient != nil && d.keyServerConfigs != nil {
            if client, ok := d.keyServerClient.(*c2keyserver.Client); ok {
                if configInterface, ok := d.keyServerConfigs[selectedLock.ServerID]; ok {
                    if config, ok := configInterface.(c2keyserver.KeyServerConfig); ok {
                        opts.KeyServerAction = &c2.KeyServerAction{
                            KeyServerClient: client,
                            KeyServerConfig: config,
                        }
                    }
                }
            }
        }
    }
    
    // If no decryption method provided, try to find a compatible lock
    if opts.RSAPrivateKey == nil && opts.ECDSAPrivateKey == nil && opts.Password == "" && opts.SymmetricKey == nil && opts.KeyServerAction == nil {
        return nil, internal.NewDecryptionError("no decryption method provided (private key, password, symmetric key, or key server)", nil)
    }

    // Extract FMK
    fmk, err := rdr.ExtractFMK(sel, opts)
    if err != nil {
        return nil, err
    }
    defer func() { for i := range fmk { fmk[i] = 0 } }()

    // Begin decryption
    if err := rdr.BeginDecryption(fmk); err != nil {
        return nil, err
    }
    defer rdr.FinishDecryption()

    // Iterate tar entries and collect files
    var files []DecryptedFile
    for {
        name, size, err := rdr.NextFile()
        if err == io.EOF {
            break
        }
        if err != nil {
            return nil, err
        }
        buf := make([]byte, size)
        if _, err := io.ReadFull(rdr, buf); err != nil {
            return nil, internal.NewDecryptionError("failed to read tar entry", err)
        }
        files = append(files, DecryptedFile{Name: name, Content: buf})
    }

    return files, nil
}

// DecryptToDirectory decrypts the CDOC and writes files to a directory
func (d *Decrypter) DecryptToDirectory(dirpath string) ([]string, error) {
	if err := os.MkdirAll(dirpath, 0755); err != nil {
		return nil, internal.NewDecryptionError("failed to create output directory", err)
	}

	files, err := d.Decrypt()
	if err != nil {
		return nil, err
	}

	var filepaths []string
	for _, file := range files {
		filepath := dirpath + "/" + file.Name
		if err := os.WriteFile(filepath, file.Content, 0644); err != nil {
			return nil, internal.NewDecryptionError("failed to write decrypted file", err)
		}
		filepaths = append(filepaths, filepath)
	}

	return filepaths, nil
}

// DecryptedFile represents a decrypted file
type DecryptedFile struct {
	Name    string
	Content []byte
}

// selectRecipient selects the appropriate recipient from the list
func (d *Decrypter) selectRecipient(recipients []xmlenc.Recipient) (xmlenc.Recipient, error) {
	if len(recipients) == 0 {
		return nil, internal.NewDecryptionError("no recipients found in CDOC", nil)
	}

	if len(recipients) == 1 {
		return recipients[0], nil
	}

	// Multiple recipients: need certificate to match
	if d.certificate == nil {
		return nil, internal.NewDecryptionError(
			"CDOC contains multiple recipients, certificate needed for selection",
			nil,
		)
	}

	// Find matching recipient
	for _, recipient := range recipients {
		if recipient.GetCertificate() != nil {
			// Compare certificates
			recipientCert := recipient.GetCertificate()
			if d.certificate.Equal(recipientCert) {
				return recipient, nil
			}
		}
	}

	return nil, internal.NewDecryptionError(
		"provided certificate does not match any recipient in CDOC",
		nil,
	)
}

// decryptTransportKey decrypts the transport key using the recipient's method
func (d *Decrypter) decryptTransportKey(recipient xmlenc.Recipient) ([]byte, error) {
	// Prefer token over private key
	if d.token != nil {
		return d.decryptTransportKeyWithToken(recipient)
	}

	if d.privateKey == nil {
		return nil, internal.NewDecryptionError("private key or token not set", nil)
	}

	switch r := recipient.(type) {
	case *xmlenc.RSARecipient:
		return d.decryptRSATransportKey(r)
	case *xmlenc.ECRecipient:
		return d.decryptECTransportKey(r)
	default:
		return nil, internal.NewDecryptionError("unsupported recipient type", nil)
	}
}

// decryptTransportKeyWithToken decrypts the transport key using a token
func (d *Decrypter) decryptTransportKeyWithToken(recipient xmlenc.Recipient) ([]byte, error) {
	if d.token == nil {
		return nil, internal.NewDecryptionError("token not set", nil)
	}

	switch r := recipient.(type) {
	case *xmlenc.RSARecipient:
		return d.token.DecryptRSA(r.EncryptedKey)
	case *xmlenc.ECRecipient:
		ephemeralKey := r.GetEphemeralPublicKey()
		encryptedKey, err := r.GetEncryptedKey()
		if err != nil {
			return nil, internal.NewDecryptionError("failed to get encrypted key", err)
		}
		return d.token.DecryptEC(
			ephemeralKey,
			r.GetAlgorithmID(),
			r.GetPartyUInfo(),
			r.GetPartyVInfo(),
			encryptedKey,
		)
	default:
		return nil, internal.NewDecryptionError("unsupported recipient type", nil)
	}
}

// decryptRSATransportKey decrypts RSA transport key
func (d *Decrypter) decryptRSATransportKey(recipient *xmlenc.RSARecipient) ([]byte, error) {
	privKey, ok := d.privateKey.RSAPrivateKey()
	if !ok {
		return nil, internal.NewDecryptionError("private key is not RSA", nil)
	}

	return crypto.DecryptRSA(recipient.EncryptedKey, privKey)
}

// decryptECTransportKey decrypts EC transport key
func (d *Decrypter) decryptECTransportKey(recipient *xmlenc.ECRecipient) ([]byte, error) {
	privKey, ok := d.privateKey.ECPrivateKey()
	if !ok {
		return nil, internal.NewDecryptionError("private key is not EC", nil)
	}

	// Perform ECDH key agreement
	sharedSecret, err := crypto.ECDHKeyAgreement(privKey, recipient.GetEphemeralPublicKey())
	if err != nil {
		return nil, internal.NewDecryptionError("failed ECDH key agreement", err)
	}

	// Derive wrap key via ConcatKDF
	wrapKey, err := crypto.ConcatKDF(
		sharedSecret,
		recipient.GetAlgorithmID(),
		recipient.GetPartyUInfo(),
		recipient.GetPartyVInfo(),
	)
	if err != nil {
		return nil, internal.NewDecryptionError("failed ConcatKDF", err)
	}

	// Unwrap transport key
	encryptedKey, err := recipient.GetEncryptedKey()
	if err != nil {
		return nil, internal.NewDecryptionError("failed to decode encrypted key", err)
	}

	return crypto.UnwrapAES256(encryptedKey, wrapKey)
}

// decryptContent11 decrypts CDOC 1.1 content (AES-256-GCM)
func (d *Decrypter) decryptContent11(encryptedContent []byte, dataKey []byte) ([]byte, error) {
	if len(encryptedContent) < 12 {
		return nil, internal.NewDecryptionError("encrypted content too short", nil)
	}

	// Extract IV (first 12 bytes)
	iv := encryptedContent[:12]
	ciphertext := encryptedContent[12:]

	return crypto.DecryptAESGCM(ciphertext, dataKey, iv)
}

// decryptContent10 decrypts CDOC 1.0 content (AES-128-CBC)
func (d *Decrypter) decryptContent10(encryptedContent []byte, dataKey []byte) ([]byte, error) {
	if len(encryptedContent) < 16 {
		return nil, internal.NewDecryptionError("encrypted content too short", nil)
	}

	// Extract IV (first 16 bytes)
	iv := encryptedContent[:16]
	ciphertext := encryptedContent[16:]

	return crypto.DecryptAESCBC(ciphertext, dataKey, iv)
}

// validateParameters validates required parameters are set
func (d *Decrypter) validateParameters() error {
	if d.cdocReader == nil && d.cdocFile == "" {
		return internal.NewDecryptionError("CDOC input not set", nil)
	}

	// Check if any decryption method is provided
	if d.privateKey == nil && d.token == nil && d.password == "" && d.symmetricKey == nil {
		return internal.NewDecryptionError("no decryption method provided (private key, token, password, or symmetric key)", nil)
	}

	return nil
}
