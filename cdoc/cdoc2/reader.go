package cdoc2

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"crypto/ecdsa"
	"crypto/rsa"
	"io"

	"github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2/bounds"
	"github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2/keyserver"
	"github.com/aarepuusepp/libcdoc-go/v2/crypto"
	"github.com/aarepuusepp/libcdoc-go/v2/internal"
)

// maxDecompressedGzipBytes caps gzip expansion during payload decode (overridable in tests).
var maxDecompressedGzipBytes = bounds.MaxDecompressedTarEntry

// Reader implements reading and decrypting CDOC2 files
type Reader struct {
	source          io.ReaderAt
	header          *Header
	headerHMAC      []byte
	fmk             []byte
	currentTar      *tar.Reader
	decryptedStream io.Reader

	// Key server support
	keyServerClient  *keyserver.Client
	keyServerConfigs map[string]keyserver.KeyServerConfig
}

// KeyServerAction provides key server client and config for decryption
type KeyServerAction struct {
	KeyServerClient *keyserver.Client
	KeyServerConfig keyserver.KeyServerConfig
}

// KeySharesAction provides fetched share bytes for decryption.
type KeySharesAction struct {
	ShareBytes  [][]byte
	MinRequired int
}

// FMKOptions provides decryption inputs for different recipient types
// Only one of RSAPrivateKey or ECDSAPrivateKey should be set for PUBLIC_KEY
// For SYMMETRIC_KEY provide SymmetricKey; for PASSWORD provide Password
// For KEY_SERVER provide KeyServerAction
// For PKCS#11 tokens, provide PKCS11Token instead of private keys
type FMKOptions struct {
	RSAPrivateKey   *rsa.PrivateKey
	ECDSAPrivateKey *ecdsa.PrivateKey
	SymmetricKey    []byte
	Password        string
	KeyServerAction *KeyServerAction
	KeySharesAction *KeySharesAction
	PKCS11Token     PKCS11TokenInterface // Token interface for PKCS#11 hardware tokens
}

// NewReader creates a new CDOC2 Chrome reader
// source must support io.ReaderAt (e.g., *os.File, *bytes.Reader)
func NewReader(source io.ReaderAt) (*Reader, error) {
	if source == nil {
		return nil, internal.NewDecryptionError("source cannot be nil", nil)
	}

	return &Reader{
		source:           source,
		keyServerConfigs: make(map[string]keyserver.KeyServerConfig),
	}, nil
}

// SetKeyServerClient sets the key server client for the reader
func (r *Reader) SetKeyServerClient(client *keyserver.Client) {
	r.keyServerClient = client
}

// AddKeyServerConfig adds a key server configuration
func (r *Reader) AddKeyServerConfig(config keyserver.KeyServerConfig) {
	if r.keyServerConfigs == nil {
		r.keyServerConfigs = make(map[string]keyserver.KeyServerConfig)
	}
	r.keyServerConfigs[config.ServerID] = config
}

// ReadHeader reads and parses the CDOC2 header
// This should be called first before decryption
func (r *Reader) ReadHeader() (*Header, error) {
	reader := io.NewSectionReader(r.source, 0, 1<<31-1) // Max int32 size

	header, headerHMAC, err := ParseHeader(reader)
	if err != nil {
		return nil, err
	}

	r.header = header
	r.headerHMAC = make([]byte, len(headerHMAC))
	copy(r.headerHMAC, headerHMAC)

	return header, nil
}

// GetLocks returns all recipient locks from the header
func (r *Reader) GetLocks() ([]Lock, error) {
	if r.header == nil {
		return nil, internal.NewDecryptionError("header not read, call ReadHeader() first", nil)
	}

	locks := make([]Lock, 0, len(r.header.Recipients))
	for _, rr := range r.header.Recipients {
		l := Lock{
			Label:        rr.KeyLabel,
			EncryptedFMK: append([]byte(nil), rr.EncryptedFMK...),
		}
		switch rr.FMKEncryptionMethod {
		case FMKEncryptionMethodXOR:
			// supported
		default:
			// keep unknown
		}

		switch c := rr.Capsule.(type) {
		case RSAPublicKeyCapsule:
			l.Type = LockTypePublicKey
			l.PKType = PKTypeRSA
			l.RecipientKey = append([]byte(nil), c.RecipientPublicKey...)
			l.KeyMaterial = append([]byte(nil), c.EncryptedKEK...)
		case ECCPublicKeyCapsule:
			l.Type = LockTypePublicKey
			l.PKType = PKTypeECC
			l.RecipientKey = append([]byte(nil), c.RecipientPublicKey...)
			l.KeyMaterial = append([]byte(nil), c.SenderPublicKey...)
		case SymmetricKeyCapsule:
			l.Type = LockTypeSymmetricKey
			l.Salt = append([]byte(nil), c.Salt...)
		case PBKDF2Capsule:
			l.Type = LockTypePassword
			l.Salt = append([]byte(nil), c.Salt...)
			l.PasswordSalt = append([]byte(nil), c.PasswordSalt...)
			l.KDFIter = c.Iterations
		case KeyServerCapsule:
			l.Type = LockTypeServer
			l.ServerID = c.KeyServerID
			l.TransactionID = c.TransactionID
			l.RecipientKey = append([]byte(nil), c.RecipientKey...)
			l.PKType = c.PKType
		case KeySharesCapsule:
			l.Type = LockTypeKeyShares
			l.KeyShares = append([]KeyShare(nil), c.Shares...)
			l.SharesSalt = append([]byte(nil), c.Salt...)
			l.RecipientID = c.RecipientID
			l.Label = rr.KeyLabel
		default:
			// Unknown capsule, skip
			continue
		}
		locks = append(locks, l)
	}
	return locks, nil
}

// ExtractFMK extracts the File Master Key for the given lock index
// This performs the key derivation and decryption based on lock type
func (r *Reader) ExtractFMK(lockIndex int, opts FMKOptions) ([]byte, error) {
	if r.header == nil {
		return nil, internal.NewDecryptionError("header not read", nil)
	}

	if lockIndex < 0 || lockIndex >= len(r.header.Recipients) {
		return nil, internal.NewDecryptionError(
			"invalid lock index",
			nil,
		)
	}

	// Convert to Lock
	locks, err := r.GetLocks()
	if err != nil {
		return nil, err
	}
	if lockIndex >= len(locks) {
		return nil, internal.NewDecryptionError("lock index out of range", nil)
	}
	lock := locks[lockIndex]

	// Choose private key interface based on provided options
	var priv interface{}
	if opts.RSAPrivateKey != nil {
		priv = opts.RSAPrivateKey
	} else if opts.ECDSAPrivateKey != nil {
		priv = opts.ECDSAPrivateKey
	}

	var keyServerAction *KeyServerAction
	if opts.KeyServerAction != nil {
		keyServerAction = opts.KeyServerAction
	} else if lock.Type == LockTypeServer && r.keyServerClient != nil {
		// Try to use reader's key server config
		if config, ok := r.keyServerConfigs[lock.ServerID]; ok {
			keyServerAction = &KeyServerAction{
				KeyServerClient: r.keyServerClient,
				KeyServerConfig: config,
			}
		}
	}
	fmk, err := ExtractFMKFromLockWithShares(lock, priv, opts.SymmetricKey, opts.Password, keyServerAction, opts.KeySharesAction, opts.PKCS11Token)
	if err != nil {
		return nil, err
	}

	// Cache for later decryption
	if r.fmk == nil {
		r.fmk = make([]byte, len(fmk))
	}
	copy(r.fmk, fmk)
	return fmk, nil
}

// BeginDecryption starts the decryption process using the provided FMK
func (r *Reader) BeginDecryption(fmk []byte) error {
	if len(fmk) != KeyLen {
		return internal.NewDecryptionError(
			"FMK must be 32 bytes",
			nil,
		)
	}

	if r.header == nil {
		return internal.NewDecryptionError("header not read", nil)
	}

	// Derive CEK from FMK
	cek, err := DeriveCEK(fmk)
	if err != nil {
		return err
	}

	// Verify header HMAC using HMAC key derived from FMK before decrypting payload
	hhk, err := DeriveHMACKey(fmk)
	if err != nil {
		return err
	}
	if err := VerifyHeaderHMAC(r.header, hhk, r.headerHMAC); err != nil {
		return err
	}

	// Calculate nonce position: after magic (5) + header_len (4) + header_data + headerHMAC (32)
	noncePos := int64(len(Label) + 4 + len(r.header.HeaderData) + KeyLen)

	// Read nonce (12 bytes)
	nonce := make([]byte, NonceLen)
	if _, err := r.source.ReadAt(nonce, noncePos); err != nil {
		return internal.NewDecryptionError("failed to read nonce", err)
	}

	// Read encrypted payload
	payloadStart := noncePos + NonceLen
	encryptedPayload, err := readAllFromReaderAt(r.source, payloadStart)
	if err != nil {
		return internal.NewDecryptionError("failed to read encrypted payload", err)
	}

	// Construct AAD (Additional Authenticated Data)
	// AAD = "CDOC20payload" + header + headerHMAC
	aad := []byte(PAYLOAD)
	aad = append(aad, r.header.HeaderData...)
	aad = append(aad, r.headerHMAC...)

	// Decrypt payload with ChaCha20-Poly1305
	decryptedPayload, err := crypto.DecryptChaCha20Poly1305(encryptedPayload, cek, nonce, aad)
	if err != nil {
		return internal.NewDecryptionError("failed to decrypt payload", err)
	}

	// Decompress if needed (CDOC2 uses zlib; legacy Go gzip is also accepted)
	decompressedPayload, err := decompressGzip(decryptedPayload)
	if err != nil {
		return internal.NewDecryptionError("failed to decompress payload", err)
	}

	// Create TAR reader
	r.decryptedStream = bytes.NewReader(decompressedPayload)
	r.currentTar = tar.NewReader(r.decryptedStream)
	r.fmk = make([]byte, KeyLen)
	copy(r.fmk, fmk)

	return nil
}

// NextFile reads the next file from the decrypted TAR archive
// Returns file name, size, and an error
// Returns io.EOF when no more files are available
func (r *Reader) NextFile() (name string, size int64, err error) {
	if r.currentTar == nil {
		return "", 0, internal.NewDecryptionError("decryption not started, call BeginDecryption() first", nil)
	}

	header, err := r.currentTar.Next()
	if err == io.EOF {
		return "", 0, io.EOF
	}
	if err != nil {
		return "", 0, internal.NewDecryptionError("failed to read tar header", err)
	}

	return header.Name, header.Size, nil
}

// Read reads data from the current file in the TAR archive
func (r *Reader) Read(p []byte) (int, error) {
	if r.currentTar == nil {
		return 0, internal.NewDecryptionError("decryption not started", nil)
	}

	return r.currentTar.Read(p)
}

// FinishDecryption cleans up resources
func (r *Reader) FinishDecryption() error {
	// Clear FMK from memory
	if r.fmk != nil {
		for i := range r.fmk {
			r.fmk[i] = 0
		}
		r.fmk = nil
	}

	r.currentTar = nil
	r.decryptedStream = nil

	return nil
}

// readAllFromReaderAt reads all data from a ReaderAt starting at offset
func readAllFromReaderAt(r io.ReaderAt, offset int64) ([]byte, error) {
	// Try to determine size if possible
	var data []byte
	buf := make([]byte, 32*1024) // 32KB chunks

	for {
		n, err := r.ReadAt(buf, offset+int64(len(data)))
		if n > 0 {
			data = append(data, buf[:n]...)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}

	return data, nil
}

// decompressGzip decompresses gzip-compressed data
func decompressGzip(data []byte) ([]byte, error) {
	// Check if it's gzip-compressed by checking magic bytes
	if len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b {
		// Gzip-compressed
		reader, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		defer func() { _ = reader.Close() }()
		limited := io.LimitReader(reader, int64(maxDecompressedGzipBytes)+1)
		out, err := io.ReadAll(limited)
		if err != nil {
			return nil, err
		}
		if len(out) > maxDecompressedGzipBytes {
			return nil, internal.NewParseError("decompressed payload exceeds limit", nil)
		}
		return out, nil
	}

	// Zlib is the standard CDOC2 payload format (RFC1950).
	if len(data) >= 2 && data[0]&0x0f == 8 && (int(data[0])*256+int(data[1]))%31 == 0 {
		reader, err := zlib.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		defer func() { _ = reader.Close() }()
		out, err := io.ReadAll(io.LimitReader(reader, int64(maxDecompressedGzipBytes)+1))
		if err != nil {
			return nil, err
		}
		if len(out) > maxDecompressedGzipBytes {
			return nil, internal.NewParseError("decompressed payload exceeds limit", nil)
		}
		return out, nil
	}
	// Historical Go releases also accepted raw tar payloads.
	if len(data) > maxDecompressedGzipBytes {
		return nil, internal.NewParseError("decompressed payload exceeds limit", nil)
	}
	return data, nil
}
