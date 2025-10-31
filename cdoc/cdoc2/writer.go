package cdoc2

import (
    "crypto/ecdsa"
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
    "crypto/x509"
    "encoding/binary"
    "fmt"
    "io"

    flatbuffers "github.com/google/flatbuffers/go"
    hdr "github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2/schema/cdoc20/header"
    rcpt "github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2/schema/cdoc20/recipients"

    xpbkdf2 "golang.org/x/crypto/pbkdf2"

    "github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2/keyserver"
    "github.com/aarepuusepp/libcdoc-go/v2/crypto"
    "github.com/aarepuusepp/libcdoc-go/v2/internal"
)

// Writer implements writing and encrypting CDOC2 files
type Writer struct {
	destination    io.Writer
	fmk            []byte
	recipients     []Recipient
	headerWritten  bool
	payloadStarted bool
	headerData     []byte // Store header data for AAD construction
	
	// Key server support
	keyServerClient *keyserver.Client
	keyServerConfigs map[string]keyserver.KeyServerConfig // Map server ID to config
}

// Recipient represents a recipient for CDOC2 encryption
type Recipient struct {
	Certificate   *x509.Certificate // For RSA/ECC recipients
	Password      string            // For password-based recipients
	SymmetricKey  []byte            // For symmetric key recipients
	Label         string            // Optional label
	ServerID      string            // For key-server recipients
	ExpiryTime    uint64            // Optional expiry time
	KDFIterations int32             // For password-based (PBKDF2)
}

// NewWriter creates a new CDOC2 writer
func NewWriter(destination io.Writer) *Writer {
	return &Writer{
		destination:      destination,
		recipients:       []Recipient{},
		keyServerConfigs: make(map[string]keyserver.KeyServerConfig),
	}
}

// SetKeyServerClient sets the key server client for the writer
func (w *Writer) SetKeyServerClient(client *keyserver.Client) {
	w.keyServerClient = client
}

// AddKeyServerConfig adds a key server configuration
func (w *Writer) AddKeyServerConfig(config keyserver.KeyServerConfig) {
	if w.keyServerConfigs == nil {
		w.keyServerConfigs = make(map[string]keyserver.KeyServerConfig)
	}
	w.keyServerConfigs[config.ServerID] = config
}

// buildRSAKeyServerCapsule builds a KeyServerCapsule with RsaKeyDetails
func (w *Writer) buildRSAKeyServerCapsule(b *flatbuffers.Builder, recipientPublicKey []byte, serverID, transactionID string) flatbuffers.UOffsetT {
	// Create byte vector BEFORE starting nested objects
	pkVec := b.CreateByteVector(recipientPublicKey)
	
	// Build RsaKeyDetails
	rcpt.RsaKeyDetailsStart(b)
	rcpt.RsaKeyDetailsAddRecipientPublicKey(b, pkVec)
	rsaKeyDetailsOff := rcpt.RsaKeyDetailsEnd(b)
	
	// Build KeyServerCapsule
	ksIdStr := b.CreateString(serverID)
	txIdStr := b.CreateString(transactionID)
	
	rc := rcpt.KeyServerCapsuleStart
	rv := rcpt.KeyServerCapsuleEnd
	rc(b)
	rcpt.KeyServerCapsuleAddRecipientKeyDetailsType(b, rcpt.KeyDetailsUnionRsaKeyDetails)
	rcpt.KeyServerCapsuleAddRecipientKeyDetails(b, rsaKeyDetailsOff)
	rcpt.KeyServerCapsuleAddKeyserverId(b, ksIdStr)
	rcpt.KeyServerCapsuleAddTransactionId(b, txIdStr)
	return rv(b)
}

// buildECCKeyServerCapsule builds a KeyServerCapsule with EccKeyDetails
func (w *Writer) buildECCKeyServerCapsule(b *flatbuffers.Builder, recipientPublicKey []byte, serverID, transactionID string) flatbuffers.UOffsetT {
	// For ECC, recipientPublicKey should be in TLS 1.3 format (0x04 + X + Y)
	// Create byte vector BEFORE starting nested objects
	pkVec := b.CreateByteVector(recipientPublicKey)
	
	// Build EccKeyDetails
	rcpt.EccKeyDetailsStart(b)
	rcpt.EccKeyDetailsAddCurve(b, rcpt.EllipticCurvesecp384r1)
	rcpt.EccKeyDetailsAddRecipientPublicKey(b, pkVec)
	eccKeyDetailsOff := rcpt.EccKeyDetailsEnd(b)
	
	// Build KeyServerCapsule
	ksIdStr := b.CreateString(serverID)
	txIdStr := b.CreateString(transactionID)
	
	rc := rcpt.KeyServerCapsuleStart
	rv := rcpt.KeyServerCapsuleEnd
	rc(b)
	rcpt.KeyServerCapsuleAddRecipientKeyDetailsType(b, rcpt.KeyDetailsUnionEccKeyDetails)
	rcpt.KeyServerCapsuleAddRecipientKeyDetails(b, eccKeyDetailsOff)
	rcpt.KeyServerCapsuleAddKeyserverId(b, ksIdStr)
	rcpt.KeyServerCapsuleAddTransactionId(b, txIdStr)
	return rv(b)
}

// AddRecipient adds a recipient to the writer
func (w *Writer) AddRecipient(recipient Recipient) error {
	if w.headerWritten {
		return internal.NewEncryptionError("cannot add recipients after header is written", nil)
	}

	w.recipients = append(w.recipients, recipient)
	return nil
}

// BeginEncryption starts the encryption process
func (w *Writer) BeginEncryption() error {
	if len(w.recipients) == 0 {
		return internal.NewEncryptionError("no recipients specified", nil)
	}

	// Generate FMK
	fmk, err := GenerateFMK()
	if err != nil {
		return err
	}
	w.fmk = fmk

	// Build and write header
	if err := w.writeHeader(); err != nil {
		return err
	}

	w.headerWritten = true
	return nil
}

// writeHeader builds and writes the CDOC2 header
func (w *Writer) writeHeader() error {
    headerData, err := w.buildHeaderData()
	if err != nil {
		return err
	}

	// Derive HMAC key
	hmacKey, err := DeriveHMACKey(w.fmk)
	if err != nil {
		return err
	}

	// Calculate HMAC
	headerHMAC := computeHMACSHA256(headerData, hmacKey)

	// Write magic label
	if _, err := w.destination.Write([]byte(Label)); err != nil {
		return internal.NewEncryptionError("failed to write magic label", err)
	}

	// Write header length (big-endian)
	headerLen := uint32(len(headerData))
	if err := binary.Write(w.destination, binary.BigEndian, headerLen); err != nil {
		return internal.NewEncryptionError("failed to write header length", err)
	}

	// Write header data
	if _, err := w.destination.Write(headerData); err != nil {
		return internal.NewEncryptionError("failed to write header data", err)
	}

	// Store header data for AAD construction
	w.headerData = make([]byte, len(headerData))
	copy(w.headerData, headerData)

	// Write header HMAC
	if _, err := w.destination.Write(headerHMAC); err != nil {
		return internal.NewEncryptionError("failed to write header HMAC", err)
	}

	return nil
}

// buildHeaderData builds the FlatBuffers-encoded header
func (w *Writer) buildHeaderData() ([]byte, error) {
    if len(w.fmk) != KeyLen {
        return nil, internal.NewEncryptionError("FMK not initialized", nil)
    }

    b := flatbuffers.NewBuilder(1024)

    // Build recipients
    recOffsets := make([]flatbuffers.UOffsetT, 0, len(w.recipients))
    for _, r := range w.recipients {
        // Derive per-recipient KEK and encrypted FMK (XOR)
        var xor []byte
        var rrOffset flatbuffers.UOffsetT

        if r.Certificate != nil {
            switch pub := r.Certificate.PublicKey.(type) {
            case *rsa.PublicKey:
                // KEK random 32 bytes
                kek := make([]byte, KeyLen)
                if _, err := rand.Read(kek); err != nil {
                    return nil, internal.NewEncryptionError("failed to generate KEK", err)
                }
                // XOR FMK
                xor = XOREncrypt(w.fmk, kek)
                // Encrypt KEK with RSA PKCS#1 v1.5 (this is the key material)
                enc, err := crypto.EncryptRSA(kek, r.Certificate)
                if err != nil {
                    return nil, err
                }
                
                // Check if this is a key server recipient
                if r.ServerID != "" && w.keyServerClient != nil {
                    config, ok := w.keyServerConfigs[r.ServerID]
                    if !ok {
                        return nil, internal.NewEncryptionError(fmt.Sprintf("key server config not found for server ID: %s", r.ServerID), nil)
                    }
                    
                    // Send key material (encrypted KEK) to key server
                    capsuleInfo, err := w.keyServerClient.SendKey(config, r.Certificate.RawSubjectPublicKeyInfo, enc, "RSA", r.ExpiryTime)
                    if err != nil {
                        return nil, internal.NewEncryptionError("failed to send key to key server", err)
                    }
                    
                    // Build KeyServerCapsule with RsaKeyDetails
                    capOff := w.buildRSAKeyServerCapsule(b, r.Certificate.RawSubjectPublicKeyInfo, config.ServerID, capsuleInfo.TransactionID)
                    
                    // Build RecipientRecord with KeyServerCapsule
                    keyLabel := b.CreateString(r.Label)
                    encF := b.CreateByteVector(xor)
                    hdr.RecipientRecordStart(b)
                    hdr.RecipientRecordAddCapsuleType(b, hdr.Capsulerecipients_KeyServerCapsule)
                    hdr.RecipientRecordAddCapsule(b, capOff)
                    hdr.RecipientRecordAddKeyLabel(b, keyLabel)
                    hdr.RecipientRecordAddEncryptedFmk(b, encF)
                    hdr.RecipientRecordAddFmkEncryptionMethod(b, hdr.FMKEncryptionMethodXOR)
                    rrOffset = hdr.RecipientRecordEnd(b)
                } else {
                    // Regular RSA capsule (no key server)
                    // Build RSA capsule
                    rp := rcpt.RSAPublicKeyCapsuleAddRecipientPublicKey
                    re := rcpt.RSAPublicKeyCapsuleAddEncryptedKek
                    rc := rcpt.RSAPublicKeyCapsuleStart
                    rv := rcpt.RSAPublicKeyCapsuleEnd

                    pkVec := b.CreateByteVector(r.Certificate.RawSubjectPublicKeyInfo)
                    encVec := b.CreateByteVector(enc)
                    rc(b)
                    rp(b, pkVec)
                    re(b, encVec)
                    capOff := rv(b)

                    // Build RecipientRecord
                    keyLabel := b.CreateString(r.Label)
                    encF := b.CreateByteVector(xor)
                    hdr.RecipientRecordStart(b)
                    hdr.RecipientRecordAddCapsuleType(b, hdr.Capsulerecipients_RSAPublicKeyCapsule)
                    hdr.RecipientRecordAddCapsule(b, capOff)
                    hdr.RecipientRecordAddKeyLabel(b, keyLabel)
                    hdr.RecipientRecordAddEncryptedFmk(b, encF)
                    hdr.RecipientRecordAddFmkEncryptionMethod(b, hdr.FMKEncryptionMethodXOR)
                    rrOffset = hdr.RecipientRecordEnd(b)
                }

            case *ecdsa.PublicKey:
                // Generate ephemeral key
                eph, err := crypto.GenerateECKeyPair(pub)
                if err != nil {
                    return nil, err
                }
                // Shared secret
                shared, err := crypto.ECDHKeyAgreement(eph, pub)
                if err != nil {
                    return nil, err
                }
                // kekPm and kek via SHA-512 HKDF
                kekPm := crypto.HKDFExtractSHA512([]byte(KEKPREMASTER), shared)
                // Recipient and sender key materials (DER SubjectPublicKeyInfo)
                rcptDER := r.Certificate.RawSubjectPublicKeyInfo
                senderDER, err := x509.MarshalPKIXPublicKey(&eph.PublicKey)
                if err != nil {
                    return nil, internal.NewEncryptionError("failed to marshal ephemeral public key", err)
                }
                info := []byte(GetSaltForExpandWithKeyMaterial(rcptDER, senderDER))
                kek, err := crypto.HKDFExpandSHA512(kekPm, info, KeyLen)
                if err != nil {
                    return nil, err
                }
                xor = XOREncrypt(w.fmk, kek)

                // Check if this is a key server recipient
                if r.ServerID != "" && w.keyServerClient != nil {
                    config, ok := w.keyServerConfigs[r.ServerID]
                    if !ok {
                        return nil, internal.NewEncryptionError(fmt.Sprintf("key server config not found for server ID: %s", r.ServerID), nil)
                    }
                    
                    // For ECC key server, the key material is senderDER (ephemeral public key)
                    // Extract recipient public key in TLS 1.3 format for the key details
                    // For ECC, we need to extract in TLS 1.3 format (0x04 + X + Y)
                    var recipientPubKeyTLS13 []byte
                    if ecdsaPub, ok := r.Certificate.PublicKey.(*ecdsa.PublicKey); ok {
                        if ecdsaPub.Curve.Params().BitSize != 384 {
                            return nil, internal.NewEncryptionError("unsupported curve bit size (only secp384r1 supported)", nil)
                        }
                        keySize := 48 // secp384r1 coordinate size
                        recipientPubKeyTLS13 = make([]byte, 1+keySize*2)
                        recipientPubKeyTLS13[0] = 0x04 // Uncompressed point format
                        xBytes := ecdsaPub.X.Bytes()
                        yBytes := ecdsaPub.Y.Bytes()
                        copy(recipientPubKeyTLS13[1+keySize-len(xBytes):1+keySize], xBytes)
                        copy(recipientPubKeyTLS13[1+keySize*2-len(yBytes):1+keySize*2], yBytes)
                    } else {
                        return nil, internal.NewEncryptionError("certificate public key is not ECC", nil)
                    }
                    
                    // Send key material (senderDER = ephemeral public key) to key server
                    capsuleInfo, err := w.keyServerClient.SendKey(config, recipientPubKeyTLS13, senderDER, "ecc_secp384r1", r.ExpiryTime)
                    if err != nil {
                        return nil, internal.NewEncryptionError("failed to send key to key server", err)
                    }
                    
                    // Build KeyServerCapsule with EccKeyDetails
                    capOff := w.buildECCKeyServerCapsule(b, recipientPubKeyTLS13, config.ServerID, capsuleInfo.TransactionID)
                    
                    // Build RecipientRecord with KeyServerCapsule
                    keyLabel := b.CreateString(r.Label)
                    encF := b.CreateByteVector(xor)
                    hdr.RecipientRecordStart(b)
                    hdr.RecipientRecordAddCapsuleType(b, hdr.Capsulerecipients_KeyServerCapsule)
                    hdr.RecipientRecordAddCapsule(b, capOff)
                    hdr.RecipientRecordAddKeyLabel(b, keyLabel)
                    hdr.RecipientRecordAddEncryptedFmk(b, encF)
                    hdr.RecipientRecordAddFmkEncryptionMethod(b, hdr.FMKEncryptionMethodXOR)
                    rrOffset = hdr.RecipientRecordEnd(b)
                } else {
                    // Regular ECC capsule (no key server)
                    // Build ECC capsule
                    // Create byte vectors BEFORE starting the capsule
                    rcptVec := b.CreateByteVector(rcptDER)
                    senderVec := b.CreateByteVector(senderDER)
                    
                    rc := rcpt.ECCPublicKeyCapsuleStart
                    rv := rcpt.ECCPublicKeyCapsuleEnd
                    rc(b)
                    rcpt.ECCPublicKeyCapsuleAddCurve(b, rcpt.EllipticCurvesecp384r1)
                    rcpt.ECCPublicKeyCapsuleAddRecipientPublicKey(b, rcptVec)
                    rcpt.ECCPublicKeyCapsuleAddSenderPublicKey(b, senderVec)
                    capOff := rv(b)

                    keyLabel := b.CreateString(r.Label)
                    encF := b.CreateByteVector(xor)
                    hdr.RecipientRecordStart(b)
                    hdr.RecipientRecordAddCapsuleType(b, hdr.Capsulerecipients_ECCPublicKeyCapsule)
                    hdr.RecipientRecordAddCapsule(b, capOff)
                    hdr.RecipientRecordAddKeyLabel(b, keyLabel)
                    hdr.RecipientRecordAddEncryptedFmk(b, encF)
                    hdr.RecipientRecordAddFmkEncryptionMethod(b, hdr.FMKEncryptionMethodXOR)
                    rrOffset = hdr.RecipientRecordEnd(b)
                }

            default:
                return nil, internal.NewEncryptionError("unsupported certificate key type", nil)
            }
        } else if len(r.SymmetricKey) > 0 || r.KDFIterations > 0 || r.Password != "" {
            // Symmetric/Password
            // Generate salt
            salt := make([]byte, KeyLen)
            if _, err := rand.Read(salt); err != nil {
                return nil, internal.NewEncryptionError("failed to generate salt", err)
            }
            if r.KDFIterations > 0 || r.Password != "" {
                // PBKDF2 path
                pwSalt := make([]byte, KeyLen)
                if _, err := rand.Read(pwSalt); err != nil {
                    return nil, internal.NewEncryptionError("failed to generate password salt", err)
                }
                // Derive kekPm via PBKDF2(password, pwSalt, iter)
                // We don't know password here at write time; for envelope, we need to produce data compatible with read.
                // In writer API, accept Password: if empty, error.
                if r.Password == "" || r.KDFIterations <= 0 {
                    return nil, internal.NewEncryptionError("password and iterations required for PBKDF2 recipient", nil)
                }
                // Derive kek via HKDF with label
                kekPm := xpbkdf2.Key([]byte(r.Password), pwSalt, int(r.KDFIterations), KeyLen, sha256.New)
                kekPm2 := crypto.HKDFExtract(salt, kekPm)
                info := []byte(GetSaltForExpand(r.Label))
                kek, err := crypto.HKDFExpand(kekPm2, info, KeyLen)
                if err != nil {
                    return nil, err
                }
                xor = XOREncrypt(w.fmk, kek)

                // Create byte vectors first
                saltVec := b.CreateByteVector(salt)
                pwSaltVec := b.CreateByteVector(pwSalt)
                
                // Build PBKDF2 capsule
                rcpt.PBKDF2CapsuleStart(b)
                rcpt.PBKDF2CapsuleAddSalt(b, saltVec)
                rcpt.PBKDF2CapsuleAddPasswordSalt(b, pwSaltVec)
                rcpt.PBKDF2CapsuleAddKdfAlgorithmIdentifier(b, rcpt.KDFAlgorithmIdentifierPBKDF2WithHmacSHA256)
                rcpt.PBKDF2CapsuleAddKdfIterations(b, r.KDFIterations)
                capOff := rcpt.PBKDF2CapsuleEnd(b)

                keyLabel := b.CreateString(r.Label)
                encF := b.CreateByteVector(xor)
                hdr.RecipientRecordStart(b)
                hdr.RecipientRecordAddCapsuleType(b, hdr.Capsulerecipients_PBKDF2Capsule)
                hdr.RecipientRecordAddCapsule(b, capOff)
                hdr.RecipientRecordAddKeyLabel(b, keyLabel)
                hdr.RecipientRecordAddEncryptedFmk(b, encF)
                hdr.RecipientRecordAddFmkEncryptionMethod(b, hdr.FMKEncryptionMethodXOR)
                rrOffset = hdr.RecipientRecordEnd(b)
            } else {
                // Symmetric shared key supplied
                if len(r.SymmetricKey) == 0 {
                    return nil, internal.NewEncryptionError("symmetric key missing", nil)
                }
                kekPm := crypto.HKDFExtract(salt, r.SymmetricKey)
                info := []byte(GetSaltForExpand(r.Label))
                kek, err := crypto.HKDFExpand(kekPm, info, KeyLen)
                if err != nil {
                    return nil, err
                }
                xor = XOREncrypt(w.fmk, kek)

                // Create byte vector first
                saltVec := b.CreateByteVector(salt)
                
                rcpt.SymmetricKeyCapsuleStart(b)
                rcpt.SymmetricKeyCapsuleAddSalt(b, saltVec)
                capOff := rcpt.SymmetricKeyCapsuleEnd(b)

                keyLabel := b.CreateString(r.Label)
                encF := b.CreateByteVector(xor)
                hdr.RecipientRecordStart(b)
                hdr.RecipientRecordAddCapsuleType(b, hdr.Capsulerecipients_SymmetricKeyCapsule)
                hdr.RecipientRecordAddCapsule(b, capOff)
                hdr.RecipientRecordAddKeyLabel(b, keyLabel)
                hdr.RecipientRecordAddEncryptedFmk(b, encF)
                hdr.RecipientRecordAddFmkEncryptionMethod(b, hdr.FMKEncryptionMethodXOR)
                rrOffset = hdr.RecipientRecordEnd(b)
            }
        } else {
            return nil, internal.NewEncryptionError("unsupported recipient configuration", nil)
        }

        recOffsets = append(recOffsets, rrOffset)
    }

    // Build vector of recipients
    hdr.HeaderStartRecipientsVector(b, len(recOffsets))
    for i := len(recOffsets) - 1; i >= 0; i-- {
        b.PrependUOffsetT(recOffsets[i])
    }
    recipientsVec := b.EndVector(len(recOffsets))

    // Build header
    hdr.HeaderStart(b)
    hdr.HeaderAddRecipients(b, recipientsVec)
    hdr.HeaderAddPayloadEncryptionMethod(b, hdr.PayloadEncryptionMethodCHACHA20POLY1305)
    headerOff := hdr.HeaderEnd(b)
    b.Finish(headerOff)

    return b.FinishedBytes(), nil
}

// FinishEncryption finalizes the encryption and cleans up
// This should be called after all files have been added
func (w *Writer) FinishEncryption() error {
	// Files should be written via WriteEncryptedData before calling this
	// This method just cleans up
	
	// Clear FMK from memory
	if w.fmk != nil {
		for i := range w.fmk {
			w.fmk[i] = 0
		}
		w.fmk = nil
	}

	// Clear header data
	w.headerData = nil

	return nil
}

