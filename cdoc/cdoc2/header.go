package cdoc2

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	hdr "github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2/schema/cdoc20/header"
	rcpt "github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2/schema/cdoc20/recipients"
	flatbuffers "github.com/google/flatbuffers/go"

	"github.com/aarepuusepp/libcdoc-go/v2/internal"
)

// Header represents a parsed CDOC2 header
type Header struct {
	Recipients              []RecipientRecord
	PayloadEncryptionMethod PayloadEncryptionMethod
	HeaderData              []byte // Raw header bytes for HMAC verification
}

// RecipientRecord represents a recipient in the CDOC2 header
type RecipientRecord struct {
	Capsule             Capsule
	KeyLabel            string
	EncryptedFMK        []byte
	FMKEncryptionMethod FMKEncryptionMethod
}

// PayloadEncryptionMethod represents the encryption method for payload
type PayloadEncryptionMethod byte

const (
	PayloadEncryptionMethodUnknown PayloadEncryptionMethod = iota
	PayloadEncryptionMethodChaCha20Poly1305
)

// FMKEncryptionMethod represents the encryption method for FMK
type FMKEncryptionMethod byte

const (
	FMKEncryptionMethodUnknown FMKEncryptionMethod = iota
	FMKEncryptionMethodXOR
)

// Capsule represents different recipient capsule types
type Capsule interface {
	// Type returns the capsule type identifier
	Type() string
}

// ParseHeader parses a CDOC2 header from a reader
// It reads the magic label, header length, header data, and header HMAC
// Returns the parsed header and the header HMAC bytes
func ParseHeader(reader io.Reader) (*Header, []byte, error) {
	// Read magic label
	magic := make([]byte, len(Label))
	if _, err := io.ReadFull(reader, magic); err != nil {
		return nil, nil, internal.NewParseError("failed to read magic label", err)
	}
	if string(magic) != Label {
		return nil, nil, internal.NewParseError(
			fmt.Sprintf("invalid magic label, expected %q, got %q", Label, string(magic)),
			nil,
		)
	}

	// Read header length (4 bytes, big-endian)
	var headerLen uint32
	if err := binary.Read(reader, binary.BigEndian, &headerLen); err != nil {
		return nil, nil, internal.NewParseError("failed to read header length", err)
	}

	// Sanity check on header length (max 1MB)
	const maxHeaderLen = 1 << 20
	if headerLen > maxHeaderLen {
		return nil, nil, internal.NewParseError(
			fmt.Sprintf("header length too large: %d bytes (max %d)", headerLen, maxHeaderLen),
			nil,
		)
	}

	// Read header data
	headerData := make([]byte, headerLen)
	if _, err := io.ReadFull(reader, headerData); err != nil {
		return nil, nil, internal.NewParseError("failed to read header data", err)
	}

	// Read header HMAC (32 bytes)
	headerHMAC := make([]byte, KeyLen)
	if _, err := io.ReadFull(reader, headerHMAC); err != nil {
		return nil, nil, internal.NewParseError("failed to read header HMAC", err)
	}

	// Parse FlatBuffers header
	// NOTE: This requires the generated FlatBuffers code to be available
	// Run: flatc --go schema/recipients.fbs schema/header.fbs in cdoc/cdoc2/schema/
	header, err := parseFlatBuffersHeader(headerData)
	if err != nil {
		return nil, nil, err
	}

	header.HeaderData = headerData
	return header, headerHMAC, nil
}

// parseFlatBuffersHeader parses the FlatBuffers-encoded header data
func parseFlatBuffersHeader(data []byte) (*Header, error) {
	h := hdr.GetRootAsHeader(data, 0)
	pem := h.PayloadEncryptionMethod()
	var out Header
	out.PayloadEncryptionMethod = mapPayloadEncMethod(pem)
	out.HeaderData = data

	// Iterate recipients
	num := h.RecipientsLength()
	out.Recipients = make([]RecipientRecord, 0, num)
	var rec hdr.RecipientRecord
	for i := 0; i < num; i++ {
		if !h.Recipients(&rec, i) {
			continue
		}
		rr := RecipientRecord{}
		// KeyLabel
		rr.KeyLabel = string(rec.KeyLabel())
		// EncryptedFMK
		rr.EncryptedFMK = append([]byte(nil), rec.EncryptedFmkBytes()...)
		// FMK method
		rr.FMKEncryptionMethod = mapFMKEncMethod(rec.FmkEncryptionMethod())

		// Capsule
		var tab flatbuffers.Table
		if rec.Capsule(&tab) {
			switch rec.CapsuleType() {
			case hdr.Capsulerecipients_RSAPublicKeyCapsule:
				var c rcpt.RSAPublicKeyCapsule
				c.Init(tab.Bytes, tab.Pos)
				rr.Capsule = RSAPublicKeyCapsule{
					RecipientPublicKey: append([]byte(nil), c.RecipientPublicKeyBytes()...),
					EncryptedKEK:       append([]byte(nil), c.EncryptedKekBytes()...),
				}
			case hdr.Capsulerecipients_ECCPublicKeyCapsule:
				var c rcpt.ECCPublicKeyCapsule
				c.Init(tab.Bytes, tab.Pos)
				rr.Capsule = ECCPublicKeyCapsule{
					RecipientPublicKey: append([]byte(nil), c.RecipientPublicKeyBytes()...),
					SenderPublicKey:    append([]byte(nil), c.SenderPublicKeyBytes()...),
				}
			case hdr.Capsulerecipients_SymmetricKeyCapsule:
				var c rcpt.SymmetricKeyCapsule
				c.Init(tab.Bytes, tab.Pos)
				rr.Capsule = SymmetricKeyCapsule{Salt: append([]byte(nil), c.SaltBytes()...)}
			case hdr.Capsulerecipients_PBKDF2Capsule:
				var c rcpt.PBKDF2Capsule
				c.Init(tab.Bytes, tab.Pos)
				rr.Capsule = PBKDF2Capsule{
					Salt:         append([]byte(nil), c.SaltBytes()...),
					PasswordSalt: append([]byte(nil), c.PasswordSaltBytes()...),
					Iterations:   c.KdfIterations(),
				}
			case hdr.Capsulerecipients_KeyServerCapsule:
				var c rcpt.KeyServerCapsule
				c.Init(tab.Bytes, tab.Pos)
				// Determine key details type
				var kd flatbuffers.Table
				pkType := PKTypeUnknown
				var recipientKey []byte
				if c.RecipientKeyDetails(&kd) {
					switch c.RecipientKeyDetailsType() {
					case rcpt.KeyDetailsUnionRsaKeyDetails:
						var kdR rcpt.RsaKeyDetails
						kdR.Init(kd.Bytes, kd.Pos)
						recipientKey = append([]byte(nil), kdR.RecipientPublicKeyBytes()...)
						pkType = PKTypeRSA
					case rcpt.KeyDetailsUnionEccKeyDetails:
						var kdE rcpt.EccKeyDetails
						kdE.Init(kd.Bytes, kd.Pos)
						recipientKey = append([]byte(nil), kdE.RecipientPublicKeyBytes()...)
						pkType = PKTypeECC
					}
				}
				rr.Capsule = KeyServerCapsule{
					RecipientKey:  recipientKey,
					PKType:        pkType,
					KeyServerID:   string(c.KeyserverId()),
					TransactionID: string(c.TransactionId()),
				}
			case hdr.Capsulerecipients_KeySharesCapsule:
				var c rcpt.KeySharesCapsule
				c.Init(tab.Bytes, tab.Pos)
				// Collect shares (url,id pairs)
				shares := make([]KeyShare, 0, c.SharesLength())
				var s rcpt.KeyShare
				for j := 0; j < c.SharesLength(); j++ {
					if c.Shares(&s, j) {
						shares = append(shares, KeyShare{
							URL:           string(s.ServerBaseUrl()),
							TransactionID: string(s.ShareId()),
						})
					}
				}
				rr.Capsule = KeySharesCapsule{
					Shares:        shares,
					Salt:          append([]byte(nil), c.SaltBytes()...),
					RecipientType: byte(c.RecipientType()),
					Scheme:        byte(c.SharesScheme()),
					RecipientID:   string(c.RecipientId()),
				}
			}
		}

		out.Recipients = append(out.Recipients, rr)
	}

	return &out, nil
}

func mapPayloadEncMethod(v hdr.PayloadEncryptionMethod) PayloadEncryptionMethod {
	switch v {
	case hdr.PayloadEncryptionMethodCHACHA20POLY1305:
		return PayloadEncryptionMethodChaCha20Poly1305
	default:
		return PayloadEncryptionMethodUnknown
	}
}

func mapFMKEncMethod(v hdr.FMKEncryptionMethod) FMKEncryptionMethod {
	switch v {
	case hdr.FMKEncryptionMethodXOR:
		return FMKEncryptionMethodXOR
	default:
		return FMKEncryptionMethodUnknown
	}
}

// VerifyHeaderHMAC verifies the HMAC of the header using the provided HMAC key
func VerifyHeaderHMAC(header *Header, hmacKey, expectedHMAC []byte) error {
	if len(hmacKey) != KeyLen {
		return internal.NewDecryptionError(
			fmt.Sprintf("HMAC key must be %d bytes, got %d", KeyLen, len(hmacKey)),
			nil,
		)
	}
	if len(expectedHMAC) != KeyLen {
		return internal.NewDecryptionError(
			fmt.Sprintf("HMAC must be %d bytes, got %d", KeyLen, len(expectedHMAC)),
			nil,
		)
	}

	// Calculate HMAC-SHA256 of header data
	computedHMAC := computeHMACSHA256(header.HeaderData, hmacKey)

	// Constant-time comparison
	if !constantTimeCompare(computedHMAC, expectedHMAC) {
		return internal.NewDecryptionError("header HMAC verification failed", nil)
	}

	return nil
}

// computeHMACSHA256 computes HMAC-SHA256 of data with key
func computeHMACSHA256(data, key []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// constantTimeCompare performs constant-time byte slice comparison
func constantTimeCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var result byte
	for i := range a {
		result |= a[i] ^ b[i]
	}
	return result == 0
}
