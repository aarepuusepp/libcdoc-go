package cdoc2

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2/keyshares"
	hdr "github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2/schema/cdoc20/header"
	rcpt "github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2/schema/cdoc20/recipients"
	"github.com/aarepuusepp/libcdoc-go/v2/crypto"
	"github.com/aarepuusepp/libcdoc-go/v2/internal"
	flatbuffers "github.com/google/flatbuffers/go"
)

func (w *Writer) buildAuthMeansRecipientRecord(b *flatbuffers.Builder, r Recipient) (flatbuffers.UOffsetT, error) {
	if len(w.sharesClients) < w.sharesMinRequired {
		return 0, internal.NewEncryptionError("insufficient key-shares servers configured", nil)
	}
	if w.sharesMinRequired < 2 || w.sharesMinRequired != len(w.sharesClients) {
		return 0, internal.NewEncryptionError("N-of-N requires minRequired to equal configured server count (minimum 2)", nil)
	}

	salt := make([]byte, KeyLen)
	if _, err := rand.Read(salt); err != nil {
		return 0, internal.NewEncryptionError("failed to generate salt", err)
	}

	inputKeyingMaterial := make([]byte, KeyLen)
	if _, err := rand.Read(inputKeyingMaterial); err != nil {
		return 0, internal.NewEncryptionError("failed to generate IKM", err)
	}
	kekPm := crypto.HKDFExtract(salt, inputKeyingMaterial)

	plainID := r.AuthMeansID
	info := []byte(fmt.Sprintf("CDOC2kekXOR%s", plainID))
	kek, err := crypto.HKDFExpand(kekPm, info, KeyLen)
	if err != nil {
		return 0, err
	}
	xor := XOREncrypt(w.fmk, kek)

	shares, err := SplitKEK(kek, len(w.sharesClients))
	if err != nil {
		return 0, internal.NewEncryptionError("failed to split KEK", err)
	}

	shareOffsets := make([]flatbuffers.UOffsetT, 0, len(w.sharesClients))
	for i, client := range w.sharesClients {
		ks := keyshares.KeyShare{
			Share:     base64.StdEncoding.EncodeToString(shares[i]),
			Recipient: plainID,
		}
		shareID, err := client.CreateKeyShare(context.Background(), ks, nil)
		if err != nil {
			return 0, err
		}
		baseURL := client.BaseURL()
		urlOff := b.CreateString(baseURL)
		idOff := b.CreateString(shareID)
		rcpt.KeyShareStart(b)
		rcpt.KeyShareAddServerBaseUrl(b, urlOff)
		rcpt.KeyShareAddShareId(b, idOff)
		shareOffsets = append(shareOffsets, rcpt.KeyShareEnd(b))
	}

	sharesVec := b.CreateVectorOfTables(shareOffsets)
	saltVec := b.CreateByteVector(salt)
	recipientIDOff := b.CreateString(plainID)

	rcpt.KeySharesCapsuleStart(b)
	rcpt.KeySharesCapsuleAddShares(b, sharesVec)
	rcpt.KeySharesCapsuleAddSalt(b, saltVec)
	rcpt.KeySharesCapsuleAddRecipientType(b, rcpt.KeyShareRecipientTypeSID_MID)
	rcpt.KeySharesCapsuleAddSharesScheme(b, rcpt.SharesSchemeN_OF_N)
	rcpt.KeySharesCapsuleAddRecipientId(b, recipientIDOff)
	capOff := rcpt.KeySharesCapsuleEnd(b)

	label := r.Label
	if label == "" {
		label = plainID
	}
	keyLabel := b.CreateString(label)
	encF := b.CreateByteVector(xor)
	hdr.RecipientRecordStart(b)
	hdr.RecipientRecordAddCapsuleType(b, hdr.Capsulerecipients_KeySharesCapsule)
	hdr.RecipientRecordAddCapsule(b, capOff)
	hdr.RecipientRecordAddKeyLabel(b, keyLabel)
	hdr.RecipientRecordAddEncryptedFmk(b, encF)
	hdr.RecipientRecordAddFmkEncryptionMethod(b, hdr.FMKEncryptionMethodXOR)
	return hdr.RecipientRecordEnd(b), nil
}

// DeriveKEKFromKeyShares combines downloaded shares into the KEK (n-of-n XOR scheme).
func DeriveKEKFromKeyShares(_ []byte, _ string, shareBytes [][]byte, minRequired int) ([]byte, error) {
	return CombineKEK(shareBytes, minRequired)
}
