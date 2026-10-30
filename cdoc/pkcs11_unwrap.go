package cdoc

import (
	"crypto/ecdsa"
	"crypto/x509"

	c2 "github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2"
	"github.com/aarepuusepp/libcdoc-go/v2/crypto"
	"github.com/aarepuusepp/libcdoc-go/v2/internal"
	"github.com/aarepuusepp/libcdoc-go/v2/key"
)

// UnwrapTransportKeyWithPKCS11 unwraps the CDOC transport key using a PKCS#11 token.
func UnwrapTransportKeyWithPKCS11(cfg key.PKCS11Config, challenge ClientUnwrapChallenge) ([]byte, error) {
	recipientCert, err := challenge.RecipientCertificate()
	if err != nil {
		return nil, err
	}
	cfg.RecipientCert = recipientCert

	token, err := NewPKCS11Token(cfg)
	if err != nil {
		return nil, err
	}
	defer func() { _ = token.Close() }()

	return UnwrapTransportKeyWithToken(token, challenge)
}

// UnwrapTransportKeyWithToken unwraps using an existing Token implementation.
func UnwrapTransportKeyWithToken(token Token, challenge ClientUnwrapChallenge) ([]byte, error) {
	if token == nil {
		return nil, internal.NewDecryptionError("token is required", nil)
	}
	if challenge.CdocVersion != "1.0" && challenge.CdocVersion != "1.1" && challenge.CdocVersion != "2.0" {
		return nil, internal.NewDecryptionError("unsupported CDOC version", nil)
	}
	if challenge.CdocVersion == "2.0" {
		return unwrapCDOC2TransportKeyWithToken(token, challenge)
	}
	switch challenge.RecipientType {
	case "RSA":
		encryptedKey, err := challenge.ChallengeEncryptedKey()
		if err != nil {
			return nil, err
		}
		return token.DecryptRSA(encryptedKey)
	case "EC":
		recipientCert, err := challenge.RecipientCertificate()
		if err != nil {
			return nil, err
		}
		if _, ok := recipientCert.PublicKey.(*ecdsa.PublicKey); !ok {
			return nil, internal.NewDecryptionError("recipient certificate is not EC", nil)
		}
		point, err := challenge.ChallengeEphemeralPoint()
		if err != nil {
			return nil, err
		}
		ephemeralKey, err := DecodeEphemeralPublicKey(InferCurveFromCert(recipientCert), point)
		if err != nil {
			return nil, err
		}
		algorithmID, err := decodeOptionalB64(challenge.AlgorithmIDB64)
		if err != nil {
			return nil, internal.NewDecryptionError("invalid algorithmId", err)
		}
		partyUInfo, err := decodeOptionalB64(challenge.PartyUInfoB64)
		if err != nil {
			return nil, internal.NewDecryptionError("invalid partyUInfo", err)
		}
		partyVInfo, err := decodeOptionalB64(challenge.PartyVInfoB64)
		if err != nil {
			return nil, internal.NewDecryptionError("invalid partyVInfo", err)
		}
		wrappedKey, err := challenge.ChallengeWrappedKey()
		if err != nil {
			return nil, err
		}
		return decryptECWithDigest(token, ephemeralKey, algorithmID, partyUInfo, partyVInfo, wrappedKey, challenge.DigestAlgorithm)
	default:
		return nil, internal.NewDecryptionError("unsupported recipient type: "+challenge.RecipientType, nil)
	}
}

type ecSharedSecretToken interface {
	DecryptECSharedSecret(ephemeralPublicKey *ecdsa.PublicKey) ([]byte, error)
}

func unwrapCDOC2TransportKeyWithToken(token Token, challenge ClientUnwrapChallenge) ([]byte, error) {
	switch challenge.RecipientType {
	case "RSA":
		encryptedKey, err := challenge.ChallengeEncryptedKey()
		if err != nil {
			return nil, err
		}
		return token.DecryptRSA(encryptedKey)
	case "EC":
		senderDER, err := challenge.ChallengeEphemeralPoint()
		if err != nil {
			return nil, err
		}
		pubAny, err := x509.ParsePKIXPublicKey(senderDER)
		if err != nil {
			return nil, internal.NewDecryptionError("invalid ECC sender public key", err)
		}
		ecPub, ok := pubAny.(*ecdsa.PublicKey)
		if !ok {
			return nil, internal.NewDecryptionError("sender public key is not ECC", nil)
		}
		sharedSecretToken, ok := token.(ecSharedSecretToken)
		if !ok {
			return nil, internal.NewDecryptionError("token does not support CDOC2 ECC unwrap", nil)
		}
		sharedSecret, err := sharedSecretToken.DecryptECSharedSecret(ecPub)
		if err != nil {
			return nil, err
		}
		defer func() {
			for i := range sharedSecret {
				sharedSecret[i] = 0
			}
		}()
		recipientKey, err := decodeChallengeB64(challenge.RecipientKeyB64, "recipientKey")
		if err != nil {
			return nil, err
		}
		kekPm := crypto.HKDFExtractSHA512([]byte(c2.KEKPREMASTER), sharedSecret)
		defer clear(kekPm)
		info := []byte(c2.GetSaltForExpandWithKeyMaterial(recipientKey, senderDER))
		kek, err := crypto.HKDFExpandSHA512(kekPm, info, c2.KeyLen)
		if err != nil {
			return nil, internal.NewDecryptionError("failed to derive ECC KEK", err)
		}
		return kek, nil
	default:
		return nil, internal.NewDecryptionError("unsupported recipient type: "+challenge.RecipientType, nil)
	}
}
