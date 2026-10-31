package cdoc

import (
	"crypto/ecdsa"

	c2 "github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2"
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
		recipientKey, err := decodeOptionalB64(challenge.RecipientKeyB64)
		if err != nil {
			return nil, err
		}
		if len(recipientKey) == 0 || c2.IsLegacySPKI(recipientKey) {
			return token.DecryptRSA(encryptedKey)
		}
		oaep, ok := token.(interface{ DecryptRSAOAEP([]byte) ([]byte, error) })
		if !ok {
			return nil, internal.NewDecryptionError("token does not support RSA-OAEP-SHA256", nil)
		}
		return oaep.DecryptRSAOAEP(encryptedKey)
	case "EC":
		senderKey, err := challenge.ChallengeEphemeralPoint()
		if err != nil {
			return nil, err
		}
		ecPub, err := c2.DecodeECCPublicKey(senderKey)
		if err != nil {
			return nil, err
		}
		recipientKey, err := decodeChallengeB64(challenge.RecipientKeyB64, "recipientKey")
		if err != nil {
			return nil, err
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

		return c2.DeriveInlineECCKEK(sharedSecret, recipientKey, senderKey)

	default:
		return nil, internal.NewDecryptionError("unsupported recipient type: "+challenge.RecipientType, nil)
	}
}
