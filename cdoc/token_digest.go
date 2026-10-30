package cdoc

import (
	"crypto/ecdsa"
	"github.com/aarepuusepp/libcdoc-go/v2/crypto"
	"github.com/aarepuusepp/libcdoc-go/v2/internal"
)

// DigestToken extends Token without breaking existing token implementations.
type DigestToken interface {
	Token
	DecryptECWithDigest(*ecdsa.PublicKey, []byte, []byte, []byte, []byte, string) ([]byte, error)
}

func decryptECWithDigest(token Token, pub *ecdsa.PublicKey, algorithm, partyU, partyV, wrapped []byte, digest string) ([]byte, error) {
	if t, ok := token.(DigestToken); ok {
		return t.DecryptECWithDigest(pub, algorithm, partyU, partyV, wrapped, digest)
	}
	if digest != "" && digest != crypto.DigestSHA384URI {
		return nil, internal.NewDecryptionError("token does not support requested digest", nil)
	}
	return token.DecryptEC(pub, algorithm, partyU, partyV, wrapped)
}
