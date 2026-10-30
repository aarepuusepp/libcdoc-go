package authtoken

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

const (
	authTokenTyp = "vnd.cdoc2.auth-token.v1+sd-jwt"
	sdAlg        = "sha-256"
	keySharesEP  = "/key-shares"
)

// ShareAccess describes one share server nonce entry in the auth token aud claim.
type ShareAccess struct {
	ServerBaseURL string
	ShareID       string
	Nonce         string
}

// AccessURL returns the aud claim URL for a share access entry.
func (s ShareAccess) AccessURL() string {
	base := strings.TrimRight(s.ServerBaseURL, "/")
	return fmt.Sprintf("%s%s/%s?nonce=%s", base, keySharesEP, s.ShareID, s.Nonce)
}

type encodedDisclosure struct {
	raw    string
	digest string
}

func generateSalt() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func encodeDisclosure(parts ...any) (encodedDisclosure, error) {
	raw, err := json.Marshal(parts)
	if err != nil {
		return encodedDisclosure{}, err
	}
	enc := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(enc))
	return encodedDisclosure{
		raw:    enc,
		digest: base64.RawURLEncoding.EncodeToString(sum[:]),
	}, nil
}

func buildDisclosures(shares []ShareAccess) (aud encodedDisclosure, perShare []encodedDisclosure, err error) {
	perShare = make([]encodedDisclosure, 0, len(shares))
	refs := make([]map[string]string, 0, len(shares))
	for _, sh := range shares {
		d, err := encodeDisclosure(generateSaltMust(), sh.AccessURL())
		if err != nil {
			return encodedDisclosure{}, nil, err
		}
		perShare = append(perShare, d)
		refs = append(refs, map[string]string{"...": d.digest})
	}
	aud, err = encodeDisclosure(generateSaltMust(), "aud", refs)
	return aud, perShare, err
}

func generateSaltMust() string {
	s, err := generateSalt()
	if err != nil {
		panic(err)
	}
	return s
}

func payloadJSON(issuer, audDigest string) ([]byte, error) {
	payload := map[string]any{
		"iss":     issuer,
		"_sd":     []string{audDigest},
		"_sd_alg": sdAlg,
	}
	return json.Marshal(payload)
}

func headerJSON(alg string) ([]byte, error) {
	header := map[string]string{
		"typ": authTokenTyp,
		"alg": alg,
	}
	return json.Marshal(header)
}

func b64url(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}
