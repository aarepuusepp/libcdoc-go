package authtoken

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// BuildSigningInput creates canonical bytes representing iss+aud for RP signing flows.
func BuildSigningInput(issuer string, shares []ShareAccess) ([]byte, error) {
	aud := make([]string, 0, len(shares))
	for _, s := range shares {
		aud = append(aud, s.AccessURL())
	}
	payload := map[string]any{
		"iss": issuer,
		"aud": aud,
	}
	return json.Marshal(payload)
}

// ErrExternalProofProfileUnsupported prevents treating an RP signature over a
// different message as a signature over a newly randomized SD-JWT.
var ErrExternalProofProfileUnsupported = errors.New("CDOC2 external auth proof profile is not verified; Smart-ID/Mobile-ID key-share recovery is unavailable")

// CreateFromSignature cannot safely reconstruct the originally signed SD-JWT
// from these arguments. Use Creator.JWSSigningInput and AttachSignature for a
// direct JWS signer; external ACSP/RFC9421 proofs require a verified adapter.
func CreateFromSignature(issuer string, shares []ShareAccess, signature, certDER []byte) (map[string]string, string, error) {
	return nil, "", ErrExternalProofProfileUnsupported
}

// DecodeCertDER accepts standard or URL-safe base64 certificate encoding.
func DecodeCertDER(cert string) ([]byte, error) {
	if cert == "" {
		return nil, fmt.Errorf("empty certificate")
	}
	if b, err := base64.RawURLEncoding.DecodeString(cert); err == nil {
		return b, nil
	}
	if b, err := base64.URLEncoding.DecodeString(cert); err == nil {
		return b, nil
	}
	return base64.StdEncoding.DecodeString(cert)
}
