package authtoken

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
)

// VerificationError indicates auth-token validation failure.
type VerificationError struct {
	Msg string
}

func (e *VerificationError) Error() string { return e.Msg }

func verifyError(msg string) error {
	return &VerificationError{Msg: msg}
}

// VerifiedClaims holds disclosed auth-token claims.
type VerifiedClaims struct {
	Issuer string
	Aud    []string
}

// VerifyTicket validates the signature and claims for a specific share access URL.
// The caller must independently validate certificate trust, validity and revocation.
func VerifyTicket(token string, certDER []byte, expectedURL string) (*VerifiedClaims, error) {
	if token == "" {
		return nil, verifyError("missing auth token")
	}
	if len(certDER) == 0 {
		return nil, verifyError("missing auth certificate")
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, verifyError("invalid auth certificate")
	}

	parts := strings.Split(token, "~")
	if len(parts) < 2 {
		return nil, verifyError("invalid sd-jwt format")
	}
	jwtPart := parts[0]
	disclosures := parts[1:]
	for len(disclosures) > 0 && disclosures[len(disclosures)-1] == "" {
		disclosures = disclosures[:len(disclosures)-1]
	}
	jwtSegments := strings.Split(jwtPart, ".")
	if len(jwtSegments) != 3 {
		return nil, verifyError("invalid jwt structure")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(jwtSegments[0])
	if err != nil {
		return nil, verifyError("invalid jwt header encoding")
	}
	var header map[string]string
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, verifyError("invalid jwt header json")
	}
	if header["typ"] != authTokenTyp {
		return nil, verifyError("unsupported jwt typ")
	}
	alg := header["alg"]
	if alg != "RS256" && alg != "ES256" {
		return nil, verifyError("unsupported jwt alg")
	}

	signingInput := jwtSegments[0] + "." + jwtSegments[1]
	sig, err := base64.RawURLEncoding.DecodeString(jwtSegments[2])
	if err != nil {
		return nil, verifyError("invalid jwt signature encoding")
	}
	if err := verifyJWSSignature(cert, alg, []byte(signingInput), sig); err != nil {
		return nil, err
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(jwtSegments[1])
	if err != nil {
		return nil, verifyError("invalid jwt payload encoding")
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, verifyError("invalid jwt payload json")
	}
	iss, _ := payload["iss"].(string)
	if iss == "" {
		return nil, verifyError("missing iss claim")
	}
	if err := issuerMatchesCertificate(iss, cert); err != nil {
		return nil, err
	}

	decoded, err := decodeDisclosures(payload, disclosures)
	if err != nil {
		return nil, err
	}
	audValues, err := audienceValues(decoded)
	if err != nil {
		return nil, err
	}
	if !containsAudience(audValues, expectedURL) {
		return nil, verifyError("audience mismatch")
	}
	return &VerifiedClaims{Issuer: iss, Aud: audValues}, nil
}

func verifyJWSSignature(cert *x509.Certificate, alg string, signingInput, sig []byte) error {
	switch alg {
	case "RS256":
		pub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return verifyError("certificate is not RSA")
		}
		hash := sha256.Sum256(signingInput)
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash[:], sig); err != nil {
			return verifyError("jwt signature verification failed")
		}
	case "ES256":
		pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return verifyError("certificate is not EC")
		}
		hash := sha256.Sum256(signingInput)
		if pub.Curve != elliptic.P256() || len(sig) != 64 || !ecdsa.Verify(pub, hash[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
			return verifyError("jwt signature verification failed")
		}
	default:
		return verifyError("unsupported jwt alg")
	}
	return nil
}

func issuerMatchesCertificate(iss string, cert *x509.Certificate) error {
	const prefix = "etsi/"
	if !strings.HasPrefix(iss, prefix) {
		return verifyError("iss must use etsi/ prefix")
	}
	want := strings.TrimPrefix(iss, prefix)
	subjectID := cert.Subject.SerialNumber
	if subjectID == "" || subjectID != want {
		return verifyError("iss does not match certificate subject")
	}
	return nil
}

func decodeDisclosures(payload map[string]any, disclosures []string) (map[string]any, error) {
	current := payload
	parsed := make([][]any, 0, len(disclosures))
	for _, enc := range disclosures {
		if enc == "" {
			continue
		}
		raw, err := base64.RawURLEncoding.DecodeString(enc)
		if err != nil {
			return nil, verifyError("invalid disclosure encoding")
		}
		var arr []any
		if err := json.Unmarshal(raw, &arr); err != nil {
			return nil, verifyError("invalid disclosure json")
		}
		parsed = append(parsed, arr)
	}
	// First pass: resolve top-level _sd digest (aud array).
	if sdVals, ok := current["_sd"].([]any); ok && len(sdVals) > 0 {
		if digest, ok := sdVals[0].(string); ok {
			for _, d := range parsed {
				if disclosureDigest(d) == digest {
					if len(d) >= 3 && d[1] == "aud" {
						current["aud"] = d[2]
						delete(current, "_sd")
						delete(current, "_sd_alg")
					}
				}
			}
		}
	}
	// Second pass: resolve individual audience URL digests.
	if audAny, ok := current["aud"].([]any); ok {
		resolved := make([]string, 0, len(audAny))
		for _, item := range audAny {
			ref, ok := item.(map[string]any)
			if !ok {
				continue
			}
			digest, _ := ref["..."].(string)
			for _, d := range parsed {
				if len(d) >= 2 && disclosureDigest(d) == digest {
					if url, ok := d[1].(string); ok {
						resolved = append(resolved, url)
					}
				}
			}
		}
		current["aud"] = resolved
	}
	return current, nil
}

func disclosureDigest(parts []any) string {
	raw, err := json.Marshal(parts)
	if err != nil {
		return ""
	}
	enc := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(enc))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func audienceValues(claims map[string]any) ([]string, error) {
	audAny, ok := claims["aud"]
	if !ok {
		return nil, verifyError("missing aud claim")
	}
	switch v := audAny.(type) {
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			s, ok := item.(string)
			if !ok {
				return nil, verifyError("invalid aud entry")
			}
			out = append(out, s)
		}
		return out, nil
	case []string:
		return v, nil
	default:
		return nil, verifyError("invalid aud claim")
	}
}

func containsAudience(aud []string, expected string) bool {
	for _, a := range aud {
		if a == expected {
			return true
		}
	}
	return false
}
