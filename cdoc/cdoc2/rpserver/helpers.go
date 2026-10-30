package rpserver

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/aarepuusepp/libcdoc-go/v2/internal"
)

var midPhonePattern = regexp.MustCompile(`^\+[1-9]\d{6,14}$`)

// NewSidAuthenticateRequest builds an OpenAPI-compliant SID authenticate body.
// signedHashBase64 is reused as rpChallenge for deterministic mock/testing flows.
func NewSidAuthenticateRequest(semanticsIdentifier, signedHashBase64 string) SidAuthenticateRequest {
	rpChallenge := strings.TrimSpace(signedHashBase64)
	if len(rpChallenge) < 32 {
		rpChallenge = base64.StdEncoding.EncodeToString([]byte(rpChallenge))
	}
	return SidAuthenticateRequest{
		SemanticsIdentifier: semanticsIdentifier,
		CertificateLevel:    "QUALIFIED",
		SignatureProtocol:   "ACSP_V2",
		SignatureProtocolParameters: AuthSignatureProtocolParameters{
			RpChallenge:        rpChallenge,
			SignatureAlgorithm: "rsassa-pss",
			SignatureAlgorithmParameters: &SignatureAlgorithmParametersInRequest{
				HashAlgorithm: "SHA-512",
			},
		},
		Interactions: DefaultSidInteractionsBase64,
		VcType:       "numeric4",
	}
}

// NewMidAuthenticateRequest builds an OpenAPI-compliant MID authenticate body.
func NewMidAuthenticateRequest(phoneNumber, nationalIdentityNumber, signedHashBase64, language, displayText string) (MidAuthenticateRequest, error) {
	if err := ValidateMidPhoneNumber(phoneNumber); err != nil {
		return MidAuthenticateRequest{}, err
	}
	format := "GSM-7"
	if err := ValidateMidDisplayText(displayText, format); err != nil {
		return MidAuthenticateRequest{}, err
	}
	lang := strings.TrimSpace(language)
	if lang == "" {
		lang = "EST"
	}
	switch lang {
	case "EST", "ENG", "RUS", "LIT", "et", "en":
	default:
		return MidAuthenticateRequest{}, internal.NewDecryptionError("mid language must be EST, ENG, RUS, or LIT", nil)
	}
	if lang == "et" {
		lang = "EST"
	}
	if lang == "en" {
		lang = "ENG"
	}
	return MidAuthenticateRequest{
		PhoneNumber:            strings.TrimSpace(phoneNumber),
		NationalIdentityNumber: strings.TrimSpace(nationalIdentityNumber),
		Hash:                   strings.TrimSpace(signedHashBase64),
		HashType:               "SHA256",
		Language:               lang,
		DisplayText:            displayText,
		DisplayTextFormat:      format,
	}, nil
}

// ValidateMidPhoneNumber checks E.164-style phone numbers required by OpenAPI.
func ValidateMidPhoneNumber(phoneNumber string) error {
	phoneNumber = strings.TrimSpace(phoneNumber)
	if !midPhonePattern.MatchString(phoneNumber) {
		return internal.NewDecryptionError("mid phoneNumber must include country code prefix, e.g. +3726234566", nil)
	}
	return nil
}

// ValidateMidDisplayText enforces GSM-7 / UCS-2 length limits from OpenAPI.
func ValidateMidDisplayText(displayText, format string) error {
	switch format {
	case "", "GSM-7":
		if len(displayText) > 100 {
			return internal.NewDecryptionError("mid displayText exceeds GSM-7 limit of 100 bytes", nil)
		}
	case "UCS-2":
		if utf8.RuneCountInString(displayText) > 50 {
			return internal.NewDecryptionError("mid displayText exceeds UCS-2 limit of 50 characters", nil)
		}
	default:
		return internal.NewDecryptionError("mid displayTextFormat must be GSM-7 or UCS-2", nil)
	}
	return nil
}

// SignatureBytes decodes the primary signature value for auth-token construction.
func (s *SidSessionStatus) SignatureBytes() ([]byte, error) {
	if s == nil || s.Signature == nil || s.Signature.Value == "" {
		return nil, internal.NewDecryptionError("sid session missing ACSP_V2 signature", nil)
	}
	return base64.StdEncoding.DecodeString(s.Signature.Value)
}

// CertificateBytes decodes the SID authentication certificate DER bytes.
func (s *SidSessionStatus) CertificateBytes() ([]byte, error) {
	if s == nil || s.Cert == nil || s.Cert.Value == "" {
		return nil, internal.NewDecryptionError("sid session missing certificate", nil)
	}
	return base64.StdEncoding.DecodeString(s.Cert.Value)
}

// SidRPv3SignatureParameters returns serialized ACSP_V2 proof parameters for Shares GET.
func (s *SidSessionStatus) SidRPv3SignatureParameters() (string, error) {
	if s == nil || s.Signature == nil {
		return "", internal.NewDecryptionError("sid session missing signature proof", nil)
	}
	raw, err := json.Marshal(s.Signature)
	if err != nil {
		return "", internal.NewDecryptionError("failed to encode sid rpv3 signature parameters", err)
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// SignatureBytes decodes MID signature bytes.
func (s *MidSessionStatus) SignatureBytes() ([]byte, error) {
	if s == nil || s.Signature == nil || s.Signature.Value == "" {
		return nil, internal.NewDecryptionError("mid session missing signature", nil)
	}
	return base64.StdEncoding.DecodeString(s.Signature.Value)
}

// CertificateBytes decodes MID certificate DER bytes.
func (s *MidSessionStatus) CertificateBytes() ([]byte, error) {
	if s == nil || strings.TrimSpace(s.Cert) == "" {
		return nil, internal.NewDecryptionError("mid session missing certificate", nil)
	}
	return base64.StdEncoding.DecodeString(s.Cert)
}

func sidTerminalError(result string) error {
	if result == "" || result == SidEndResultOK {
		return nil
	}
	return internal.NewDecryptionError(fmt.Sprintf("sid session ended with result %s", result), nil)
}

func midTerminalError(result string) error {
	if result == "" || result == MidResultOK {
		return nil
	}
	return internal.NewDecryptionError(fmt.Sprintf("mid session ended with result %s", result), nil)
}
