package rpserver

// Session states per OpenAPI 0.9.3-draft.
const (
	StateRunning  = "RUNNING"
	StateComplete = "COMPLETE"
)

// SID end results.
const (
	SidEndResultOK = "OK"
)

// MID session results.
const (
	MidResultOK = "OK"
)

// DefaultSidInteractionsBase64 is the OpenAPI example interactions payload.
const DefaultSidInteractionsBase64 = "W3sidHlwZSI6ImNvbmZpcm1hdGlvbk1lc3NhZ2UiLCJkaXNwbGF5VGV4dDIwMCI6IkRlY3J5cHRpbmcgY29udGFpbmVyIGZpbGUgXCJ0ZXN0LnR4dFwiIn0seyJ0eXBlIjoiZGlzcGxheVRleHRBbmRQSU4iLCJkaXNwbGF5VGV4dDYwIjoiRGVjcnlwdGluZyBjb250YWluZXIgZmlsZSBcInRlc3QudHh0XCIifV0="

// SidAuthenticateRequest is POST /sid/authenticate body per OpenAPI 0.9.3-draft.
type SidAuthenticateRequest struct {
	SemanticsIdentifier         string                          `json:"semanticsIdentifier"`
	CertificateLevel            string                          `json:"certificateLevel,omitempty"`
	SignatureProtocol           string                          `json:"signatureProtocol"`
	SignatureProtocolParameters AuthSignatureProtocolParameters `json:"signatureProtocolParameters"`
	Interactions                string                          `json:"interactions"`
	RequestProperties           *RequestProperties              `json:"requestProperties,omitempty"`
	Capabilities                []string                        `json:"capabilities,omitempty"`
	VcType                      string                          `json:"vcType"`
}

// AuthSignatureProtocolParameters holds ACSP_V2 request parameters.
type AuthSignatureProtocolParameters struct {
	RpChallenge                  string                                 `json:"rpChallenge"`
	SignatureAlgorithm           string                                 `json:"signatureAlgorithm"`
	SignatureAlgorithmParameters *SignatureAlgorithmParametersInRequest `json:"signatureAlgorithmParameters,omitempty"`
}

// SignatureAlgorithmParametersInRequest is rsassa-pss hash algorithm in request.
type SignatureAlgorithmParametersInRequest struct {
	HashAlgorithm string `json:"hashAlgorithm"`
}

// RequestProperties holds optional RP request properties.
type RequestProperties struct {
	ShareMdClientIpAddress bool `json:"shareMdClientIpAddress,omitempty"`
}

// MidAuthenticateRequest is POST /mid/authenticate body per OpenAPI 0.9.3-draft.
type MidAuthenticateRequest struct {
	PhoneNumber            string `json:"phoneNumber"`
	NationalIdentityNumber string `json:"nationalIdentityNumber"`
	Hash                   string `json:"hash"`
	HashType               string `json:"hashType"`
	Language               string `json:"language"`
	DisplayText            string `json:"displayText"`
	DisplayTextFormat      string `json:"displayTextFormat"`
}

// SessionIDResponse is returned when creating an RP session.
type SessionIDResponse struct {
	SessionID string `json:"sessionID"`
}

// SidSessionStatus is GET /sid/session/{sessionID} response body.
type SidSessionStatus struct {
	State               string            `json:"state"`
	Result              *SidSessionResult `json:"result,omitempty"`
	SignatureProtocol   string            `json:"signatureProtocol,omitempty"`
	Signature           *AcspV2Signature  `json:"signature,omitempty"`
	Cert                *SidCertificate   `json:"cert,omitempty"`
	InteractionTypeUsed string            `json:"interactionTypeUsed,omitempty"`
}

// SidSessionResult holds SID terminal result metadata.
type SidSessionResult struct {
	EndResult      string `json:"endResult"`
	DocumentNumber string `json:"documentNumber,omitempty"`
}

// AcspV2Signature is Smart-ID ACSP_V2 signature output.
type AcspV2Signature struct {
	Value                        string         `json:"value"`
	ServerRandom                 string         `json:"serverRandom"`
	UserChallenge                string         `json:"userChallenge"`
	FlowType                     string         `json:"flowType"`
	SignatureAlgorithm           string         `json:"signatureAlgorithm"`
	SignatureAlgorithmParameters map[string]any `json:"signatureAlgorithmParameters,omitempty"`
}

// SidCertificate is DER+Base64 certificate with level metadata.
type SidCertificate struct {
	Value            string `json:"value"`
	CertificateLevel string `json:"certificateLevel"`
}

// MidSessionStatus is GET /mid/session/{sessionID} response body.
type MidSessionStatus struct {
	State     string        `json:"state"`
	Result    string        `json:"result,omitempty"`
	Signature *MidSignature `json:"signature,omitempty"`
	Cert      string        `json:"cert,omitempty"`
	Time      string        `json:"time,omitempty"`
	TraceID   string        `json:"traceId,omitempty"`
	Proof     RFC9421Proof  `json:"-"`
}

// MidSignature holds Mobile-ID signature output.
type MidSignature struct {
	Value     string `json:"value"`
	Algorithm string `json:"algorithm"`
}

// RFC9421Proof holds MID session response RFC 9421 countersignature headers.
type RFC9421Proof struct {
	RpSignedHash   string
	RpName         string
	SignatureInput string
	Signature      string
}
