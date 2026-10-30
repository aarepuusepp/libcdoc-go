package authtoken

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"math/big"
)

// Creator builds selectively-disclosed CDOC2 auth-token SD-JWT tickets.
type Creator struct {
	issuer    string
	shares    []ShareAccess
	aud       encodedDisclosure
	perShare  []encodedDisclosure
	certDER   []byte
	algorithm string
	signedJWT string
}

// NewCreator prepares SD-JWT auth token material for the given issuer and share accesses.
func NewCreator(issuer string, shares []ShareAccess) (*Creator, error) {
	if issuer == "" {
		return nil, fmt.Errorf("issuer required")
	}
	if len(shares) == 0 {
		return nil, fmt.Errorf("at least one share access required")
	}
	aud, perShare, err := buildDisclosures(shares)
	if err != nil {
		return nil, err
	}
	return &Creator{
		issuer:   issuer,
		shares:   shares,
		aud:      aud,
		perShare: perShare,
	}, nil
}

// JWSSigningInput returns the bytes that must be signed for the auth-token JWT.
func (c *Creator) JWSSigningInput(alg string) ([]byte, error) {
	if c == nil {
		return nil, fmt.Errorf("creator not initialized")
	}
	header, err := headerJSON(alg)
	if err != nil {
		return nil, err
	}
	payload, err := payloadJSON(c.issuer, c.aud.digest)
	if err != nil {
		return nil, err
	}
	return []byte(b64url(header) + "." + b64url(payload)), nil
}

// AttachSignature accepts a JWS signature over this Creator's exact signing input.
// An RP proof must first be verified and converted by a supported proof adapter.
func (c *Creator) AttachSignature(signature []byte, certDER []byte, alg string) error {
	if len(signature) == 0 {
		return fmt.Errorf("signature required")
	}
	if len(certDER) == 0 {
		return fmt.Errorf("certificate required")
	}
	signingInput, err := c.JWSSigningInput(alg)
	if err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("invalid auth certificate: %w", err)
	}
	if err := issuerMatchesCertificate(c.issuer, cert); err != nil {
		return err
	}
	if err := verifyJWSSignature(cert, alg, signingInput, signature); err != nil {
		return err
	}
	c.signedJWT = string(signingInput) + "." + b64url(signature)
	c.certDER = certDER
	c.algorithm = alg
	return nil
}

// SignWithSigner signs the auth token locally (tests and HSM-backed signers).
func (c *Creator) SignWithSigner(signer crypto.Signer, certDER []byte) error {
	if signer == nil {
		return fmt.Errorf("signer required")
	}
	alg, err := jwsAlgorithmForSigner(signer)
	if err != nil {
		return err
	}
	signingInput, err := c.JWSSigningInput(alg)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(signingInput)
	sig, err := signer.Sign(rand.Reader, sum[:], hashForAlgorithm(alg))
	if err != nil {
		return err
	}
	if alg == "ES256" {
		var parsed struct{ R, S *big.Int }
		rest, err := asn1.Unmarshal(sig, &parsed)
		if err != nil || len(rest) != 0 || parsed.R == nil || parsed.S == nil || parsed.R.Sign() <= 0 || parsed.S.Sign() <= 0 || parsed.R.BitLen() > 256 || parsed.S.BitLen() > 256 {
			return fmt.Errorf("invalid ECDSA signer output")
		}
		sig = make([]byte, 64)
		parsed.R.FillBytes(sig[:32])
		parsed.S.FillBytes(sig[32:])
	}
	return c.AttachSignature(sig, certDER, alg)
}

// TicketForShareID returns the SD-JWT ticket disclosing only the requested share audience.
func (c *Creator) TicketForShareID(shareID string) (string, error) {
	if c.signedJWT == "" {
		return "", fmt.Errorf("auth token not signed")
	}
	for i, sh := range c.shares {
		if sh.ShareID == shareID {
			return c.ticketAt(i), nil
		}
	}
	return "", fmt.Errorf("share id not found in auth token")
}

func (c *Creator) ticketAt(index int) string {
	return c.signedJWT + "~" + c.aud.raw + "~" + c.perShare[index].raw + "~"
}

// CertBase64URL returns the authenticator certificate for x-cdoc2-auth-x5c.
func (c *Creator) CertBase64URL() string {
	if len(c.certDER) == 0 {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(c.certDER)
}

func jwsAlgorithmForSigner(signer crypto.Signer) (string, error) {
	switch public := signer.Public().(type) {
	case *rsa.PublicKey:
		return "RS256", nil
	case *ecdsa.PublicKey:
		if public.Curve != elliptic.P256() {
			return "", fmt.Errorf("ES256 requires P-256")
		}
		return "ES256", nil
	default:
		return "", fmt.Errorf("unsupported signer key type")
	}
}

func hashForAlgorithm(alg string) crypto.Hash {
	switch alg {
	case "ES256", "RS256":
		return crypto.SHA256
	default:
		return crypto.Hash(0)
	}
}

// AlgorithmForCertificate picks RS256/ES256 from an authenticator certificate.
func AlgorithmForCertificate(certDER []byte) (string, error) {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return "", err
	}
	switch public := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RS256", nil
	case *ecdsa.PublicKey:
		if public.Curve != elliptic.P256() {
			return "", fmt.Errorf("ES256 requires P-256")
		}
		return "ES256", nil
	default:
		return "", fmt.Errorf("unsupported certificate key type")
	}
}
