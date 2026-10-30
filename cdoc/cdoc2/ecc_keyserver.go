package cdoc2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"

	rcpt "github.com/aarepuusepp/libcdoc-go/v2/cdoc/cdoc2/schema/cdoc20/recipients"
	"github.com/aarepuusepp/libcdoc-go/v2/internal"
)

// ECKeyServerEncoding holds TLS point bytes and OpenAPI capsule_type for key-server ECC recipients.
type ECKeyServerEncoding struct {
	TLSPoint    []byte
	CapsuleType string
	FBCurve     rcpt.EllipticCurve
}

// EncodeECKeyServerRecipient builds TLS 1.3 uncompressed point bytes and capsule metadata.
func EncodeECKeyServerRecipient(pub *ecdsa.PublicKey) (ECKeyServerEncoding, error) {
	if pub == nil {
		return ECKeyServerEncoding{}, internal.NewEncryptionError("nil EC public key", nil)
	}
	coordLen, capsuleType, fbCurve, err := ecKeyServerCurveMeta(pub.Curve)
	if err != nil {
		return ECKeyServerEncoding{}, err
	}
	tlsPoint := make([]byte, 1+coordLen*2)
	tlsPoint[0] = 0x04
	//nolint:staticcheck
	xBytes := pub.X.Bytes()
	//nolint:staticcheck
	yBytes := pub.Y.Bytes()
	copy(tlsPoint[1+coordLen-len(xBytes):1+coordLen], xBytes)
	copy(tlsPoint[1+coordLen*2-len(yBytes):1+coordLen*2], yBytes)
	return ECKeyServerEncoding{
		TLSPoint:    tlsPoint,
		CapsuleType: capsuleType,
		FBCurve:     fbCurve,
	}, nil
}

func ecKeyServerCurveMeta(curve elliptic.Curve) (coordLen int, capsuleType string, fbCurve rcpt.EllipticCurve, err error) {
	switch curve {
	case elliptic.P256():
		return 32, "ecc_secp256r1", rcpt.EllipticCurveUNKNOWN, nil
	case elliptic.P384():
		return 48, "ecc_secp384r1", rcpt.EllipticCurvesecp384r1, nil
	case elliptic.P521():
		return 66, "ecc_secp521r1", rcpt.EllipticCurveUNKNOWN, nil
	default:
		return 0, "", rcpt.EllipticCurveUNKNOWN, internal.NewEncryptionError(
			fmt.Sprintf("unsupported EC curve for key server: %T", curve), nil)
	}
}
