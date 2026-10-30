package bounds

import "fmt"

// CDOC2 resource limits (CDOC2-035).
const (
	MaxContainerBytes       = 256 << 20
	MaxHeaderBytes          = 4 << 20
	MaxCertificateDERBytes  = 32 << 10
	MaxKeyMaterialBytes     = 4 << 10
	MaxCapsuleFieldBytes    = 2100
	MaxTransactionIDLen     = 34
	MinTransactionIDLen     = 18
	MaxShareIDLen           = 128
	MaxDecompressedTarEntry = 64 << 20
)

// Len returns an error when n exceeds max.
func Len(name string, n, max int) error {
	if n < 0 || n > max {
		return fmt.Errorf("%s exceeds limit (%d > %d)", name, n, max)
	}
	return nil
}
