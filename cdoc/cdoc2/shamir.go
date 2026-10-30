package cdoc2

import (
	"crypto/rand"
)

// SplitKEK splits a KEK into n shares using XOR-based n-of-n splitting (CDOC2 compatible).
func SplitKEK(kek []byte, numShares int) ([][]byte, error) {
	if numShares < 1 {
		return nil, internalValidationError("numShares must be >= 1")
	}
	shares := make([][]byte, numShares)
	shares[0] = make([]byte, len(kek))
	copy(shares[0], kek)
	for i := 1; i < numShares; i++ {
		share := make([]byte, len(kek))
		if _, err := rand.Read(share); err != nil {
			return nil, err
		}
		shares[i] = share
		shares[0] = xorBytes(shares[0], share)
	}
	return shares, nil
}

// CombineKEK combines key shares into the original KEK (strict N-of-N: all shares required).
func CombineKEK(shares [][]byte, minRequired int) ([]byte, error) {
	if minRequired < 2 {
		return nil, internalValidationError("N-of-N requires at least 2 shares")
	}
	if len(shares) != minRequired {
		return nil, internalValidationError("N-of-N requires all shares")
	}
	if len(shares) == 0 {
		return nil, internalValidationError("no shares provided")
	}
	kek := make([]byte, len(shares[0]))
	copy(kek, shares[0])
	for i := 1; i < len(shares); i++ {
		kek = xorBytes(kek, shares[i])
	}
	return kek, nil
}

func xorBytes(a, b []byte) []byte {
	out := make([]byte, len(a))
	for i := range a {
		out[i] = a[i] ^ b[i]
	}
	return out
}

func internalValidationError(msg string) error {
	return &validationError{msg: msg}
}

type validationError struct {
	msg string
}

func (e *validationError) Error() string {
	return e.msg
}
