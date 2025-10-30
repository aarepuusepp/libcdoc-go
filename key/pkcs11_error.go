package key

import (
	"github.com/yourorg/cdoc1-go/internal"
)

// NewPKCS11Error creates a new PKCS#11-related error (wrapper for internal.NewPKCS11Error)
func NewPKCS11Error(message string, cause error) error {
	return internal.NewPKCS11Error(message, cause)
}

