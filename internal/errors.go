package internal

import "fmt"

// CDOCError is the base error type for all CDOC-related errors
type CDOCError struct {
	Message string
	Cause   error
}

// Error implements the error interface
func (e *CDOCError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Cause)
	}
	return e.Message
}

// Unwrap returns the underlying error
func (e *CDOCError) Unwrap() error {
	return e.Cause
}

// ValidationError represents input validation errors
type ValidationError struct {
	CDOCError
}

// NewValidationError creates a new ValidationError
func NewValidationError(message string, cause error) *ValidationError {
	return &ValidationError{
		CDOCError: CDOCError{
			Message: message,
			Cause:   cause,
		},
	}
}

// EncryptionError represents encryption operation errors
type EncryptionError struct {
	CDOCError
}

// NewEncryptionError creates a new EncryptionError
func NewEncryptionError(message string, cause error) *EncryptionError {
	return &EncryptionError{
		CDOCError: CDOCError{
			Message: message,
			Cause:   cause,
		},
	}
}

// DecryptionError represents decryption operation errors
type DecryptionError struct {
	CDOCError
}

// NewDecryptionError creates a new DecryptionError
func NewDecryptionError(message string, cause error) *DecryptionError {
	return &DecryptionError{
		CDOCError: CDOCError{
			Message: message,
			Cause:   cause,
		},
	}
}

// ParseError represents XML parsing errors
type ParseError struct {
	CDOCError
}

// NewParseError creates a new ParseError
func NewParseError(message string, cause error) *ParseError {
	return &ParseError{
		CDOCError: CDOCError{
			Message: message,
			Cause:   cause,
		},
	}
}

// CertificateError represents certificate-related errors
type CertificateError struct {
	CDOCError
}

// NewCertificateError creates a new CertificateError
func NewCertificateError(message string, cause error) *CertificateError {
	return &CertificateError{
		CDOCError: CDOCError{
			Message: message,
			Cause:   cause,
		},
	}
}

// PKCS11Error represents PKCS#11 token-related errors
type PKCS11Error struct {
	CDOCError
}

// NewPKCS11Error creates a new PKCS11Error
func NewPKCS11Error(message string, cause error) *PKCS11Error {
	return &PKCS11Error{
		CDOCError: CDOCError{
			Message: message,
			Cause:   cause,
		},
	}
}
