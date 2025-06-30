package utils

import (
	"fmt"
	"strings"
)

// Error types
const (
	ErrTypeConnection = "connection"
	ErrTypeTLS        = "tls"
	ErrTypeCertificate = "certificate"
	ErrTypeValidation = "validation"
	ErrTypeIO         = "io"
	ErrTypeConfig     = "config"
)

// ScanError represents a structured error with context
type ScanError struct {
	Type    string
	Message string
	Details string
	Err     error
}

// Error implements the error interface
func (e *ScanError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s (%s)", e.Type, e.Message, e.Err.Error())
	}
	return fmt.Sprintf("%s: %s", e.Type, e.Message)
}

// Unwrap returns the underlying error
func (e *ScanError) Unwrap() error {
	return e.Err
}

// NewConnectionError creates a new connection error
func NewConnectionError(message string, err error) *ScanError {
	return &ScanError{
		Type:    ErrTypeConnection,
		Message: message,
		Err:     err,
	}
}

// NewTLSError creates a new TLS error
func NewTLSError(message string, err error) *ScanError {
	return &ScanError{
		Type:    ErrTypeTLS,
		Message: message,
		Err:     err,
	}
}

// NewCertificateError creates a new certificate error
func NewCertificateError(message string, err error) *ScanError {
	return &ScanError{
		Type:    ErrTypeCertificate,
		Message: message,
		Err:     err,
	}
}

// NewValidationError creates a new validation error
func NewValidationError(message string) *ScanError {
	return &ScanError{
		Type:    ErrTypeValidation,
		Message: message,
	}
}

// NewIOError creates a new I/O error
func NewIOError(message string, err error) *ScanError {
	return &ScanError{
		Type:    ErrTypeIO,
		Message: message,
		Err:     err,
	}
}

// NewConfigError creates a new configuration error
func NewConfigError(message string, err error) *ScanError {
	return &ScanError{
		Type:    ErrTypeConfig,
		Message: message,
		Err:     err,
	}
}

// IsConnectionError checks if an error is a connection error
func IsConnectionError(err error) bool {
	if scanErr, ok := err.(*ScanError); ok {
		return scanErr.Type == ErrTypeConnection
	}
	return false
}

// IsTLSError checks if an error is a TLS error
func IsTLSError(err error) bool {
	if scanErr, ok := err.(*ScanError); ok {
		return scanErr.Type == ErrTypeTLS
	}
	return false
}

// IsCertificateError checks if an error is a certificate error
func IsCertificateError(err error) bool {
	if scanErr, ok := err.(*ScanError); ok {
		return scanErr.Type == ErrTypeCertificate
	}
	return false
}

// FormatError formats an error with consistent styling
func FormatError(err error) string {
	if scanErr, ok := err.(*ScanError); ok {
		return scanErr.Error()
	}
	return err.Error()
}

// CollectErrors collects multiple errors into a single error
func CollectErrors(errors []error) error {
	if len(errors) == 0 {
		return nil
	}
	if len(errors) == 1 {
		return errors[0]
	}

	var messages []string
	for _, err := range errors {
		messages = append(messages, FormatError(err))
	}

	return fmt.Errorf("multiple errors occurred:\n%s", strings.Join(messages, "\n"))
}
