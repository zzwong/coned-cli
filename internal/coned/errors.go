// Package coned implements the Con Edison HTTP authentication protocol.
package coned

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"unicode"
)

var (
	ErrInvalidCredentials = errors.New("coned: invalid credentials")
	ErrMFARequired        = errors.New("coned: multi-factor authentication required")
	ErrChallengeRequired  = errors.New("coned: authentication challenge required")
	ErrSessionExpired     = errors.New("coned: session expired; run `coned auth login`")
	ErrProtocolChanged    = errors.New("coned: login protocol changed")
	ErrBillNotFound       = errors.New("coned: bill not found")
)

// ProtocolError is deliberately limited to metadata that is safe to report.
// It never includes a response body, URL query, cookie, or credential.
type ProtocolError struct {
	Status    int
	RequestID string
}

func (e *ProtocolError) Error() string {
	if e.RequestID == "" {
		return fmt.Sprintf("%s (status %d)", ErrProtocolChanged, e.Status)
	}
	return fmt.Sprintf("%s (status %d, request id %s)", ErrProtocolChanged, e.Status, e.RequestID)
}
func (e *ProtocolError) Unwrap() error { return ErrProtocolChanged }

// BillDownloadError adds only the caller-supplied public bill ID to a safe
// download failure. The wrapped error must never contain private request data.
type BillDownloadError struct {
	ID    string
	cause error
}

func (e *BillDownloadError) Error() string {
	cause := safeBillDownloadCause(e.cause)
	if validPublicBillID(e.ID) {
		return fmt.Sprintf("coned: download bill %s: %v", e.ID, cause)
	}
	return fmt.Sprintf("coned: download bill: %v", cause)
}

func safeBillDownloadCause(err error) error {
	if protocol, ok := AsSafeProtocolError(err); ok {
		// Request IDs are useful for authentication diagnostics, but bill
		// errors are intentionally limited to the HTTP status.
		return &ProtocolError{Status: protocol.Status}
	}
	for _, safe := range []error{ErrSessionExpired, ErrBillNotFound, ErrProtocolChanged} {
		if errors.Is(err, safe) {
			return safe
		}
	}
	return ErrProtocolChanged
}

// AsSafeProtocolError extracts only the safe metadata from a ProtocolError.
// Any wrapped error, including URLs and response details, is discarded.
func AsSafeProtocolError(err error) (*ProtocolError, bool) {
	var protocol *ProtocolError
	if !errors.As(err, &protocol) || protocol == nil || protocol.Status < 100 || protocol.Status > 599 {
		return nil, false
	}
	clean := &ProtocolError{Status: protocol.Status}
	if safeRequestIDValue(protocol.RequestID) {
		clean.RequestID = protocol.RequestID
	}
	return clean, true
}

// Unwrap preserves only a safe category, never a provider-supplied cause.
func (e *BillDownloadError) Unwrap() error { return safeBillDownloadCause(e.cause) }

func billDownloadError(id string, err error) error {
	if err == nil {
		return nil
	}
	// Do not retain an arbitrary caller value: it may be a provider document
	// ID. Only validated public IDs may appear in a download error.
	if !validPublicBillID(id) {
		id = ""
	}
	return &BillDownloadError{ID: id, cause: safeBillDownloadCause(err)}
}

// protocolError extracts only safe, bounded diagnostic metadata. Response
// bodies and URLs are intentionally never consulted or retained.
func protocolError(response *http.Response) *ProtocolError {
	if response == nil {
		return &ProtocolError{}
	}
	return &ProtocolError{Status: response.StatusCode, RequestID: safeRequestID(response.Header)}
}

func safeRequestID(headers http.Header) string {
	for _, name := range []string{"Request-Id", "X-Request-Id", "x-ms-middleware-request-id"} {
		if id := strings.TrimSpace(headers.Get(name)); safeRequestIDValue(id) {
			return id
		}
	}
	return ""
}

func safeRequestIDValue(id string) bool {
	if id == "" || len(id) > 256 {
		return false
	}
	for _, r := range id {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' && r != '_' {
			return false
		}
	}
	return true
}
