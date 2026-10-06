// Package coned implements the Con Edison HTTP authentication protocol.
package coned

import (
	"context"
	"errors"
	"fmt"
	"net"
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
	ErrTransport          = errors.New("coned: request to Con Edison failed")
	ErrBillNotFound       = errors.New("coned: bill not found")
)

// TransportKind is the safe, allowlisted category of a failed HTTP request.
type TransportKind string

const (
	TransportTimeout    TransportKind = "timeout"
	TransportDNS        TransportKind = "dns"
	TransportTLS        TransportKind = "tls"
	TransportConnection TransportKind = "connection"
	TransportUnknown    TransportKind = "unknown"
)

// TransportError classifies a request failure without rendering its underlying
// cause. Kind and Retryable are safe for human and machine-readable output.
// The cause is kept only so errors.Is can recognize context cancellation and
// deadline errors; Error never formats it.
type TransportError struct {
	Kind      TransportKind
	Retryable bool
	cause     error
}

func (e *TransportError) Error() string {
	kind := e.Kind
	if !validTransportKind(kind) {
		kind = TransportUnknown
	}
	return fmt.Sprintf("%s (%s)", ErrTransport, kind)
}

// Is lets callers recognize any classified request failure by its sentinel.
func (e *TransportError) Is(target error) bool { return target == ErrTransport }

// Unwrap preserves safe cause inspection, including errors.Is for context
// deadline errors, while Error remains independent of the cause text.
func (e *TransportError) Unwrap() error { return e.cause }

// AsSafeTransportError returns a detached, allowlisted transport error. It
// discards arbitrary wrappers while retaining the private cause for errors.Is.
func AsSafeTransportError(err error) (*TransportError, bool) {
	var transport *TransportError
	if !errors.As(err, &transport) || transport == nil || !validTransportKind(transport.Kind) {
		return nil, false
	}
	return &TransportError{Kind: transport.Kind, Retryable: transportRetryable(transport.Kind, transport.cause), cause: transport.cause}, true
}

func validTransportKind(kind TransportKind) bool {
	switch kind {
	case TransportTimeout, TransportDNS, TransportTLS, TransportConnection, TransportUnknown:
		return true
	default:
		return false
	}
}

func transportRetryable(kind TransportKind, cause error) bool {
	switch kind {
	case TransportTimeout:
		if errors.Is(cause, context.DeadlineExceeded) {
			return true
		}
		var networkErr net.Error
		return errors.As(cause, &networkErr) && networkErr.Timeout()
	case TransportDNS:
		var dnsErr *net.DNSError
		return errors.As(cause, &dnsErr) && (dnsErr.IsTimeout || dnsErr.IsTemporary)
	case TransportConnection:
		return isConnectionError(cause)
	default:
		return false
	}
}

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

// DocumentError names the part of the bill-document contract that failed, so a
// provider change can be diagnosed from the error alone. Reason is one of this
// package's document* constants, and Host is set only when the host is what
// failed, so neither can carry a signed URL or bill data.
type DocumentError struct {
	Reason string
	Host   string
}

func (e *DocumentError) Error() string {
	if e.Host != "" {
		return fmt.Sprintf("coned: bill document contract changed: %s: %s", e.Reason, e.Host)
	}
	return "coned: bill document contract changed: " + e.Reason
}
func (e *DocumentError) Unwrap() error { return ErrProtocolChanged }

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
	var document *DocumentError
	if errors.As(err, &document) {
		clean := &DocumentError{Reason: document.Reason}
		if safeHostname(document.Host) {
			clean.Host = document.Host
		}
		return clean
	}
	if transport, ok := AsSafeTransportError(err); ok {
		return transport
	}
	if protocol, ok := AsSafeProtocolError(err); ok {
		// Request IDs are useful for authentication diagnostics, but bill
		// errors are intentionally limited to the HTTP status.
		return &ProtocolError{Status: protocol.Status}
	}
	for _, safe := range []error{ErrSelectionRequired, ErrSessionExpired, ErrBillNotFound, ErrProtocolChanged} {
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

func safeHostname(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	for _, r := range host {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' && r != '.' {
			return false
		}
	}
	return true
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
