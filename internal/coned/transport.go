package coned

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"syscall"
)

type transportStep string

type transportReadTracker struct {
	reader io.Reader
	err    error
}

func (r *transportReadTracker) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if err != nil && err != io.EOF {
		r.err = err
	}
	return n, err
}

const (
	stepRequest      transportStep = "request"
	stepOktaReset    transportStep = "okta-reset"
	stepLogin        transportStep = "login"
	stepMFAResend    transportStep = "mfa-resend"
	stepMFAVerify    transportStep = "mfa-verify"
	stepRedirect     transportStep = "redirect"
	stepSessionCheck transportStep = "session-check"
	stepBillHistory  transportStep = "bill-history"
	stepBillDocument transportStep = "bill-document"
	stepPDFDownload  transportStep = "pdf-download"
	stepUsage        transportStep = "usage"
	stepUsageExport  transportStep = "usage-export"
	stepDiagnostics  transportStep = "diagnostics"
)

func safeTransportStep(step transportStep) string {
	switch step {
	case stepOktaReset, stepLogin, stepMFAResend, stepMFAVerify, stepRedirect,
		stepSessionCheck, stepBillHistory, stepBillDocument, stepPDFDownload,
		stepUsage, stepUsageExport, stepDiagnostics:
		return string(step)
	default:
		return string(stepRequest)
	}
}

func (c *Client) transportFailure(ctx context.Context, step transportStep, cause error) error {
	safe := transportError(ctx, cause)
	if transport, ok := AsSafeTransportError(safe); ok {
		c.debugf("http request failed step=%s kind=%s", safeTransportStep(step), transport.Kind)
	} else if errors.Is(safe, context.Canceled) {
		c.debugf("http request canceled step=%s", safeTransportStep(step))
	}
	return safe
}

func transportError(ctx context.Context, cause error) error {
	if ctx != nil {
		if ctxErr := ctx.Err(); errors.Is(ctxErr, context.Canceled) {
			return context.Canceled
		} else if errors.Is(ctxErr, context.DeadlineExceeded) {
			return &TransportError{Kind: TransportTimeout, Retryable: true, cause: ctxErr}
		}
	}
	if errors.Is(cause, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(cause, context.DeadlineExceeded) {
		return &TransportError{Kind: TransportTimeout, Retryable: true, cause: cause}
	}

	var dnsErr *net.DNSError
	if errors.As(cause, &dnsErr) {
		return &TransportError{
			Kind: TransportDNS, Retryable: dnsErr.IsTimeout || dnsErr.IsTemporary, cause: cause,
		}
	}
	if isTLSError(cause) {
		return &TransportError{Kind: TransportTLS, Retryable: false, cause: cause}
	}
	if isConnectionError(cause) {
		return &TransportError{Kind: TransportConnection, Retryable: true, cause: cause}
	}

	var networkErr net.Error
	if errors.As(cause, &networkErr) && networkErr.Timeout() {
		return &TransportError{Kind: TransportTimeout, Retryable: true, cause: cause}
	}
	return &TransportError{Kind: TransportUnknown, Retryable: false, cause: cause}
}

func isTLSError(err error) bool {
	var verificationErr *tls.CertificateVerificationError
	if errors.As(err, &verificationErr) {
		return true
	}
	var alertErr tls.AlertError
	if errors.As(err, &alertErr) {
		return true
	}
	var recordErr tls.RecordHeaderError
	if errors.As(err, &recordErr) {
		return true
	}
	var unknownAuthority x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthority) {
		return true
	}
	var hostnameErr x509.HostnameError
	if errors.As(err, &hostnameErr) {
		return true
	}
	var invalidCert x509.CertificateInvalidError
	return errors.As(err, &invalidCert)
}

func isConnectionError(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, net.ErrClosed)
}
