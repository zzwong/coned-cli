package coned

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"testing"

	"github.com/zzwong/coned-cli/internal/auth"
)

type transportFailureRoundTripper struct{ err error }

func (r transportFailureRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, r.err
}

type transportFailureBody struct{ err error }

func (r transportFailureBody) Read([]byte) (int, error) { return 0, r.err }
func (transportFailureBody) Close() error               { return nil }

func TestTransportFailuresAreNotProtocolChangesAcrossClients(t *testing.T) {
	const secretURL = "https://account:password@example.invalid/login?token=URL-CANARY"
	const secretCause = "private socket detail CAUSE-CANARY"
	cause := &url.Error{Op: http.MethodPost, URL: secretURL, Err: errors.New(secretCause)}

	checks := []struct {
		name string
		run  func(*Client) error
	}{
		{
			name: "authentication",
			run: func(client *Client) error {
				_, err := client.Authenticate(context.Background(), auth.Credentials{Email: "person@example.test", Password: "synthetic-password"})
				return err
			},
		},
		{
			name: "bill history",
			run: func(client *Client) error {
				_, err := client.ListBills(context.Background(), auth.Session{Cookies: []auth.Cookie{{Name: "CE_AUTH", Value: "synthetic", Domain: "www.coned.com", Path: "/"}}})
				return err
			},
		},
		{
			name: "usage",
			run: func(client *Client) error {
				_, err := client.Forecast(context.Background(), auth.Session{Cookies: []auth.Cookie{{Name: "OPOWER_AUTH_TOKEN", Value: "synthetic-token", Domain: "www.coned.com", Path: "/"}}})
				return err
			},
		},
	}

	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			var debug bytes.Buffer
			client, err := NewClient(Options{Transport: transportFailureRoundTripper{err: cause}, DebugWriter: &debug})
			if err != nil {
				t.Fatal(err)
			}
			got := check.run(client)
			if got == nil {
				t.Fatal("expected transport error")
			}
			if errors.Is(got, ErrProtocolChanged) {
				t.Fatalf("transport failure was reported as provider protocol change: %v", got)
			}
			transport, ok := AsSafeTransportError(got)
			if !ok || transport.Kind != TransportUnknown || transport.Retryable || !errors.Is(got, ErrTransport) {
				t.Fatalf("transport classification = %#v, want non-retryable unknown transport failure", transport)
			}
			for _, output := range []string{got.Error(), debug.String()} {
				if strings.Contains(output, "URL-CANARY") || strings.Contains(output, "CAUSE-CANARY") || strings.Contains(output, "account:password") {
					t.Fatalf("transport details leaked: %q", output)
				}
			}
		})
	}
}

type timeoutTestError struct{}

func (timeoutTestError) Error() string   { return "timeout detail" }
func (timeoutTestError) Timeout() bool   { return true }
func (timeoutTestError) Temporary() bool { return true }

func TestTransportErrorClassifications(t *testing.T) {
	for _, tc := range []struct {
		name      string
		cause     error
		wantKind  TransportKind
		wantRetry bool
	}{
		{name: "deadline", cause: context.DeadlineExceeded, wantKind: TransportTimeout, wantRetry: true},
		{name: "network timeout", cause: &url.Error{Op: "Get", URL: "https://secret.invalid/?token=x", Err: timeoutTestError{}}, wantKind: TransportTimeout, wantRetry: true},
		{name: "temporary dns", cause: &net.DNSError{Err: "lookup failed", Name: "dns-canary.invalid", IsTemporary: true}, wantKind: TransportDNS, wantRetry: true},
		{name: "permanent dns", cause: &net.DNSError{Err: "no such host", Name: "dns-canary.invalid"}, wantKind: TransportDNS, wantRetry: false},
		{name: "dns timeout", cause: &net.DNSError{Err: "timeout", Name: "dns-canary.invalid", IsTimeout: true}, wantKind: TransportDNS, wantRetry: true},
		{name: "certificate", cause: x509.UnknownAuthorityError{}, wantKind: TransportTLS, wantRetry: false},
		{name: "connection refused", cause: &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}, wantKind: TransportConnection, wantRetry: true},
		{name: "connection reset", cause: &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}, wantKind: TransportConnection, wantRetry: true},
		{name: "broken connection", cause: &net.OpError{Op: "write", Net: "tcp", Err: syscall.EPIPE}, wantKind: TransportConnection, wantRetry: true},
		{name: "unknown", cause: errors.New("opaque operating system detail"), wantKind: TransportUnknown, wantRetry: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := transportError(context.Background(), tc.cause)
			transport, ok := AsSafeTransportError(got)
			if !ok || transport.Kind != tc.wantKind || transport.Retryable != tc.wantRetry {
				t.Fatalf("transportError() = %#v, want kind=%q retryable=%t", transport, tc.wantKind, tc.wantRetry)
			}
			if errors.Is(got, ErrProtocolChanged) || !errors.Is(got, ErrTransport) {
				t.Fatalf("transport error identity = %v", got)
			}
		})
	}
}

func TestTransportErrorPreservesContextAndRedactsWrappedURL(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := transportError(ctx, errors.New("private detail")); !errors.Is(got, context.Canceled) || errors.Is(got, ErrTransport) {
		t.Fatalf("cancellation = %v, want direct safe context cancellation", got)
	}

	deadline := fmt.Errorf("request wrapper: %w", context.DeadlineExceeded)
	got := transportError(context.Background(), &url.Error{Op: "Get", URL: "https://name:password@host.invalid/path?token=URL-CANARY", Err: deadline})
	if !errors.Is(got, context.DeadlineExceeded) {
		t.Fatalf("deadline identity lost: %v", got)
	}
	if !strings.Contains(got.Error(), "timeout") || strings.Contains(got.Error(), "URL-CANARY") || strings.Contains(got.Error(), "password") {
		t.Fatalf("unsafe timeout error: %v", got)
	}
}

func TestAsSafeTransportErrorAllowlistAndRetryability(t *testing.T) {
	for _, kind := range []TransportKind{TransportTLS, TransportUnknown} {
		unsafe := &TransportError{Kind: kind, Retryable: true}
		safe, ok := AsSafeTransportError(unsafe)
		if !ok || safe.Retryable {
			t.Fatalf("unsafe %s retryability survived inspection: %#v", kind, safe)
		}
	}
	unsafe := &TransportError{Kind: TransportKind("private-kind"), Retryable: true}
	if _, ok := AsSafeTransportError(unsafe); ok {
		t.Fatal("unlisted transport kind was accepted")
	}
}

func TestAuthenticationClassifiesResponseBodyReadFailure(t *testing.T) {
	const canary = "body-read secret detail"
	client, err := NewClient(Options{Transport: transportFailureRoundTripper{err: nil}, DebugWriter: &bytes.Buffer{}})
	if err != nil {
		t.Fatal(err)
	}
	client.httpClient.Transport = roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodDelete {
			return &http.Response{StatusCode: http.StatusNotFound, Header: make(http.Header), Body: http.NoBody, Request: request}, nil
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: transportFailureBody{err: errors.New(canary)}, Request: request}, nil
	})
	_, err = client.Authenticate(context.Background(), auth.Credentials{Email: "person@example.test", Password: "synthetic-password"})
	transport, ok := AsSafeTransportError(err)
	if !ok || transport.Kind != TransportUnknown || transport.Retryable || errors.Is(err, ErrProtocolChanged) {
		t.Fatalf("body read error = %#v, want unknown transport failure", transport)
	}
	if strings.Contains(err.Error(), canary) {
		t.Fatalf("body read cause leaked: %v", err)
	}
}

func TestDebugOutputUsesStaticStepsAndOmitsCookieNames(t *testing.T) {
	var debug bytes.Buffer
	client, err := NewClient(Options{
		BaseURL:                  "http://127.0.0.1:8080",
		InsecureLoopbackForTests: true,
		DebugWriter:              &debug,
		Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
			header := make(http.Header)
			header.Add("Set-Cookie", "RESPONSE-NAME-CANARY=secret; Path=/")
			return &http.Response{StatusCode: http.StatusOK, Header: header, Body: http.NoBody, Request: request}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	endpoint, _ := url.Parse("http://127.0.0.1:8080/login")
	client.jar.SetCookies(endpoint, []*http.Cookie{{Name: "REQUEST-NAME-CANARY", Value: "secret", Path: "/"}})
	if _, err := client.request(context.Background(), stepLogin, http.MethodGet, endpoint, nil, false); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(debug.String(), "REQUEST-NAME-CANARY") || strings.Contains(debug.String(), "RESPONSE-NAME-CANARY") {
		t.Fatalf("cookie name leaked in debug output: %q", debug.String())
	}
	if !strings.Contains(debug.String(), "step=login") {
		t.Fatalf("debug output omitted safe operation step: %q", debug.String())
	}
}
