package coned

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
)

// authFixtureTransport explicitly models the initial remote-session reset.
// No real Okta request is delegated. Every other request must use the exact
// fixture origin, not merely any loopback address.
type authFixtureTransport struct {
	origin     *url.URL
	base       http.RoundTripper
	unexpected func()
	resets     atomic.Int32
	logins     atomic.Int32
	closed     atomic.Int32
}

type resetFixtureBody struct{ closed *atomic.Int32 }

func (*resetFixtureBody) Read([]byte) (int, error) { return 0, io.EOF }
func (b *resetFixtureBody) Close() error           { b.closed.Add(1); return nil }

func (f *authFixtureTransport) reject() (*http.Response, error) {
	f.unexpected()
	return nil, errors.New("unexpected request outside auth fixture contract")
}

func (f *authFixtureTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r == nil || r.URL == nil {
		return f.reject()
	}
	if r.Method == http.MethodDelete && r.URL.String() == defaultLogoutURL && r.Body == nil {
		f.resets.Add(1)
		return &http.Response{StatusCode: http.StatusNotFound, Header: make(http.Header), Body: &resetFixtureBody{closed: &f.closed}, Request: r}, nil
	}
	if r.URL.User != nil || r.URL.Fragment != "" || r.URL.Scheme != f.origin.Scheme || r.URL.Host != f.origin.Host {
		return f.reject()
	}
	if r.URL.Path == loginPath {
		// The reset must happen exactly once before each credential exchange.
		if r.Method != http.MethodPost || f.resets.Load() != f.logins.Add(1) {
			return f.reject()
		}
	}
	return f.base.RoundTrip(r)
}

func newAuthFixtureTransport(t *testing.T, server *httptest.Server) *authFixtureTransport {
	t.Helper()
	origin, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	f := &authFixtureTransport{origin: origin, base: http.DefaultTransport, unexpected: func() { t.Error("unexpected auth fixture request blocked before dialing") }}
	t.Cleanup(func() {
		if f.resets.Load() != f.logins.Load() {
			t.Errorf("reset count %d differs from login count %d", f.resets.Load(), f.logins.Load())
		}
		if f.resets.Load() != f.closed.Load() {
			t.Errorf("reset response bodies not closed: resets=%d closed=%d", f.resets.Load(), f.closed.Load())
		}
	})
	return f
}

func TestAuthFixtureResetIsSyntheticAndClosed(t *testing.T) {
	origin, _ := url.Parse("http://127.0.0.1:1234")
	delegated, blocked := 0, 0
	f := &authFixtureTransport{origin: origin, base: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		delegated++
		return &http.Response{StatusCode: 200, Body: http.NoBody, Request: r}, nil
	}), unexpected: func() { blocked++ }}
	req, err := http.NewRequest(http.MethodDelete, defaultLogoutURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := f.RoundTrip(req)
	if err != nil || response.StatusCode != http.StatusNotFound || delegated != 0 || blocked != 0 {
		t.Fatalf("reset was not synthetic: response=%v error=%v delegated=%d blocked=%d", response, err, delegated, blocked)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	login, err := http.NewRequest(http.MethodPost, origin.String()+loginPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.RoundTrip(login); err != nil {
		t.Fatal(err)
	}
	if f.resets.Load() != 1 || f.logins.Load() != 1 || f.closed.Load() != 1 || delegated != 1 || blocked != 0 {
		t.Fatal("reset/login contract not recorded")
	}
}

func TestAuthFixtureBlocksUnexpectedDestinationsBeforeDelegation(t *testing.T) {
	for _, target := range []string{"https://coned.okta.com/api/v1/sessions/me?unexpected=1", "https://www.coned.com/", "http://127.0.0.1:4321/", "http://user:password@127.0.0.1:1234/", "http://127.0.0.1:1234/#fragment"} {
		origin, _ := url.Parse("http://127.0.0.1:1234")
		delegated, blocked := 0, 0
		f := &authFixtureTransport{origin: origin, base: roundTripperFunc(func(*http.Request) (*http.Response, error) { delegated++; return nil, nil }), unexpected: func() { blocked++ }}
		req, err := http.NewRequest(http.MethodDelete, target, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.RoundTrip(req); err == nil || blocked != 1 || delegated != 0 {
			t.Fatalf("target escaped fixture: error=%v blocked=%d delegated=%d", err, blocked, delegated)
		}
	}
}

func TestAuthFixtureRequiresResetBeforeLogin(t *testing.T) {
	origin, _ := url.Parse("http://127.0.0.1:1234")
	delegated, blocked := 0, 0
	f := &authFixtureTransport{origin: origin, base: roundTripperFunc(func(*http.Request) (*http.Response, error) { delegated++; return nil, nil }), unexpected: func() { blocked++ }}
	req, err := http.NewRequest(http.MethodPost, origin.String()+loginPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.RoundTrip(req); err == nil || blocked != 1 || delegated != 0 {
		t.Fatalf("login before reset accepted: error=%v blocked=%d delegated=%d", err, blocked, delegated)
	}
}
