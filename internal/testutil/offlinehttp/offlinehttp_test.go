package offlinehttp

import (
	"errors"
	"net/http"
	"testing"
)

type fakeTransport func(*http.Request) (*http.Response, error)

func (f fakeTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestGuardRejectsBeforeDelegation(t *testing.T) {
	for _, target := range []string{"https://coned.okta.com/api/v1/sessions/me", "http://localhost/", "http://127.0.0.1.example.test/", "http://192.0.2.1/", "ftp://127.0.0.1/", "http://user:secret@127.0.0.1/"} {
		t.Run(target, func(t *testing.T) {
			calls := 0
			g := &guard{base: fakeTransport(func(*http.Request) (*http.Response, error) { calls++; return nil, nil })}
			req, err := http.NewRequest(http.MethodGet, target, nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := g.RoundTrip(req); !errors.Is(err, errBlocked) {
				t.Fatalf("error = %v", err)
			}
			if calls != 0 || g.blocked.Load() != 1 {
				t.Fatalf("delegations=%d blocked=%d", calls, g.blocked.Load())
			}
		})
	}
}

func TestGuardAllowsLiteralLoopbackOnly(t *testing.T) {
	for _, target := range []string{"http://127.0.0.1:1234/", "https://[::1]:1234/"} {
		calls := 0
		g := &guard{base: fakeTransport(func(r *http.Request) (*http.Response, error) {
			calls++
			return &http.Response{StatusCode: 200, Body: http.NoBody, Request: r}, nil
		})}
		req, err := http.NewRequest(http.MethodGet, target, nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := g.RoundTrip(req)
		if err != nil || calls != 1 || g.blocked.Load() != 0 {
			t.Fatalf("response=%v error=%v calls=%d", response, err, calls)
		}
	}
}

func TestInstallDisablesProxyAndReportsSwallowedBlock(t *testing.T) {
	before := http.DefaultTransport
	check := Install()
	g := http.DefaultTransport.(*guard)
	if g.base.(*http.Transport).Proxy != nil {
		t.Fatal("proxy remains enabled")
	}
	req, err := http.NewRequest(http.MethodGet, "https://example.test/", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = http.DefaultTransport.RoundTrip(req) // deliberately swallow the error
	if check() {
		t.Fatal("swallowed outbound request did not fail final check")
	}
	if http.DefaultTransport != before {
		t.Fatal("default transport not restored")
	}
}
