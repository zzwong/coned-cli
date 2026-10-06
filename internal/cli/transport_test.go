package cli

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zzwong/coned-cli/internal/auth"
	"github.com/zzwong/coned-cli/internal/coned"
	"github.com/zzwong/coned-cli/internal/securestore"
)

type cliTransportFailureRoundTripper struct{ err error }

func (r cliTransportFailureRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, r.err
}

func TestTransportErrorsSurviveCLITranslationBoundaries(t *testing.T) {
	const urlCanary = "https://user:password@example.invalid/path?token=URL-CANARY"
	const causeCanary = "private network detail CAUSE-CANARY"
	failure := &url.Error{Op: http.MethodGet, URL: urlCanary, Err: fmt.Errorf("%s: %w", causeCanary, context.DeadlineExceeded)}
	client, err := coned.NewClient(coned.Options{Transport: cliTransportFailureRoundTripper{err: failure}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	session := auth.Session{
		Cookies: []auth.Cookie{
			{Name: "CE_AUTH", Value: "synthetic-session", Domain: "www.coned.com", Path: "/"},
			{Name: "OPOWER_AUTH_TOKEN", Value: "synthetic-token", Domain: "www.coned.com", Path: "/"},
		},
		AuthenticatedAt: now,
	}
	store := securestore.NewMemoryStore()
	if err := auth.SaveSession(store, "default", session); err != nil {
		t.Fatal(err)
	}
	if err := auth.SaveCredentials(store, "default", auth.Credentials{Email: "person@example.test", Password: "synthetic-password"}); err != nil {
		t.Fatal(err)
	}
	deps := Dependencies{Store: store, Authenticator: client, Bills: client, Opower: client, Clock: time.Now}
	for _, command := range []string{
		"auth login --force --no-store",
		"bills list",
		"usage forecast",
		"usage export --format json",
		"green-button inspect",
	} {
		t.Run(command, func(t *testing.T) {
			output, got := runWithDependencies(t, deps, "", command)
			if got == nil || !errors.Is(got, coned.ErrTransport) || !errors.Is(got, context.DeadlineExceeded) {
				t.Fatalf("error = %v, want safe transport error preserving deadline identity", got)
			}
			transport, ok := coned.AsSafeTransportError(got)
			if !ok || transport.Kind != coned.TransportTimeout || !transport.Retryable {
				t.Fatalf("transport = %#v, want retryable timeout", transport)
			}
			for _, rendered := range []string{got.Error(), output} {
				if strings.Contains(rendered, "URL-CANARY") || strings.Contains(rendered, "CAUSE-CANARY") || strings.Contains(rendered, "user:password") {
					t.Fatalf("transport details leaked: %q", rendered)
				}
			}
		})
	}
}
