package coned

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/zzwong/coned-cli/internal/auth"
)

func readFixture(t *testing.T, name string) string {
	t.Helper()
	body, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func testClient(t *testing.T, server *httptest.Server) *Client {
	t.Helper()
	client, err := NewClient(Options{BaseURL: server.URL, InsecureLoopbackForTests: true})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestAuthenticateSuccessAndExactPayload(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case loginPath:
			if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Accept") != "application/json" || !strings.Contains(r.Header.Get("User-Agent"), "Chrome/149") || r.Header.Get("Referer") != server.URL+"/" {
				t.Error("incorrect login request")
			}
			body, _ := io.ReadAll(r.Body)
			const want = `{"LoginEmail":"person@example.test","LoginPassword":"synthetic-password","LoginRememberMe":false,"ReturnUrl":"/en/accounts-billing/my-account/energy-use","OpenIdRelayState":""}`
			if string(body) != want {
				t.Errorf("incorrect payload: %s", body)
			}
			fixture := readFixture(t, "login_success.json")
			_, _ = w.Write([]byte(strings.ReplaceAll(fixture, "https://www.coned.com", server.URL)))
		case "/authorize":
			if r.URL.Query().Get("state") != "synthetic" || r.URL.Query().Get("nonce") != "synthetic" || r.URL.Query().Get("sessionToken") != "synthetic-session-token" {
				t.Error("authorize state, nonce, or session token was not preserved")
			}
			http.Redirect(w, r, "/complete?state=synthetic&nonce=synthetic", http.StatusFound)
		case "/complete":
			if r.URL.Query().Get("state") != "synthetic" || r.URL.Query().Get("nonce") != "synthetic" {
				t.Error("redirect query was not preserved")
			}
			http.SetCookie(w, &http.Cookie{Name: "CE_AUTH", Value: "synthetic", Path: "/", HttpOnly: true})
			w.WriteHeader(http.StatusOK)
		case accountPath:
			if _, err := r.Cookie("CE_AUTH"); err != nil {
				t.Error("session cookie absent")
			}
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client, err := NewClient(Options{BaseURL: server.URL, Version: "test", InsecureLoopbackForTests: true})
	if err != nil {
		t.Fatal(err)
	}
	session, err := client.Authenticate(context.Background(), auth.Credentials{Email: "person@example.test", Password: "synthetic-password"})
	if err != nil {
		t.Fatal(err)
	}
	if len(session.Cookies) != 1 || session.Cookies[0].Name != "CE_AUTH" {
		t.Fatalf("session = %#v", session)
	}
}

func TestVerifyMFAExactPayloadAndSession(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case verifyMFAPath:
			body, _ := io.ReadAll(r.Body)
			const want = `{"MFACode":"001103","ReturnUrl":"/en/accounts-billing/my-account/energy-use","OpenIdRelayState":""}`
			if string(body) != want {
				t.Errorf("incorrect MFA payload: %s", body)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"code":true,"authRedirectUrl":"` + server.URL + `/complete"}`))
		case "/complete":
			http.SetCookie(w, &http.Cookie{Name: "CE_AUTH", Value: "synthetic", Path: "/", HttpOnly: true})
			w.WriteHeader(http.StatusOK)
		case accountPath:
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	session, err := testClient(t, server).VerifyMFA(context.Background(), " 001103 ")
	if err != nil {
		t.Fatal(err)
	}
	if len(session.Cookies) != 1 || session.Cookies[0].Name != "CE_AUTH" {
		t.Fatalf("session = %#v", session)
	}
}

func TestVerifyMFARejectsInvalidCodeAndUnsafeRedirect(t *testing.T) {
	for _, tc := range []struct {
		name, response string
		want           error
	}{
		{"rejected", `{"code":false}`, ErrChallengeRequired},
		{"unsafe", `{"code":true,"authRedirectUrl":"https://evil.example/"}`, ErrProtocolChanged},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(tc.response)) }))
			defer server.Close()
			_, err := testClient(t, server).VerifyMFA(context.Background(), "123456")
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestResendMFAResponses(t *testing.T) {
	for _, tc := range []struct {
		status int
		want   error
	}{{http.StatusNoContent, nil}, {http.StatusTooManyRequests, ErrChallengeRequired}, {http.StatusInternalServerError, ErrProtocolChanged}} {
		t.Run(strconv.Itoa(tc.status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != resendMFAPath || r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
					t.Errorf("request = %s %s content-type=%q", r.Method, r.URL.Path, r.Header.Get("Content-Type"))
				}
				body, _ := io.ReadAll(r.Body)
				if string(body) != "{}" {
					t.Errorf("resend body = %q", body)
				}
				w.WriteHeader(tc.status)
			}))
			defer server.Close()
			err := testClient(t, server).ResendMFA(context.Background())
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestAuthenticationResponseErrors(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
		want       error
	}{
		{"invalid", `{"message":"invalid credentials"}`, http.StatusUnauthorized, ErrInvalidCredentials},
		{"mfa", `{"result":{"message":"MFA required"}}`, http.StatusOK, ErrMFARequired},
		{"challenge", `{"data":{"message":"challenge required"}}`, http.StatusOK, ErrChallengeRequired},
		{"unknown", `{"unexpected":"shape"}`, http.StatusOK, ErrProtocolChanged},
		{"malformed", `{`, http.StatusOK, ErrProtocolChanged},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				if tc.name == "invalid" {
					_, _ = w.Write([]byte(readFixture(t, "login_failure.json")))
				} else {
					_, _ = w.Write([]byte(tc.body))
				}
			}))
			defer server.Close()
			_, err := testClient(t, server).Authenticate(context.Background(), auth.Credentials{Email: "a@b", Password: "p"})
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestUnsafeRedirectAndRedirectToLogin(t *testing.T) {
	for _, tc := range []struct {
		name      string
		login     string
		authorize bool
		want      error
	}{
		{"unsafe host", `{"redirectUrl":"https://example.test/path"}`, false, ErrProtocolChanged},
		{"unsafe base port", `{"redirectUrl":"https://www.coned.com:8443/path"}`, false, ErrProtocolChanged},
		{"unsafe follow", ``, true, ErrProtocolChanged},
		{"login redirect", `{"url":"REPLACE/authorize"}`, false, ErrSessionExpired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var server *httptest.Server
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == loginPath {
					body := strings.ReplaceAll(tc.login, "REPLACE", server.URL)
					if tc.authorize {
						body = `{"url":"` + server.URL + `/authorize"}`
					}
					_, _ = w.Write([]byte(body))
					return
				}
				if r.URL.Path == "/authorize" {
					if tc.authorize {
						http.Redirect(w, r, "https://example.test/", http.StatusFound)
					} else {
						w.WriteHeader(http.StatusOK)
					}
					return
				}
				if r.URL.Path == accountPath {
					http.Redirect(w, r, "/en/login", http.StatusFound)
					return
				}
			}))
			defer server.Close()
			_, err := testClient(t, server).Authenticate(context.Background(), auth.Credentials{Email: "a@b", Password: "p"})
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestTimeoutAndCookieFilteringAndRestore(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == loginPath {
			time.Sleep(100 * time.Millisecond)
			_, _ = w.Write([]byte(`{}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	client, err := NewClient(Options{BaseURL: server.URL, Timeout: 10 * time.Millisecond, InsecureLoopbackForTests: true})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Authenticate(context.Background(), auth.Credentials{Email: "a@b", Password: "p"})
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, ErrProtocolChanged) {
		t.Fatalf("timeout = %v", err)
	}

	u, _ := url.Parse(server.URL)
	client.jar.SetCookies(u, []*http.Cookie{{Name: "CE_AUTH", Value: "value", Path: "/"}, {Name: "_ga", Value: "analytics", Path: "/"}, {Name: "language", Value: "en", Path: "/"}})
	session := client.ExportSession()
	if len(session.Cookies) != 1 || session.Cookies[0].Name != "CE_AUTH" {
		t.Fatalf("filtered cookies = %#v", session.Cookies)
	}
	restored := testClient(t, server)
	if err := restored.RestoreSession(session); err != nil {
		t.Fatal(err)
	}
	if got := restored.httpClient.Jar.Cookies(u); len(got) != 1 || got[0].Name != "CE_AUTH" || got[0].Value != "value" {
		t.Fatalf("restored cookies = %#v", got)
	}
}

func TestRestoreSessionIgnoresExpiredAllowedCookies(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	session := auth.Session{Cookies: []auth.Cookie{
		{Name: "CE_AUTH", Value: "live", Domain: u.Hostname(), Path: "/"},
		{Name: "CE_AUTH_TOKEN", Value: "expired", Domain: u.Hostname(), Path: "/", Expires: now.Add(-time.Second)},
	}}
	client := testClient(t, server)
	if err := client.RestoreSession(session); err != nil {
		t.Fatalf("RestoreSession() = %v", err)
	}
	cookies := client.httpClient.Jar.Cookies(u)
	if len(cookies) != 1 || cookies[0].Name != "CE_AUTH" || cookies[0].Value != "live" {
		t.Fatalf("restored cookies = %#v", cookies)
	}
	if err := testClient(t, server).RestoreSession(auth.Session{Cookies: session.Cookies[1:]}); !errors.Is(err, auth.ErrInvalidSession) {
		t.Fatalf("all-expired RestoreSession() = %v, want invalid session", err)
	}
}

func TestLogoutRemoteAttemptAndLocalClear(t *testing.T) {
	for _, tc := range []struct {
		status  int
		wantErr bool
	}{
		{http.StatusOK, false}, {http.StatusNoContent, false},
		{http.StatusUnauthorized, false}, {http.StatusNotFound, false},
		{http.StatusBadGateway, true},
	} {
		t.Run(strconv.Itoa(tc.status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodDelete || r.URL.Path != "/logout" || r.URL.RawQuery != "" {
					t.Errorf("request = %s %s", r.Method, r.URL.RequestURI())
				}
				if got, err := r.Cookie("CE_AUTH"); err != nil || got.Value != "remote-cookie" {
					t.Errorf("logout cookie = %v, %v", got, err)
				}
				body, _ := io.ReadAll(r.Body)
				if len(body) != 0 {
					t.Errorf("logout body = %q", body)
				}
				w.WriteHeader(tc.status)
			}))
			defer server.Close()
			client, err := NewClient(Options{BaseURL: server.URL, LogoutURL: server.URL + "/logout", InsecureLoopbackForTests: true})
			if err != nil {
				t.Fatal(err)
			}
			u, _ := url.Parse(server.URL)
			client.jar.SetCookies(u, []*http.Cookie{{Name: "CE_AUTH", Value: "remote-cookie", Path: "/"}})
			err = client.Logout(context.Background(), client.ExportSession())
			if tc.wantErr {
				if !errors.Is(err, auth.ErrLogoutFailed) {
					t.Fatalf("Logout() = %v, want safe logout error", err)
				}
			} else if err != nil {
				t.Fatalf("Logout() = %v", err)
			}
			if got := client.ExportSession(); len(got.Cookies) != 0 {
				t.Fatalf("cookies remained after logout: %#v", got)
			}
		})
	}
}

func TestLogoutClearsOnFailureAndHonorsCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	client, err := NewClient(Options{BaseURL: server.URL, LogoutURL: server.URL + "/logout", Timeout: time.Second, InsecureLoopbackForTests: true})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(server.URL)
	client.jar.SetCookies(u, []*http.Cookie{{Name: "CE_AUTH", Value: "value", Path: "/"}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := client.Logout(ctx, client.ExportSession()); !errors.Is(err, context.Canceled) {
		t.Fatalf("Logout cancellation = %v", err)
	}
	if got := client.ExportSession(); len(got.Cookies) != 0 {
		t.Fatalf("cookies remained after cancellation: %#v", got)
	}
	server.Close()
}

func TestProtocolErrorDiagnosticsAreSafe(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("x-ms-middleware-request-id", "safe-request_123")
		_, _ = w.Write([]byte(`{`))
	}))
	defer server.Close()
	_, err := testClient(t, server).Authenticate(context.Background(), auth.Credentials{Email: "a@b", Password: "p"})
	var protocol *ProtocolError
	if !errors.As(err, &protocol) || !errors.Is(err, ErrProtocolChanged) || protocol.Status != http.StatusOK || protocol.RequestID != "safe-request_123" {
		t.Fatalf("error = %#v", err)
	}
	if strings.Contains(err.Error(), "{") || strings.Contains(err.Error(), "a@b") {
		t.Fatalf("unsafe protocol error: %v", err)
	}
}

func TestCookieAllowlistAndStrictHostScope(t *testing.T) {
	client := NewDefaultClient()
	u, _ := url.Parse(defaultBaseURL)
	past := time.Now().Add(-time.Hour)
	client.jar.SetCookies(u, []*http.Cookie{
		{Name: "CE_AUTH", Value: "good", Path: "/"},
		{Name: "CE_AUTH_TOKEN", Value: "good", Path: "/"},
		{Name: "CE_SESSION_ID_COOKIE", Value: "good", Path: "/"},
		{Name: "CE_USER_ID", Value: "good", Path: "/"},
		{Name: "CE_MAID_AUTH", Value: "good", Path: "/"},
		{Name: "CE_ACCOUNT_FOCUS", Value: "good", Path: "/"},
		{Name: "CE_DEVICE_ID", Value: "good", Path: "/"},
		{Name: "CE_AUTH_TOKEN", Value: "parent", Domain: ".coned.com", Path: "/"},
		{Name: "CE_USER_ID", Value: "expired", Path: "/", Expires: past},
		{Name: "CE_DEVICE_ID", Value: "deleted", Path: "/", MaxAge: -1},
		{Name: "_ga", Value: "analytics", Path: "/"}, {Name: "language", Value: "en", Path: "/"},
	})
	session := client.ExportSession()
	if len(session.Cookies) != 5 { // expired CE_USER_ID and deleted CE_DEVICE_ID were removed.
		t.Fatalf("exported cookies = %#v", session.Cookies)
	}
	for _, cookie := range session.Cookies {
		if !allowedAuthCookie(cookie.Name) || cookie.Domain != "www.coned.com" {
			t.Fatalf("unexpected exported cookie = %#v", cookie)
		}
	}
	for name := range conedAuthCookies {
		probe := NewDefaultClient()
		probe.jar.SetCookies(u, []*http.Cookie{{Name: name, Value: "value", Path: "/"}})
		if got := probe.ExportSession().Cookies; len(got) != 1 || got[0].Name != name {
			t.Fatalf("allowlisted cookie %q was not exported: %#v", name, got)
		}
	}
	for _, cookie := range []auth.Cookie{
		{Name: "CE_AUTH", Value: "parent", Domain: "coned.com"},
		{Name: "CE_AUTH", Value: "expired", Domain: "www.coned.com", Expires: past},
		{Name: "language", Value: "en", Domain: "www.coned.com"},
	} {
		if err := NewDefaultClient().RestoreSession(auth.Session{Cookies: []auth.Cookie{cookie}}); !errors.Is(err, auth.ErrInvalidSession) {
			t.Fatalf("RestoreSession(%#v) = %v, want invalid session", cookie, err)
		}
	}
}

func TestConfirmationProtocolErrorDiagnostics(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case loginPath:
			_, _ = w.Write([]byte(strings.ReplaceAll(readFixture(t, "login_success.json"), "https://www.coned.com", server.URL)))
		case "/authorize":
			w.WriteHeader(http.StatusOK)
		case accountPath:
			w.Header().Set("Request-Id", "confirmation-123")
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer server.Close()
	_, err := testClient(t, server).Authenticate(context.Background(), auth.Credentials{Email: "a@b", Password: "p"})
	var protocol *ProtocolError
	if !errors.As(err, &protocol) || protocol.Status != http.StatusServiceUnavailable || protocol.RequestID != "confirmation-123" {
		t.Fatalf("confirmation error = %#v", err)
	}
}

func TestBaseAndRedirectSafety(t *testing.T) {
	for _, base := range []string{"http://www.coned.com", "https://example.test", "http://example.test", "https://user:password@www.coned.com", "https://www.coned.com?token=secret", "https://www.coned.com/untrusted"} {
		if _, err := NewClient(Options{BaseURL: base}); err == nil {
			t.Fatalf("NewClient accepted unsafe base %q", base)
		}
	}
	if _, err := NewClient(Options{BaseURL: "http://127.0.0.1:8080"}); err == nil {
		t.Fatal("NewClient accepted insecure loopback without test option")
	}
	if _, err := NewClient(Options{BaseURL: "http://127.0.0.1:8080", InsecureLoopbackForTests: true}); err != nil {
		t.Fatalf("NewClient rejected explicit loopback test base: %v", err)
	}
	client := NewDefaultClient()
	unsafe, _ := url.Parse("https://user:password@www.coned.com/authorize?state=synthetic")
	if client.allowedURL(unsafe) {
		t.Fatal("allowed redirect URL with userinfo")
	}
}
