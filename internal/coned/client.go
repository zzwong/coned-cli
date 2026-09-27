package coned

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/zzwong/coned-cli/internal/auth"
)

const (
	defaultBaseURL   = "https://www.coned.com"
	defaultLogoutURL = "https://coned.okta.com/api/v1/sessions/me"
)

// Options controls a Client. A zero value uses the production base URL and a
// 30 second timeout. InsecureLoopbackForTests is solely for deterministic
// local HTTP test servers; it must never be used for production traffic.
type Options struct {
	BaseURL                  string
	Version                  string
	Transport                http.RoundTripper
	Timeout                  time.Duration
	InsecureLoopbackForTests bool
	// LogoutURL overrides the production remote logout endpoint. In production it
	// must be exactly https://coned.okta.com/api/v1/sessions/me. Loopback HTTP
	// or HTTPS URLs are accepted only with InsecureLoopbackForTests.
	LogoutURL   string
	DebugWriter io.Writer
}

// Client is a stateful HTTP client. Its cookie jar is intentionally private so
// callers cannot accidentally serialize every browser cookie.
type Client struct {
	httpClient               *http.Client
	base                     *url.URL
	version                  string
	jar                      *trackedJar
	logoutURL                *url.URL
	insecureLoopbackForTests bool
	// operationMu serializes all public operations that access or replace the
	// stateful cookie jar. It is held across requests, but never acquired by
	// request/redirect helpers, preventing recursive-lock deadlocks.
	operationMu sync.Mutex
	debug       io.Writer
}

// NewDefaultClient constructs the production client. Its construction cannot
// fail because the built-in base URL is a constant.
func NewDefaultClient() *Client {
	client, err := NewClient(Options{})
	if err != nil {
		panic(err)
	}
	return client
}

// NewClient creates a client with manual redirect handling and an isolated
// in-memory cookie jar.
func NewClient(options Options) (*Client, error) {
	baseText := options.BaseURL
	if baseText == "" {
		baseText = defaultBaseURL
	}
	base, err := url.Parse(baseText)
	if err != nil || base.Scheme == "" || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return nil, errors.New("invalid Con Edison base URL")
	}
	base.Path = strings.TrimRight(base.Path, "/")
	if !validBaseURL(base, options.InsecureLoopbackForTests) {
		return nil, errors.New("invalid Con Edison base URL")
	}
	logoutText := options.LogoutURL
	if logoutText == "" {
		logoutText = defaultLogoutURL
	}
	logoutURL, err := url.Parse(logoutText)
	if err != nil || !validLogoutURL(logoutURL, options.InsecureLoopbackForTests) {
		return nil, errors.New("invalid Con Edison logout URL")
	}
	jar, err := newTrackedJar()
	if err != nil {
		return nil, err
	}
	timeout := options.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	transport := options.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	debug := options.DebugWriter
	if debug == nil && os.Getenv("CONED_DEBUG") == "1" {
		debug = os.Stderr
	}
	return &Client{base: base, version: options.Version, jar: jar, logoutURL: logoutURL, insecureLoopbackForTests: options.InsecureLoopbackForTests, debug: debug, httpClient: &http.Client{
		Transport: transport, Timeout: timeout, Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

func validLogoutURL(u *url.URL, insecureLoopback bool) bool {
	if u == nil || u.User != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	if insecureLoopback && isLoopbackHost(u.Hostname()) && (u.Scheme == "http" || u.Scheme == "https") {
		return true
	}
	return u.Scheme == "https" && strings.EqualFold(u.Host, "coned.okta.com") && u.Path == "/api/v1/sessions/me"
}

func validBaseURL(base *url.URL, insecureLoopback bool) bool {
	if base.User != nil || base.Path != "" {
		return false
	}
	if strings.EqualFold(base.Scheme, "https") && strings.EqualFold(base.Host, "www.coned.com") {
		return true
	}
	return insecureLoopback && isLoopbackHost(base.Hostname()) && (base.Scheme == "http" || base.Scheme == "https")
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (c *Client) debugf(format string, args ...any) {
	if c.debug != nil {
		_, _ = fmt.Fprintf(c.debug, "coned debug: "+format+"\n", args...)
	}
}

func (c *Client) userAgent() string {
	version := c.version
	if version == "" {
		version = "dev"
	}
	return "coned-cli/" + version
}

func (c *Client) endpoint(path string) *url.URL {
	u := *c.base
	u.Path = strings.TrimRight(c.base.Path, "/") + path
	u.RawQuery = ""
	u.Fragment = ""
	return &u
}

// ExportSession returns only the explicit Con Edison authentication-cookie
// allowlist for the exact configured host.
func (c *Client) ExportSession() auth.Session {
	c.operationMu.Lock()
	defer c.operationMu.Unlock()
	return c.exportSession()
}

func (c *Client) exportSession() auth.Session { return auth.Session{Cookies: c.jar.export(c.base)} }

// RestoreSession loads only allowed, live, exact-host cookies into a fresh jar.
// Expired allowed cookies are ignored, as they are by auth.Session.State.
func (c *Client) RestoreSession(session auth.Session) error {
	c.operationMu.Lock()
	defer c.operationMu.Unlock()
	return c.restoreSession(session)
}

// VerifySession asks Con Edison whether session is still live. The local
// expiry only bounds a session's lifetime; the provider can end it sooner.
func (c *Client) VerifySession(ctx context.Context, session auth.Session) error {
	c.operationMu.Lock()
	defer c.operationMu.Unlock()
	if session.State(time.Now()) != auth.SessionValid {
		return ErrSessionExpired
	}
	// Check with the stored cookies in a jar of their own, so a session the
	// provider rejects cannot leak into a login that follows.
	jar := c.jar
	defer func() { c.jar, c.httpClient.Jar = jar, jar }()
	if c.restoreSession(session) != nil {
		return ErrSessionExpired
	}
	_, err := c.mintOpowerToken(ctx)
	return err
}

// restoreSession is called only while operationMu is held.
func (c *Client) restoreSession(session auth.Session) error {
	if err := auth.ValidateSession(session); err != nil {
		return err
	}
	host := strings.ToLower(c.base.Hostname())
	now := time.Now()
	cookies := make([]*http.Cookie, 0, len(session.Cookies))
	for _, cookie := range session.Cookies {
		if !allowedAuthCookie(cookie.Name) || strings.TrimPrefix(strings.ToLower(cookie.Domain), ".") != host {
			return auth.ErrInvalidSession
		}
		if !cookie.Expires.IsZero() && !cookie.Expires.After(now) {
			continue
		}
		cookies = append(cookies, &http.Cookie{Name: cookie.Name, Value: cookie.Value, Domain: cookie.Domain, Path: cookie.Path, Secure: cookie.Secure, HttpOnly: cookie.HTTPOnly, Expires: cookie.Expires})
	}
	if len(cookies) == 0 {
		return auth.ErrInvalidSession
	}
	jar, err := newTrackedJar()
	if err != nil {
		return ErrProtocolChanged
	}
	jar.SetCookies(c.base, cookies)
	c.jar, c.httpClient.Jar = jar, jar
	return nil
}

type trackedJar struct {
	jar     http.CookieJar
	mu      sync.Mutex
	cookies map[string]auth.Cookie
}

func newTrackedJar() (*trackedJar, error) {
	jar, err := cookiejar.New(nil)
	return &trackedJar{jar: jar, cookies: make(map[string]auth.Cookie)}, err
}
func (j *trackedJar) Cookies(u *url.URL) []*http.Cookie { return j.jar.Cookies(u) }
func (j *trackedJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	j.jar.SetCookies(u, cookies)
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, c := range cookies {
		if c == nil || c.Name == "" {
			continue
		}
		domain := strings.TrimPrefix(strings.ToLower(c.Domain), ".")
		if domain == "" {
			domain = strings.ToLower(u.Hostname())
		}
		path := c.Path
		if path == "" {
			path = defaultCookiePath(u.Path)
		}
		key := domain + "\x00" + path + "\x00" + c.Name
		if c.MaxAge < 0 || c.Value == "" || (!c.Expires.IsZero() && !c.Expires.After(time.Now())) {
			delete(j.cookies, key)
			continue
		}
		j.cookies[key] = auth.Cookie{Name: c.Name, Value: c.Value, Domain: domain, Path: path, Secure: c.Secure, HTTPOnly: c.HttpOnly, Expires: c.Expires}
	}
}
func defaultCookiePath(requestPath string) string {
	if requestPath == "" || requestPath[0] != '/' || strings.Count(requestPath, "/") <= 1 {
		return "/"
	}
	return requestPath[:strings.LastIndex(requestPath, "/")]
}

var conedAuthCookies = map[string]struct{}{
	"CE_AUTH": {}, "CE_AUTH_TOKEN": {}, "CE_SESSION_ID_COOKIE": {}, "CE_USER_ID": {},
	"CE_MAID_AUTH": {}, "CE_ACCOUNT_FOCUS": {}, "CE_DEVICE_ID": {}, "CE_PREF_LANG": {},
	"CE_SUGG_TILE_COOKIE": {}, "OPOWER_AUTH_TOKEN": {},
}

func allowedAuthCookie(name string) bool {
	_, ok := conedAuthCookies[name]
	return ok
}

func (j *trackedJar) export(base *url.URL) []auth.Cookie {
	host := strings.ToLower(base.Hostname())
	now := time.Now()
	j.mu.Lock()
	defer j.mu.Unlock()
	out := make([]auth.Cookie, 0)
	for _, c := range j.cookies {
		if c.Value == "" || !c.Expires.IsZero() && !c.Expires.After(now) || c.Domain != host || !allowedAuthCookie(c.Name) {
			continue
		}
		out = append(out, c)
	}
	return out
}
