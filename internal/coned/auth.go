package coned

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/zzwong/coned-cli/internal/auth"
)

const (
	loginPath      = "/sitecore/api/ssc/ConEdWeb-Foundation-Login-Areas-LoginAPI/User/0/Login"
	verifyMFAPath  = "/sitecore/api/ssc/ConEdWeb-Foundation-Login-Areas-LoginAPI/User/0/VerifyFactor"
	resendMFAPath  = "/sitecore/api/ssc/ConEdWeb-Foundation-Login-Areas-LoginAPI/User/0/ResendMFACode"
	accountPath    = "/en/accounts-billing/my-account"
	authReturnPath = accountPath + "/energy-use"
)

// Authenticate signs in through Con Edison's supported JSON endpoint. It does
// not infer credentials or tokens from unstructured response data.
func (c *Client) Authenticate(ctx context.Context, credentials auth.Credentials) (auth.Session, error) {
	c.operationMu.Lock()
	defer c.operationMu.Unlock()
	if auth.ValidateCredentials(credentials) != nil {
		return auth.Session{}, ErrInvalidCredentials
	}
	payload := struct {
		LoginEmail       string `json:"LoginEmail"`
		LoginPassword    string `json:"LoginPassword"`
		LoginRememberMe  bool   `json:"LoginRememberMe"`
		ReturnURL        string `json:"ReturnUrl"`
		FromURI          string `json:"FromURI,omitempty"`
		OpenIDRelayState string `json:"OpenIdRelayState"`
	}{credentials.Email, credentials.Password, false, authReturnPath, "", ""}
	data, err := json.Marshal(payload)
	if err != nil {
		return auth.Session{}, ErrProtocolChanged
	}
	// Match the browser flow: clear any stale Okta session before starting a
	// credential exchange. The site treats 404 as an already-cleared session.
	resetURL, _ := url.Parse("https://coned.okta.com/api/v1/sessions/me")
	if reset, resetErr := c.request(ctx, stepOktaReset, http.MethodDelete, resetURL, nil, false); resetErr == nil {
		c.debugf("auth Okta reset response status=%d", reset.StatusCode)
		_ = reset.Body.Close()
	}
	c.debugf("auth login request started")
	response, err := c.request(ctx, stepLogin, http.MethodPost, c.endpoint(loginPath), bytes.NewReader(data), true)
	if err != nil {
		return auth.Session{}, err
	}
	defer func() { _ = response.Body.Close() }()
	c.debugf("auth login response status=%d", response.StatusCode)
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return auth.Session{}, c.transportFailure(ctx, stepLogin, err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return auth.Session{}, classifyResponse(response, body)
	}
	if challenge, ok := parseMFAChallenge(body); ok {
		c.debugf("auth MFA required new_device=%t resend_enabled=%t cooldown_ms=%d numeric=%t", challenge.NewDevice, challenge.ResendEnabled, challenge.WaitingTime, challenge.Numeric)
		return auth.Session{}, ErrMFARequired
	}
	next, err := c.parseAuthorizeURL(response, body)
	if err != nil {
		return auth.Session{}, err
	}
	if err := c.follow(ctx, next); err != nil {
		return auth.Session{}, err
	}
	if err := c.confirm(ctx); err != nil {
		return auth.Session{}, err
	}
	if c.debug != nil {
		c.jar.mu.Lock()
		for _, cookie := range c.jar.cookies {
			if allowedAuthCookie(cookie.Name) {
				c.debugf("auth cookie observed name=%s", cookie.Name)
			}
		}
		c.jar.mu.Unlock()
	}
	session := c.exportSession()
	if auth.ValidateSession(session) != nil || !hasAuthenticatedCookie(session) {
		c.debugf("auth confirmation did not retain an authenticated cookie")
		return auth.Session{}, ErrSessionExpired
	}
	session.AuthenticatedAt = time.Now()
	return session, nil
}

func (c *Client) request(ctx context.Context, step transportStep, method string, u *url.URL, body io.Reader, jsonRequest bool) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, c.transportFailure(ctx, step, err)
	}
	request.Header.Set("User-Agent", c.userAgent())
	request.Header.Set("Accept", "application/json")
	if strings.EqualFold(u.Host, c.base.Host) || strings.EqualFold(u.Host, "coned.okta.com") {
		request.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.7827.53 Safari/537.36")
		request.Header.Set("Referer", c.base.String()+"/")
		request.Header.Set("Sec-CH-UA", `"Google Chrome";v="149", "Chromium";v="149", "Not)A;Brand";v="24"`)
		request.Header.Set("Sec-CH-UA-Mobile", "?0")
		request.Header.Set("Sec-CH-UA-Platform", `"Linux"`)
		request.Header.Set("Sec-CH-UA-Arch", `"x86"`)
		request.Header.Set("Sec-CH-UA-Bitness", `"64"`)
		request.Header.Set("Sec-CH-UA-Full-Version-List", `"Google Chrome";v="149.0.7827.53", "Chromium";v="149.0.7827.53", "Not)A;Brand";v="24.0.0.0"`)
		request.Header.Set("Sec-CH-UA-Model", `""`)
		request.Header.Set("Sec-CH-UA-Platform-Version", `""`)
	}
	if jsonRequest {
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", strings.TrimSuffix(c.base.String(), "/"))
		request.Header.Set("X-Requested-With", "XMLHttpRequest")
		request.Header.Set("Sec-Fetch-Dest", "empty")
		request.Header.Set("Sec-Fetch-Mode", "cors")
		request.Header.Set("Sec-Fetch-Site", "same-origin")
	}
	if c.debug != nil {
		c.debugf("http request step=%s method=%s cookies_present=%t", safeTransportStep(step), method, len(c.jar.Cookies(u)) > 0)
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, c.transportFailure(ctx, step, err)
	}
	c.debugf("http response step=%s status=%d method=%s", safeTransportStep(step), response.StatusCode, method)
	if response.Header.Get("Location") != "" {
		c.debugf("http redirect received")
	}
	return response, err
}

type mfaChallenge struct {
	Login         bool `json:"login"`
	NewDevice     bool `json:"newDevice"`
	NoMFA         bool `json:"noMfa"`
	ResendEnabled bool `json:"enableResendMfaCode"`
	WaitingTime   int  `json:"waitingTime"`
	Numeric       bool `json:"isNumeric"`
}

func parseMFAChallenge(body []byte) (mfaChallenge, bool) {
	var response mfaChallenge
	err := json.Unmarshal(body, &response)
	return response, err == nil && response.Login && response.NewDevice && !response.NoMFA
}

// ResendMFA requests another code without restarting the credential login.
func (c *Client) ResendMFA(ctx context.Context) error {
	c.operationMu.Lock()
	defer c.operationMu.Unlock()
	c.debugf("auth MFA resend request started")
	response, err := c.request(ctx, stepMFAResend, http.MethodPost, c.endpoint(resendMFAPath), strings.NewReader("{}"), true)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	c.debugf("auth MFA resend response status=%d", response.StatusCode)
	if _, err := io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20)); err != nil {
		return c.transportFailure(ctx, stepMFAResend, err)
	}
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		return nil
	}
	if response.StatusCode == http.StatusTooManyRequests {
		return ErrChallengeRequired
	}
	return protocolError(response)
}

// VerifyMFA completes an in-memory new-device challenge started by Authenticate.
func (c *Client) VerifyMFA(ctx context.Context, code string) (auth.Session, error) {
	c.operationMu.Lock()
	defer c.operationMu.Unlock()
	code = strings.TrimSpace(code)
	if code == "" {
		return auth.Session{}, ErrChallengeRequired
	}
	payload := struct {
		MFACode          string `json:"MFACode"`
		ReturnURL        string `json:"ReturnUrl"`
		FromURI          string `json:"FromURI,omitempty"`
		OpenIDRelayState string `json:"OpenIdRelayState"`
	}{code, authReturnPath, "", ""}
	data, err := json.Marshal(payload)
	if err != nil {
		return auth.Session{}, ErrProtocolChanged
	}
	c.debugf("auth MFA verification request started")
	response, err := c.request(ctx, stepMFAVerify, http.MethodPost, c.endpoint(verifyMFAPath), bytes.NewReader(data), true)
	if err != nil {
		return auth.Session{}, err
	}
	defer func() { _ = response.Body.Close() }()
	c.debugf("auth MFA verification response status=%d", response.StatusCode)
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return auth.Session{}, c.transportFailure(ctx, stepMFAVerify, err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return auth.Session{}, classifyResponse(response, body)
	}
	var result struct {
		Code            bool   `json:"code"`
		AuthRedirectURL string `json:"authRedirectUrl"`
	}
	if json.Unmarshal(body, &result) != nil {
		c.debugf("auth MFA verification response malformed")
		return auth.Session{}, ErrChallengeRequired
	}
	c.debugf("auth MFA verification accepted=%t redirect_present=%t", result.Code, result.AuthRedirectURL != "")
	if !result.Code || result.AuthRedirectURL == "" {
		return auth.Session{}, ErrChallengeRequired
	}
	next, err := url.Parse(result.AuthRedirectURL)
	if err != nil || !next.IsAbs() || !c.allowedURL(next) {
		return auth.Session{}, ErrProtocolChanged
	}
	if err := c.follow(ctx, next); err != nil {
		return auth.Session{}, err
	}
	if err := c.confirm(ctx); err != nil {
		return auth.Session{}, err
	}
	session := c.exportSession()
	if auth.ValidateSession(session) != nil || !hasAuthenticatedCookie(session) {
		c.debugf("auth confirmation did not retain an authenticated cookie")
		return auth.Session{}, ErrSessionExpired
	}
	session.AuthenticatedAt = time.Now()
	return session, nil
}

func hasAuthenticatedCookie(session auth.Session) bool {
	for _, cookie := range session.Cookies {
		if cookie.Name == "CE_AUTH" || cookie.Name == "CE_AUTH_TOKEN" {
			return true
		}
	}
	return false
}

func (c *Client) parseAuthorizeURL(response *http.Response, body []byte) (*url.URL, error) {
	var value any
	if json.Unmarshal(body, &value) != nil {
		return nil, protocolError(response)
	}
	candidate, ok := findRedirect(value)
	if !ok {
		return nil, classifyResponse(response, body)
	}
	u, err := url.Parse(candidate)
	if err != nil || !u.IsAbs() || !c.allowedURL(u) {
		return nil, protocolError(response)
	}
	if token, ok := findSessionToken(value); ok && u.Query().Get("sessionToken") == "" {
		query := u.Query()
		query.Set("sessionToken", token)
		u.RawQuery = query.Encode()
	}
	return u, nil
}

// findRedirect accepts only documented URL property names. Its precedence is
// deterministic: redirectUrl, redirectUri, authorizeUrl, then url; within an
// envelope matching is case-insensitive, and data is considered before result.
func findRedirect(value any) (string, bool) {
	return findEnvelopeString(value, "authredirecturl", "nomfaredirecturl", "redirecturl", "redirecturi", "authorizeurl", "url")
}

func findSessionToken(value any) (string, bool) {
	return findEnvelopeString(value, "sessiontoken", "oktasessiontoken")
}

func findEnvelopeString(value any, names ...string) (string, bool) {
	object, ok := value.(map[string]any)
	if !ok {
		return "", false
	}
	for _, name := range names {
		// Prefer an exact spelling. This also gives duplicate case variants a
		// deterministic result without relying on Go map iteration order.
		if text, ok := object[name].(string); ok && text != "" {
			return text, true
		}
		keys := make([]string, 0)
		for key := range object {
			if key != name && strings.EqualFold(key, name) {
				keys = append(keys, key)
			}
		}
		sort.Strings(keys)
		for _, key := range keys {
			if text, ok := object[key].(string); ok && text != "" {
				return text, true
			}
		}
	}
	for _, envelope := range []string{"data", "result"} {
		keys := make([]string, 0)
		for key := range object {
			if strings.EqualFold(key, envelope) {
				keys = append(keys, key)
			}
		}
		sort.Strings(keys)
		for _, key := range keys {
			if text, ok := findEnvelopeString(object[key], names...); ok {
				return text, true
			}
		}
	}
	return "", false
}

func classifyResponse(response *http.Response, body []byte) error {
	text := strings.ToLower(string(body))
	switch {
	case strings.Contains(text, "mfa") || strings.Contains(text, "multi-factor") || strings.Contains(text, "multifactor"):
		return ErrMFARequired
	case strings.Contains(text, "challenge"):
		return ErrChallengeRequired
	case response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden || strings.Contains(text, "invalid credential") || strings.Contains(text, "invalid password") || strings.Contains(text, "invalid login"):
		return ErrInvalidCredentials
	default:
		return protocolError(response)
	}
}

func (c *Client) allowedURL(u *url.URL) bool {
	if u == nil || u.Host == "" || u.User != nil {
		return false
	}
	// Match Host rather than Hostname so a redirect cannot change the port.
	if strings.EqualFold(u.Host, c.base.Host) {
		return u.Scheme == c.base.Scheme && (u.Scheme == "https" || c.insecureLoopbackForTests && isLoopbackHost(u.Hostname()))
	}
	return strings.EqualFold(u.Host, "coned.okta.com") && u.Scheme == "https"
}

// follow handles a bounded redirect chain manually so every destination is
// host-validated while preserving service-provided state and nonce parameters.
func (c *Client) follow(ctx context.Context, next *url.URL) error {
	for redirects := 0; redirects < 10; redirects++ {
		if !c.allowedURL(next) {
			return ErrProtocolChanged
		}
		requestCookies := c.jar.Cookies(next)
		c.debugf("auth redirect request cookies_present=%t", len(requestCookies) > 0)
		response, err := c.request(ctx, stepRedirect, http.MethodGet, next, nil, false)
		if err != nil {
			return err
		}
		_ = response.Body.Close()
		c.debugf("auth redirect response status=%d", response.StatusCode)
		for _, cookie := range response.Cookies() {
			c.debugf("auth redirect set-cookie recognized=%t", allowedAuthCookie(cookie.Name))
		}
		if response.StatusCode >= 200 && response.StatusCode < 300 {
			return nil
		}
		if response.StatusCode < 300 || response.StatusCode >= 400 {
			return protocolError(response)
		}
		location, err := response.Location()
		if err != nil {
			return protocolError(response)
		}
		next = response.Request.URL.ResolveReference(location)
	}
	return ErrProtocolChanged
}

// ValidateAuthenticatedSession verifies a session against the account page.
func (c *Client) ValidateAuthenticatedSession(ctx context.Context, session auth.Session) error {
	c.operationMu.Lock()
	defer c.operationMu.Unlock()
	if err := c.restoreSession(session); err != nil {
		return ErrSessionExpired
	}
	return c.confirm(ctx)
}

func (c *Client) confirm(ctx context.Context) error {
	response, err := c.request(ctx, stepSessionCheck, http.MethodGet, c.endpoint(accountPath), nil, false)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	c.debugf("auth confirmation response status=%d", response.StatusCode)
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		location, err := response.Location()
		if err != nil {
			return protocolError(response)
		}
		if strings.Contains(strings.ToLower(location.Path), "/en/login") {
			return ErrSessionExpired
		}
		return protocolError(response)
	}
	if strings.Contains(strings.ToLower(response.Request.URL.Path), "/en/login") {
		return ErrSessionExpired
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return protocolError(response)
	}
	return nil
}

// Logout asks the service to invalidate the remote session, then clears this
// process's browser cookies regardless of the HTTP result.
func (c *Client) Logout(ctx context.Context, session auth.Session) error {
	c.operationMu.Lock()
	defer c.operationMu.Unlock()
	jar, err := newTrackedJar()
	if err != nil {
		return auth.ErrLogoutFailed
	}
	defer func() {
		c.jar, c.httpClient.Jar = jar, jar
	}()

	request, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.logoutURL.String(), nil)
	if err != nil {
		return auth.ErrLogoutFailed
	}
	request.Header.Set("User-Agent", c.userAgent())
	request.Header.Set("Accept", "application/json")
	for _, cookie := range session.Cookies {
		if allowedAuthCookie(cookie.Name) && cookie.Value != "" {
			request.AddCookie(&http.Cookie{Name: cookie.Name, Value: cookie.Value})
		}
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return auth.ErrLogoutFailed
	}
	_ = response.Body.Close()
	if (response.StatusCode >= 200 && response.StatusCode < 300) || response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusNotFound {
		return nil
	}
	return auth.ErrLogoutFailed
}

var _ auth.Authenticator = (*Client)(nil)
