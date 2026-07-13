// Package auth defines authentication data and contracts.
package auth

import (
	"context"
	"errors"
	"strings"
	"time"
)

var (
	// ErrInvalidCredentials indicates credentials that cannot be stored or used.
	ErrInvalidCredentials = errors.New("invalid credentials")
	// ErrInvalidSession indicates a session that cannot be stored.
	ErrInvalidSession = errors.New("invalid session")
	// ErrAuthenticationFailed indicates rejected credentials.
	ErrAuthenticationFailed = errors.New("authentication failed")
	// ErrNotImplemented is returned by the safe default authenticator.
	ErrNotImplemented = errors.New("authentication is not implemented")
	// ErrPasswordInputNotTerminal indicates that an interactive password was
	// requested from a non-terminal input.
	ErrPasswordInputNotTerminal = errors.New("interactive password input requires a terminal")
	// ErrInvalidPasswordStdin indicates malformed --password-stdin input.
	ErrInvalidPasswordStdin = errors.New("invalid password standard input")
	// ErrLogoutFailed reports a remote logout failure without exposing remote
	// response data or session secrets.
	ErrLogoutFailed = errors.New("remote logout failed")
	// ErrStorageFailed reports a secure-store operation failure without exposing
	// a backend error, which might contain credentials or session data.
	ErrStorageFailed = errors.New("secure storage operation failed")
	// ErrPromptFailed reports interactive prompt failure without exposing an
	// input-reader error, which might contain entered account data.
	ErrPromptFailed = errors.New("interactive prompt failed")
	// ErrPasswordReadFailed reports a terminal password reader failure without
	// exposing its potentially sensitive error detail.
	ErrPasswordReadFailed = errors.New("password read failed")
)

// Credentials are account secrets. They must only be serialized by this package's session-store helpers.
type Credentials struct {
	Email    string
	Password string
}

// Cookie represents a browser session cookie.
type Cookie struct {
	Name     string
	Value    string
	Domain   string
	Path     string
	Secure   bool
	HTTPOnly bool
	Expires  time.Time
}

// Session is an authenticated browser session. It must only be serialized by this package's session-store helpers.
type Session struct {
	Cookies         []Cookie
	AuthenticatedAt time.Time
	OpowerEntities  []string
}

// Authenticator authenticates credentials and may invalidate a remote session.
type Authenticator interface {
	Authenticate(context.Context, Credentials) (Session, error)
	Logout(context.Context, Session) error
}

// MFAAuthenticator completes a factor challenge started by Authenticate.
// Implementations keep challenge state only in memory for the current process.
type MFAAuthenticator interface {
	VerifyMFA(context.Context, string) (Session, error)
}

// MFAResender requests another code for the in-memory challenge.
type MFAResender interface {
	ResendMFA(context.Context) error
}

// SessionRestorer seeds device/session cookies before a credential login.
type SessionRestorer interface {
	RestoreSession(Session) error
}

// NotImplementedAuthenticator is the safe default until a service-specific
// authenticator is configured. It never performs network authentication.
type NotImplementedAuthenticator struct{}

func (NotImplementedAuthenticator) Authenticate(context.Context, Credentials) (Session, error) {
	return Session{}, ErrNotImplemented
}
func (NotImplementedAuthenticator) Logout(context.Context, Session) error { return ErrNotImplemented }

// ValidateCredentials rejects empty account secrets.
func ValidateCredentials(credentials Credentials) error {
	if strings.TrimSpace(credentials.Email) == "" || credentials.Password == "" {
		return ErrInvalidCredentials
	}
	return nil
}

// ValidateSession rejects sessions with missing cookie names or values.
func ValidateSession(session Session) error {
	if len(session.Cookies) == 0 {
		return ErrInvalidSession
	}
	for _, cookie := range session.Cookies {
		if cookie.Name == "" || cookie.Value == "" {
			return ErrInvalidSession
		}
	}
	return nil
}

// SessionState describes whether a session can currently be used.
type SessionState int

const (
	SessionInvalid SessionState = iota
	SessionExpired
	SessionValid
)

// State reports session validity. A non-expiring session cookie keeps a session
// valid; persistent cookies expire the session only when all of them have expired.
func (s Session) State(now time.Time) SessionState {
	if ValidateSession(s) != nil {
		return SessionInvalid
	}
	for _, cookie := range s.Cookies {
		if cookie.Expires.IsZero() || cookie.Expires.After(now) {
			return SessionValid
		}
	}
	return SessionExpired
}
