package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zzwong/coned-cli/internal/auth"
	"github.com/zzwong/coned-cli/internal/coned"
	"github.com/zzwong/coned-cli/internal/securestore"
)

type fakeAuthenticator struct {
	calls       int
	logoutCalls int
	credentials auth.Credentials
	session     auth.Session
	err         error
	logoutErr   error
}

func (a *fakeAuthenticator) Authenticate(_ context.Context, credentials auth.Credentials) (auth.Session, error) {
	a.calls++
	a.credentials = credentials
	if a.err != nil {
		return auth.Session{}, a.err
	}
	return a.session, nil
}
func (a *fakeAuthenticator) Logout(context.Context, auth.Session) error {
	a.logoutCalls++
	return a.logoutErr
}

type fakePrompter struct {
	email                           string
	mfaCode                         string
	save                            bool
	emailCalls, mfaCalls, saveCalls int
	emailErr, mfaErr, saveErr       error
}

func (p *fakePrompter) Email() (string, error) {
	p.emailCalls++
	return p.email, p.emailErr
}
func (p *fakePrompter) MFACode() (string, error) {
	p.mfaCalls++
	return p.mfaCode, p.mfaErr
}
func (p *fakePrompter) ConfirmSave() (bool, error) {
	p.saveCalls++
	return p.save, p.saveErr
}

type fakeTerminal struct {
	terminal  bool
	password  string
	err       error
	readCalls int
}

func (t *fakeTerminal) IsTerminal(io.Reader) bool { return t.terminal }
func (t *fakeTerminal) ReadPassword(io.Reader) ([]byte, error) {
	t.readCalls++
	return []byte(t.password), t.err
}

type failingStore struct {
	securestore.Store
	getErr, setErr, deleteErr error
	getKey                    string
}

func (s failingStore) Get(profile, key string) ([]byte, error) {
	if s.getErr != nil && (s.getKey == "" || s.getKey == key) {
		return nil, s.getErr
	}
	return s.Store.Get(profile, key)
}
func (s failingStore) Set(profile, key string, value []byte) error {
	if s.setErr != nil {
		return s.setErr
	}
	return s.Store.Set(profile, key, value)
}
func (s failingStore) Delete(profile, key string) error {
	if s.deleteErr != nil {
		return s.deleteErr
	}
	return s.Store.Delete(profile, key)
}

func validSession(now time.Time) auth.Session {
	return auth.Session{Cookies: []auth.Cookie{{Name: "sid", Value: "secret-cookie"}}, AuthenticatedAt: now}
}

func run(t *testing.T, store securestore.Store, authenticator *fakeAuthenticator, prompt *fakePrompter, input, args string) (string, error) {
	t.Helper()
	return runWithDependencies(t, Dependencies{
		Store: store, Authenticator: authenticator, Clock: func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) }, Prompter: prompt, PasswordTerminal: &fakeTerminal{},
	}, input, args)
}

func runWithDependencies(t *testing.T, deps Dependencies, input, args string) (string, error) {
	t.Helper()
	var out, errOut bytes.Buffer
	cmd := NewRootCommandWithDependencies(strings.NewReader(input), &out, &errOut, deps)
	cmd.SetArgs(strings.Fields(args))
	err := cmd.Execute()
	return out.String() + errOut.String(), err
}

func TestLoginNoStoreAndPasswordStdin(t *testing.T) {
	store := securestore.NewMemoryStore()
	a := &fakeAuthenticator{session: validSession(time.Now())}
	p := &fakePrompter{email: "person@example.test", save: true}
	output, err := run(t, store, a, p, "passphrase\n", "auth login --no-store --password-stdin")
	if err != nil {
		t.Fatal(err)
	}
	if a.credentials.Password != "passphrase" || a.credentials.Email != "person@example.test" {
		t.Fatalf("unexpected credentials: %#v", a.credentials)
	}
	if p.saveCalls != 0 {
		t.Fatal("no-store prompted to save")
	}
	if _, err := auth.LoadSession(store, "default"); !errors.Is(err, securestore.ErrNotFound) {
		t.Fatalf("session persisted: %v", err)
	}
	if strings.Contains(output, "passphrase") || strings.Contains(output, "person@example.test") || strings.Contains(output, "secret-cookie") {
		t.Fatalf("secret leaked in output: %q", output)
	}
}

func TestPasswordStdinPromptsForEmail(t *testing.T) {
	store := securestore.NewMemoryStore()
	a := &fakeAuthenticator{session: validSession(time.Now())}
	p := &fakePrompter{email: "person@example.test", save: false}
	if _, err := run(t, store, a, p, "password\n", "auth login --no-store --password-stdin"); err != nil {
		t.Fatal(err)
	}
	if p.emailCalls != 1 || a.credentials.Email != "person@example.test" || a.credentials.Password != "password" {
		t.Fatalf("stdin/password handling failed: prompts=%d credentials=%#v", p.emailCalls, a.credentials)
	}
}

func TestNoStoreUsesStoredCredentialsWithoutPersisting(t *testing.T) {
	base := securestore.NewMemoryStore()
	stored := auth.Credentials{Email: "stored@example.test", Password: "stored-secret"}
	if err := auth.SaveCredentials(base, "default", stored); err != nil {
		t.Fatal(err)
	}
	store := failingStore{Store: base, setErr: errors.New("unexpected persistence")}
	a := &fakeAuthenticator{session: validSession(time.Now())}
	p := &fakePrompter{}
	if _, err := run(t, store, a, p, "", "auth login --no-store"); err != nil {
		t.Fatal(err)
	}
	if a.calls != 1 || a.credentials != stored || p.emailCalls != 0 {
		t.Fatalf("stored credentials not used: calls=%d credentials=%#v prompts=%d", a.calls, a.credentials, p.emailCalls)
	}
	if _, err := auth.LoadSession(base, "default"); !errors.Is(err, securestore.ErrNotFound) {
		t.Fatalf("session persisted: %v", err)
	}
}

func TestInteractivePasswordRequiresTerminal(t *testing.T) {
	deps := Dependencies{Store: securestore.NewMemoryStore(), Authenticator: &fakeAuthenticator{}, Clock: time.Now, Prompter: &fakePrompter{email: "person@example.test"}, PasswordTerminal: &fakeTerminal{terminal: false}}
	_, err := runWithDependencies(t, deps, "", "auth login --no-store")
	if !errors.Is(err, auth.ErrPasswordInputNotTerminal) {
		t.Fatalf("error = %v, want %v", err, auth.ErrPasswordInputNotTerminal)
	}
}

func TestAuthInitResolution(t *testing.T) {
	t.Run("stored session", func(t *testing.T) {
		store := securestore.NewMemoryStore()
		if err := auth.SaveSession(store, "default", validSession(time.Now())); err != nil {
			t.Fatal(err)
		}
		a := &fakeAuthenticator{}
		if _, err := run(t, store, a, &fakePrompter{}, "", "auth init"); err != nil {
			t.Fatal(err)
		}
		if a.calls != 0 {
			t.Fatalf("authentication called %d times", a.calls)
		}
	})

	t.Run("force stored credentials", func(t *testing.T) {
		store := securestore.NewMemoryStore()
		stored := auth.Credentials{Email: "stored@example.test", Password: "stored-secret"}
		if err := auth.SaveSession(store, "default", validSession(time.Now())); err != nil {
			t.Fatal(err)
		}
		if err := auth.SaveCredentials(store, "default", stored); err != nil {
			t.Fatal(err)
		}
		a := &fakeAuthenticator{session: validSession(time.Now())}
		if _, err := run(t, store, a, &fakePrompter{}, "", "auth init --force"); err != nil {
			t.Fatal(err)
		}
		if a.calls != 1 || a.credentials != stored {
			t.Fatalf("stored credentials not used: calls=%d credentials=%#v", a.calls, a.credentials)
		}
	})

	t.Run("prompt fallback", func(t *testing.T) {
		store := securestore.NewMemoryStore()
		a := &fakeAuthenticator{session: validSession(time.Now())}
		p := &fakePrompter{email: "prompt@example.test"}
		if _, err := run(t, store, a, p, "prompt-secret\n", "auth init --no-store --password-stdin"); err != nil {
			t.Fatal(err)
		}
		if a.credentials != (auth.Credentials{Email: "prompt@example.test", Password: "prompt-secret"}) || p.emailCalls != 1 {
			t.Fatalf("prompt fallback failed: credentials=%#v prompts=%d", a.credentials, p.emailCalls)
		}
	})
}

func TestPasswordStdinReadsBufferedEmailThenPassword(t *testing.T) {
	store := securestore.NewMemoryStore()
	a := &fakeAuthenticator{session: validSession(time.Now())}
	var out, errOut bytes.Buffer
	cmd := NewRootCommandWithDependencies(strings.NewReader("person@example.test\npassword\n"), &out, &errOut, Dependencies{
		Store: store, Authenticator: a, Clock: time.Now, PasswordTerminal: &fakeTerminal{},
	})
	cmd.SetArgs([]string{"auth", "login", "--no-store", "--password-stdin"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if a.credentials.Email != "person@example.test" || a.credentials.Password != "password" {
		t.Fatalf("credentials = %#v", a.credentials)
	}
}

func TestPasswordStdinRequiresOneTerminatedLine(t *testing.T) {
	store := securestore.NewMemoryStore()
	a := &fakeAuthenticator{session: validSession(time.Now())}
	p := &fakePrompter{email: "a@b"}
	_, err := run(t, store, a, p, "password", "auth login --password-stdin --no-store")
	if !errors.Is(err, auth.ErrInvalidPasswordStdin) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestReadPasswordStdinConsumesExactlyOneLine(t *testing.T) {
	input := bufio.NewReader(strings.NewReader("password\nsecond line\n"))
	password, err := readPasswordStdin(input)
	if err != nil || password != "password" {
		t.Fatalf("got password=%q err=%v", password, err)
	}
	remaining, err := input.ReadString('\n')
	if err != nil || remaining != "second line\n" {
		t.Fatalf("password reader consumed remaining input: %q, %v", remaining, err)
	}
}

func TestInvalidStoredSessionFallsThroughToCredentials(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{name: "corrupt", data: []byte(`{"Cookies":[`)},
		{name: "invalid", data: []byte(`{"Cookies":[{"Name":"sid"}]}`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := securestore.NewMemoryStore()
			stored := auth.Credentials{Email: "stored@example.test", Password: "stored-secret"}
			if err := auth.SaveCredentials(store, "default", stored); err != nil {
				t.Fatal(err)
			}
			if err := store.Set("default", "session", tc.data); err != nil {
				t.Fatal(err)
			}
			a := &fakeAuthenticator{session: validSession(time.Now())}
			p := &fakePrompter{email: "prompt@example.test"}
			output, err := run(t, store, a, p, "unused\n", "auth login")
			if err != nil {
				t.Fatal(err)
			}
			if a.calls != 1 || a.credentials != stored || p.emailCalls != 0 {
				t.Fatalf("fallthrough failed: calls=%d credentials=%#v email prompts=%d", a.calls, a.credentials, p.emailCalls)
			}
			if strings.Contains(output, "stored-secret") || strings.Contains(output, "prompt@example.test") {
				t.Fatalf("secret leaked in output: %q", output)
			}
		})
	}
}

func TestInvalidStoredCredentialsFallsThroughToPrompt(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{name: "corrupt", data: []byte(`{"Email":"person@example.test"`)},
		{name: "invalid", data: []byte(`{"Email":"person@example.test"}`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := securestore.NewMemoryStore()
			if err := store.Set("default", "credentials", tc.data); err != nil {
				t.Fatal(err)
			}
			a := &fakeAuthenticator{session: validSession(time.Now())}
			p := &fakePrompter{email: "prompt@example.test"}
			output, err := run(t, store, a, p, "prompt-secret\n", "auth login --password-stdin")
			if err != nil {
				t.Fatal(err)
			}
			if a.calls != 1 || a.credentials.Email != p.email || a.credentials.Password != "prompt-secret" || p.emailCalls != 1 {
				t.Fatalf("prompt fallthrough failed: calls=%d credentials=%#v email prompts=%d", a.calls, a.credentials, p.emailCalls)
			}
			if strings.Contains(output, "prompt-secret") || strings.Contains(output, "prompt@example.test") {
				t.Fatalf("secret leaked in output: %q", output)
			}
		})
	}
}

func TestStoredSessionReuseAndForce(t *testing.T) {
	store := securestore.NewMemoryStore()
	now := time.Now()
	if err := auth.SaveSession(store, "default", validSession(now)); err != nil {
		t.Fatal(err)
	}
	a := &fakeAuthenticator{session: validSession(now)}
	p := &fakePrompter{email: "a@b", save: false}
	if _, err := run(t, store, a, p, "new\n", "auth login"); err != nil {
		t.Fatal(err)
	}
	if a.calls != 0 {
		t.Fatalf("authentication called %d times despite valid session", a.calls)
	}
	if _, err := run(t, store, a, p, "new\n", "auth login --force --password-stdin"); err != nil {
		t.Fatal(err)
	}
	if a.calls != 1 {
		t.Fatalf("force did not authenticate: %d", a.calls)
	}
}

func TestProfileIsolationAndInitPrompts(t *testing.T) {
	store := securestore.NewMemoryStore()
	now := time.Now()
	if err := auth.SaveCredentials(store, "one", auth.Credentials{Email: "one@test", Password: "one"}); err != nil {
		t.Fatal(err)
	}
	if err := auth.SaveSession(store, "one", validSession(now)); err != nil {
		t.Fatal(err)
	}
	a := &fakeAuthenticator{session: validSession(now)}
	p := &fakePrompter{email: "two@test", save: true}
	if _, err := run(t, store, a, p, "two\n", "--profile two auth login --password-stdin"); err != nil {
		t.Fatal(err)
	}
	if a.credentials.Email != "two@test" {
		t.Fatalf("wrong profile credentials: %#v", a.credentials)
	}
	if _, err := run(t, store, a, p, "", "--profile one auth init"); err != nil {
		t.Fatal(err)
	}
	if a.calls != 1 || p.emailCalls != 1 {
		t.Fatalf("init did not reuse stored authentication: calls=%d email prompts=%d", a.calls, p.emailCalls)
	}
}

func TestStatusStatesAndJSON(t *testing.T) {
	store := securestore.NewMemoryStore()
	a := &fakeAuthenticator{}
	p := &fakePrompter{}
	out, err := run(t, store, a, p, "", "auth status")
	if err != nil || out != "not authenticated\n" {
		t.Fatalf("got %q %v", out, err)
	}
	expired := validSession(time.Now())
	expired.Cookies[0].Expires = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := auth.SaveSession(store, "default", expired); err != nil {
		t.Fatal(err)
	}
	out, err = run(t, store, a, p, "", "auth status")
	if err != nil || out != "expired\n" {
		t.Fatalf("got %q %v", out, err)
	}
	valid := validSession(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if err := auth.SaveSession(store, "default", valid); err != nil {
		t.Fatal(err)
	}
	out, err = run(t, store, a, p, "", "--json auth status")
	if err != nil || !strings.Contains(out, `"profile":"default"`) || !strings.Contains(out, `"status":"authenticated"`) || !strings.Contains(out, `"authentication_timestamp"`) {
		t.Fatalf("got %q %v", out, err)
	}
}

func TestStatusTreatsInvalidStoredSessionAsNotAuthenticated(t *testing.T) {
	store := securestore.NewMemoryStore()
	secret := []byte(`{"Cookies":[{"Name":"sid","Value":"secret-cookie"}]`)
	if err := store.Set("default", "session", secret); err != nil {
		t.Fatal(err)
	}

	for _, args := range []string{"auth status", "--json auth status"} {
		t.Run(args, func(t *testing.T) {
			output, err := run(t, store, &fakeAuthenticator{}, &fakePrompter{}, "", args)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(output, "secret-cookie") || strings.Contains(output, "authentication_timestamp") {
				t.Fatalf("invalid session leaked data: %q", output)
			}
			if strings.Contains(args, "--json") {
				if output != `{"profile":"default","status":"not authenticated"}`+"\n" {
					t.Fatalf("got %q", output)
				}
			} else if output != "not authenticated\n" {
				t.Fatalf("got %q", output)
			}
		})
	}
}

func TestLogoutDeletesLocallyOnRemoteFailureAndForgets(t *testing.T) {
	store := securestore.NewMemoryStore()
	if err := auth.SaveSession(store, "default", validSession(time.Now())); err != nil {
		t.Fatal(err)
	}
	if err := auth.SaveCredentials(store, "default", auth.Credentials{Email: "a@b", Password: "pw"}); err != nil {
		t.Fatal(err)
	}
	a := &fakeAuthenticator{logoutErr: errors.New("network failed")}
	_, err := run(t, store, a, &fakePrompter{}, "", "auth logout --forget")
	if err == nil {
		t.Fatal("expected remote error")
	}
	if _, err := auth.LoadSession(store, "default"); !errors.Is(err, securestore.ErrNotFound) {
		t.Fatalf("session remains: %v", err)
	}
	if _, err := auth.LoadCredentials(store, "default"); !errors.Is(err, securestore.ErrNotFound) {
		t.Fatalf("credentials remain: %v", err)
	}
}

func TestAuthenticationAndStatusRejectStorageLoadFailures(t *testing.T) {
	secret := errors.New("storage failure")
	for _, tc := range []struct {
		name   string
		args   string
		getKey string
	}{
		{name: "session during login", args: "auth login --password-stdin", getKey: "session"},
		{name: "credentials during login", args: "auth login --password-stdin", getKey: "credentials"},
		{name: "session during status", args: "auth status", getKey: "session"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prompt := &fakePrompter{email: "person@example.test"}
			store := failingStore{Store: securestore.NewMemoryStore(), getErr: secret, getKey: tc.getKey}
			output, err := run(t, store, &fakeAuthenticator{}, prompt, "password\n", tc.args)
			if !errors.Is(err, auth.ErrStorageFailed) {
				t.Fatalf("error = %v, want %v", err, auth.ErrStorageFailed)
			}
			if prompt.emailCalls != 0 {
				t.Fatalf("email prompt called %d times", prompt.emailCalls)
			}
			if strings.Contains(output, secret.Error()) {
				t.Fatalf("storage error leaked: %q", output)
			}
		})
	}
}

func TestInteractivePasswordUsesInjectedTerminal(t *testing.T) {
	store := securestore.NewMemoryStore()
	a := &fakeAuthenticator{session: validSession(time.Now())}
	prompt := &fakePrompter{email: "person@example.test", save: false}
	terminal := &fakeTerminal{terminal: true, password: "terminal-password"}
	_, err := runWithDependencies(t, Dependencies{Store: store, Authenticator: a, Clock: time.Now, Prompter: prompt, PasswordTerminal: terminal}, "", "auth login --no-store")
	if err != nil {
		t.Fatal(err)
	}
	if terminal.readCalls != 1 || a.credentials.Password != "terminal-password" {
		t.Fatalf("terminal calls=%d credentials=%#v", terminal.readCalls, a.credentials)
	}
}

func TestCredentialPersistenceConfirmationAndAuthenticationFailure(t *testing.T) {
	for _, tc := range []struct {
		name      string
		save      bool
		authErr   error
		wantSaved bool
	}{
		{name: "yes saves after successful authentication", save: true, wantSaved: true},
		{name: "no does not save", save: false},
		{name: "authentication failure does not save", save: true, authErr: errors.New("remote rejected")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := securestore.NewMemoryStore()
			a := &fakeAuthenticator{session: validSession(time.Now()), err: tc.authErr}
			prompt := &fakePrompter{email: "person@example.test", save: tc.save}
			_, err := run(t, store, a, prompt, "password\n", "auth login --password-stdin")
			if tc.authErr != nil {
				if !errors.Is(err, auth.ErrAuthenticationFailed) {
					t.Fatalf("error = %v", err)
				}
				if prompt.saveCalls != 0 {
					t.Fatal("confirmation happened before authentication succeeded")
				}
			} else if err != nil {
				t.Fatal(err)
			}
			_, loadErr := auth.LoadCredentials(store, "default")
			if got := loadErr == nil; got != tc.wantSaved {
				t.Fatalf("credentials saved=%t, load error=%v", got, loadErr)
			}
		})
	}
}

func TestStatusJSONTimestampAbsentAndExpiredPresent(t *testing.T) {
	store := securestore.NewMemoryStore()
	a := &fakeAuthenticator{}
	out, err := run(t, store, a, &fakePrompter{}, "", "--json auth status")
	if err != nil {
		t.Fatal(err)
	}
	var noSession map[string]any
	if err := json.Unmarshal([]byte(out), &noSession); err != nil {
		t.Fatal(err)
	}
	if _, ok := noSession["authentication_timestamp"]; ok {
		t.Fatalf("absent session emitted timestamp: %s", out)
	}

	at := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	expired := validSession(at)
	expired.Cookies[0].Expires = at.Add(-time.Hour)
	if err := auth.SaveSession(store, "default", expired); err != nil {
		t.Fatal(err)
	}
	out, err = run(t, store, a, &fakePrompter{}, "", "--json auth status")
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatal(err)
	}
	if result["status"] != "expired" || result["authentication_timestamp"] == nil {
		t.Fatalf("expired session JSON = %s", out)
	}
}

func TestLogoutCallsRemoteOnceAndOnlyForgetsCredentialsWithFlag(t *testing.T) {
	for _, forget := range []bool{false, true} {
		t.Run(map[bool]string{false: "without forget", true: "with forget"}[forget], func(t *testing.T) {
			store := securestore.NewMemoryStore()
			if err := auth.SaveSession(store, "default", validSession(time.Now())); err != nil {
				t.Fatal(err)
			}
			if err := auth.SaveCredentials(store, "default", auth.Credentials{Email: "a@b", Password: "password"}); err != nil {
				t.Fatal(err)
			}
			a := &fakeAuthenticator{}
			args := "auth logout"
			if forget {
				args += " --forget"
			}
			if _, err := run(t, store, a, &fakePrompter{}, "", args); err != nil {
				t.Fatal(err)
			}
			if a.logoutCalls != 1 {
				t.Fatalf("remote logout calls = %d", a.logoutCalls)
			}
			if _, err := auth.LoadSession(store, "default"); !errors.Is(err, securestore.ErrNotFound) {
				t.Fatalf("session remains: %v", err)
			}
			_, credentialsErr := auth.LoadCredentials(store, "default")
			if got := credentialsErr == nil; got == forget {
				t.Fatalf("credentials retained=%t, error=%v", got, credentialsErr)
			}
		})
	}
}

func TestCommandErrorsAreSafeAndCategorized(t *testing.T) {
	const secret = "known-secret-never-display"
	cases := []struct {
		name string
		deps Dependencies
		args string
		want error
	}{
		{name: "prompt", args: "auth login --no-store --password-stdin", want: auth.ErrPromptFailed, deps: Dependencies{Store: securestore.NewMemoryStore(), Authenticator: &fakeAuthenticator{}, Clock: time.Now, Prompter: &fakePrompter{emailErr: errors.New(secret)}, PasswordTerminal: &fakeTerminal{}}},
		{name: "terminal password", args: "auth login --no-store", want: auth.ErrPasswordReadFailed, deps: Dependencies{Store: securestore.NewMemoryStore(), Authenticator: &fakeAuthenticator{}, Clock: time.Now, Prompter: &fakePrompter{email: "a@b"}, PasswordTerminal: &fakeTerminal{terminal: true, err: errors.New(secret)}}},
		{name: "confirmation", args: "auth login --password-stdin", want: auth.ErrPromptFailed, deps: Dependencies{Store: securestore.NewMemoryStore(), Authenticator: &fakeAuthenticator{session: validSession(time.Now())}, Clock: time.Now, Prompter: &fakePrompter{email: "a@b", saveErr: errors.New(secret)}, PasswordTerminal: &fakeTerminal{}}},
		{name: "authenticator", args: "auth login --no-store --password-stdin", want: auth.ErrAuthenticationFailed, deps: Dependencies{Store: securestore.NewMemoryStore(), Authenticator: &fakeAuthenticator{err: errors.New(secret)}, Clock: time.Now, Prompter: &fakePrompter{email: "a@b"}, PasswordTerminal: &fakeTerminal{}}},
		{name: "session storage", args: "auth login --password-stdin", want: auth.ErrStorageFailed, deps: Dependencies{Store: failingStore{Store: securestore.NewMemoryStore(), setErr: errors.New(secret)}, Authenticator: &fakeAuthenticator{session: validSession(time.Now())}, Clock: time.Now, Prompter: &fakePrompter{email: "a@b"}, PasswordTerminal: &fakeTerminal{}}},
		{name: "logout storage", args: "auth logout", want: auth.ErrStorageFailed, deps: Dependencies{Store: failingStore{Store: securestore.NewMemoryStore(), getErr: errors.New(secret), deleteErr: errors.New(secret)}, Authenticator: &fakeAuthenticator{}, Clock: time.Now, Prompter: &fakePrompter{}, PasswordTerminal: &fakeTerminal{}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			output, err := runWithDependencies(t, tc.deps, "password\n", tc.args)
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
			if strings.Contains(output, secret) || strings.Contains(err.Error(), secret) {
				t.Fatalf("secret leaked: output=%q error=%v", output, err)
			}
		})
	}
}

func TestNotImplementedAuthenticatorErrorIsPreserved(t *testing.T) {
	output, err := runWithDependencies(t, Dependencies{Store: securestore.NewMemoryStore(), Authenticator: auth.NotImplementedAuthenticator{}, Clock: time.Now, Prompter: &fakePrompter{email: "a@b"}, PasswordTerminal: &fakeTerminal{}}, "not-a-real-password-value\n", "auth login --no-store --password-stdin")
	if !errors.Is(err, auth.ErrNotImplemented) {
		t.Fatalf("error = %v", err)
	}
	if strings.Contains(output, "not-a-real-password-value") {
		t.Fatalf("secret leaked in output: %q", output)
	}
}

type verifyingAuthenticator struct {
	fakeAuthenticator
	verifyErr   error
	verifyCalls int
	restored    []auth.Session
}

func (a *verifyingAuthenticator) VerifySession(context.Context, auth.Session) error {
	a.verifyCalls++
	return a.verifyErr
}
func (a *verifyingAuthenticator) RestoreSession(session auth.Session) error {
	a.restored = append(a.restored, session)
	return nil
}

func TestLoginConfirmsStoredSessionWithProvider(t *testing.T) {
	now := time.Now()
	stored := validSession(now)
	stored.Cookies = append(stored.Cookies, auth.Cookie{Name: "CE_DEVICE_ID", Value: "remembered-device"})
	for _, tc := range []struct {
		name      string
		verifyErr error
		wantCalls int
		wantErr   error
	}{
		{name: "live session is reused", wantCalls: 0},
		{name: "provider-ended session is replaced", verifyErr: coned.ErrSessionExpired, wantCalls: 1},
		{name: "provider fault is reported, not papered over", verifyErr: &coned.ProtocolError{Status: 503}, wantErr: coned.ErrProtocolChanged},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := securestore.NewMemoryStore()
			if err := auth.SaveSession(store, "default", stored); err != nil {
				t.Fatal(err)
			}
			a := &verifyingAuthenticator{fakeAuthenticator: fakeAuthenticator{session: validSession(now)}, verifyErr: tc.verifyErr}
			deps := Dependencies{Store: store, Authenticator: a, Clock: time.Now, Prompter: &fakePrompter{email: "a@b"}, PasswordTerminal: &fakeTerminal{}}
			_, err := runWithDependencies(t, deps, "new\n", "auth login --password-stdin")
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if a.verifyCalls != 1 || a.calls != tc.wantCalls {
				t.Fatalf("verify calls = %d, authenticate calls = %d", a.verifyCalls, a.calls)
			}
			if tc.wantCalls == 1 {
				restored := a.restored[len(a.restored)-1].Cookies
				if len(restored) != 1 || restored[0].Name != "CE_DEVICE_ID" {
					t.Fatalf("replacement login restored %#v, want only the remembered device", restored)
				}
			}
		})
	}
}

func TestProviderEndedSessionDoesNotImplyForce(t *testing.T) {
	store := securestore.NewMemoryStore()
	if err := auth.SaveSession(store, "default", validSession(time.Now())); err != nil {
		t.Fatal(err)
	}
	a := &verifyingAuthenticator{fakeAuthenticator: fakeAuthenticator{session: validSession(time.Now())}, verifyErr: coned.ErrSessionExpired}
	deps := Dependencies{
		Store: failingStore{Store: store, getErr: fmt.Errorf("get secure value: %w", securestore.ErrAccessDenied), getKey: "credentials"}, Authenticator: a,
		Clock: time.Now, Prompter: &fakePrompter{email: "a@b"}, PasswordTerminal: &fakeTerminal{},
	}
	if _, err := runWithDependencies(t, deps, "new\n", "auth login --password-stdin"); !errors.Is(err, auth.ErrStorageFailed) {
		t.Fatalf("err = %v: unreadable credentials were passed over without --force", err)
	}
	if a.calls != 0 {
		t.Fatal("authenticated after a storage failure the user did not ask to override")
	}
}

func TestForcedLoginSkipsProviderVerification(t *testing.T) {
	store := securestore.NewMemoryStore()
	if err := auth.SaveSession(store, "default", validSession(time.Now())); err != nil {
		t.Fatal(err)
	}
	a := &verifyingAuthenticator{fakeAuthenticator: fakeAuthenticator{session: validSession(time.Now())}}
	deps := Dependencies{Store: store, Authenticator: a, Clock: time.Now, Prompter: &fakePrompter{email: "a@b"}, PasswordTerminal: &fakeTerminal{}}
	if _, err := runWithDependencies(t, deps, "new\n", "auth login --force --password-stdin"); err != nil {
		t.Fatal(err)
	}
	if a.verifyCalls != 0 || a.calls != 1 {
		t.Fatalf("verify calls = %d, authenticate calls = %d", a.verifyCalls, a.calls)
	}
}

func TestUnreadableStoredValuesExplainTheRecovery(t *testing.T) {
	denied := fmt.Errorf("get secure value: %w", securestore.ErrAccessDenied)
	memory := securestore.NewMemoryStore()
	if err := auth.SaveSession(memory, "default", validSession(time.Now())); err != nil {
		t.Fatal(err)
	}
	store := failingStore{Store: memory, getErr: denied}
	a := &fakeAuthenticator{session: validSession(time.Now())}

	for _, args := range []string{"auth status", "auth login --password-stdin"} {
		out, err := run(t, store, a, &fakePrompter{email: "a@b"}, "new\n", args)
		if !errors.Is(err, auth.ErrStorageAccessDenied) || !errors.Is(err, auth.ErrStorageFailed) {
			t.Fatalf("%s: err = %v", args, err)
		}
		if !strings.Contains(out, "auth login --force") {
			t.Fatalf("%s: output does not name the recovery: %q", args, out)
		}
	}
	if a.calls != 0 {
		t.Fatalf("authenticated %d times without --force", a.calls)
	}

	p := &fakePrompter{email: "a@b", save: true}
	if _, err := run(t, store, a, p, "new\n", "auth login --force --password-stdin"); err != nil {
		t.Fatalf("forced login over unreadable values: %v", err)
	}
	if a.calls != 1 || p.emailCalls != 1 {
		t.Fatalf("authenticate calls = %d, email prompts = %d", a.calls, p.emailCalls)
	}
	if _, err := auth.LoadCredentials(memory, "default"); err != nil {
		t.Fatalf("forced login did not store fresh credentials: %v", err)
	}
}

func TestForcedLoginReclaimsAnUnreadableHandleKeyOnlyWhenUnused(t *testing.T) {
	denied := fmt.Errorf("get secure value: %w", securestore.ErrAccessDenied)
	for _, tc := range []struct {
		name        string
		config      string
		wantReplace bool
	}{
		{name: "no saved selections", config: `{}`, wantReplace: true},
		{name: "aliases refer to current handles", config: `{"selections":{"default":{"aliases":{"home":"account-aaaaaaaaaaaa"}}}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			memory := securestore.NewMemoryStore()
			if err := memory.Set("default", "entity-handle-key-v1", bytes.Repeat([]byte{7}, 32)); err != nil {
				t.Fatal(err)
			}
			configPath := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(configPath, []byte(tc.config), 0o600); err != nil {
				t.Fatal(err)
			}
			a := &fakeAuthenticator{session: validSession(time.Now())}
			deps := Dependencies{
				Store: failingStore{Store: memory, getErr: denied, getKey: "entity-handle-key-v1"}, Authenticator: a, Clock: time.Now,
				Prompter: &fakePrompter{email: "a@b"}, PasswordTerminal: &fakeTerminal{}, ConfigPath: configPath,
			}
			if _, err := runWithDependencies(t, deps, "new\n", "auth login --force --password-stdin"); err != nil {
				t.Fatal(err)
			}
			key, err := memory.Get("default", "entity-handle-key-v1")
			if err != nil {
				t.Fatal(err)
			}
			if replaced := !bytes.Equal(key, bytes.Repeat([]byte{7}, 32)); replaced != tc.wantReplace {
				t.Fatalf("key replaced = %v, want %v", replaced, tc.wantReplace)
			}
		})
	}
}

func TestHandlesInUseFailsClosed(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		name, config string
		want         bool
	}{
		{name: "no saved selections", config: `{}`, want: false},
		{name: "saved alias", config: `{"selections":{"default":{"aliases":{"home":"account-aaaaaaaaaaaa"}}}}`, want: true},
		{name: "unreadable configuration", config: `{not json`, want: true},
	} {
		path := filepath.Join(dir, strings.ReplaceAll(tc.name, " ", "-")+".json")
		if err := os.WriteFile(path, []byte(tc.config), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := handlesInUse(Dependencies{ConfigPath: path}, "default"); got != tc.want {
			t.Fatalf("%s: handlesInUse = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestLockedStoreAsksTheUserToUnlock(t *testing.T) {
	locked := fmt.Errorf("get secure value: %w", securestore.ErrLocked)
	store := failingStore{Store: securestore.NewMemoryStore(), getErr: locked}
	out, err := run(t, store, &fakeAuthenticator{}, &fakePrompter{}, "", "auth status")
	if !errors.Is(err, auth.ErrStorageLocked) || !strings.Contains(out, "security unlock-keychain") {
		t.Fatalf("err = %v, output = %q", err, out)
	}
}

type mfaAuthenticator struct {
	fakeAuthenticator
	codes []string
}

func (a *mfaAuthenticator) Authenticate(context.Context, auth.Credentials) (auth.Session, error) {
	a.calls++
	return auth.Session{}, coned.ErrMFARequired
}
func (a *mfaAuthenticator) VerifyMFA(_ context.Context, code string) (auth.Session, error) {
	a.codes = append(a.codes, code)
	return a.session, nil
}

func TestJSONLoginEmitsEventsAndKeepsPromptsOffStdout(t *testing.T) {
	store := securestore.NewMemoryStore()
	if err := auth.SaveCredentials(store, "default", auth.Credentials{Email: "a@b", Password: "synthetic-password"}); err != nil {
		t.Fatal(err)
	}
	a := &mfaAuthenticator{fakeAuthenticator: fakeAuthenticator{session: validSession(time.Now())}}
	var stdout, stderr bytes.Buffer
	deps := Dependencies{Store: store, Authenticator: a, Clock: time.Now, PasswordTerminal: &fakeTerminal{}}
	cmd := NewRootCommandWithDependencies(strings.NewReader("123456\n"), &stdout, &stderr, deps)
	cmd.SetArgs([]string{"--json", "auth", "login"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if got, want := stdout.String(), "{\"event\":\"mfa_required\"}\n{\"event\":\"authenticated\"}\n"; got != want {
		t.Fatalf("stdout = %q, want %q", got, want)
	}
	if !strings.Contains(stderr.String(), "Verification code") {
		t.Fatalf("prompt missing from stderr: %q", stderr.String())
	}
	if len(a.codes) != 1 || a.codes[0] != "123456" {
		t.Fatalf("codes = %v, want the one read from stdin", a.codes)
	}
}

func TestJSONLoginWithLiveSessionReportsAuthenticated(t *testing.T) {
	store := securestore.NewMemoryStore()
	if err := auth.SaveSession(store, "default", validSession(time.Now())); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	deps := Dependencies{Store: store, Authenticator: &verifyingAuthenticator{}, Clock: time.Now, Prompter: &fakePrompter{}, PasswordTerminal: &fakeTerminal{}}
	cmd := NewRootCommandWithDependencies(strings.NewReader(""), &stdout, io.Discard, deps)
	cmd.SetArgs([]string{"--json", "auth", "login"})
	if err := cmd.Execute(); err != nil || stdout.String() != "{\"event\":\"authenticated\"}\n" {
		t.Fatalf("stdout = %q, err = %v", stdout.String(), err)
	}
}

func TestJSONLoginFailureKeepsStdoutFreeOfUsage(t *testing.T) {
	var stdout bytes.Buffer
	deps := Dependencies{Store: securestore.NewMemoryStore(), Authenticator: &fakeAuthenticator{}, Clock: time.Now, Prompter: &fakePrompter{}, PasswordTerminal: &fakeTerminal{}}
	cmd := NewRootCommandWithDependencies(strings.NewReader(""), &stdout, io.Discard, deps)
	cmd.SetArgs([]string{"--json", "auth", "login"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("login without credentials or a terminal succeeded")
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want nothing on failure", stdout.String())
	}
}
