package auth

import (
	"errors"
	"testing"
	"time"
)

func TestValidation(t *testing.T) {
	if !errors.Is(ValidateCredentials(Credentials{}), ErrInvalidCredentials) {
		t.Fatal("empty credentials accepted")
	}
	if !errors.Is(ValidateSession(Session{}), ErrInvalidSession) {
		t.Fatal("empty session accepted")
	}
	if !errors.Is(ValidateSession(Session{Cookies: []Cookie{{Name: "name"}}}), ErrInvalidSession) {
		t.Fatal("empty cookie value accepted")
	}
}

func TestSessionState(t *testing.T) {
	now := time.Now()
	if got := (Session{Cookies: []Cookie{{Name: "a", Value: "b", Expires: now.Add(-time.Hour)}}}).State(now); got != SessionExpired {
		t.Fatalf("got %v", got)
	}
	if got := (Session{Cookies: []Cookie{{Name: "a", Value: "b"}, {Name: "c", Value: "d", Expires: now.Add(-time.Hour)}}}).State(now); got != SessionValid {
		t.Fatalf("session cookie should remain valid, got %v", got)
	}
	if got := (Session{Cookies: []Cookie{{Name: "a", Value: "b", Expires: now.Add(time.Hour)}}}).State(now); got != SessionValid {
		t.Fatalf("future cookie should be valid, got %v", got)
	}
}
