package auth

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/zzwong/coned-cli/internal/securestore"
)

func TestLoadMalformedJSONReturnsSentinels(t *testing.T) {
	store := securestore.NewMemoryStore()
	if err := store.Set("default", credentialsKey, []byte(`{"Password":"secret"`)); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCredentials(store, "default"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("credentials error = %v, want %v", err, ErrInvalidCredentials)
	}
	if err := store.Set("default", sessionKey, []byte(`{"Cookies":[{"Value":"secret-cookie"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSession(store, "default"); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("session error = %v, want %v", err, ErrInvalidSession)
	}
}

func TestSessionStoreValidationAndProfiles(t *testing.T) {
	store := securestore.NewMemoryStore()
	if err := SaveCredentials(store, "one", Credentials{}); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("got %v", err)
	}
	if err := SaveSession(store, "one", Session{}); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("got %v", err)
	}
	credentials := Credentials{Email: "one@example.test", Password: "password"}
	if err := SaveCredentials(store, "one", credentials); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCredentials(store, "two"); !errors.Is(err, securestore.ErrNotFound) {
		t.Fatalf("profiles were not isolated: %v", err)
	}
	got, err := LoadCredentials(store, "one")
	if err != nil {
		t.Fatal(err)
	}
	if got != credentials {
		t.Fatalf("got %#v", got)
	}
	original := Session{Cookies: []Cookie{{Name: "sid", Value: "value", Domain: "example.test", Path: "/", Secure: true, HTTPOnly: true}}, AuthenticatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	if err := SaveSession(store, "one", original); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadSession(store, "one")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(loaded, original) {
		t.Fatalf("session changed: %#v", loaded)
	}
}
