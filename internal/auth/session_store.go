package auth

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/zzwong/coned-cli/internal/securestore"
)

const (
	credentialsKey = "credentials"
	sessionKey     = "session"
)

// LoadCredentials loads validated credentials for profile.
func LoadCredentials(store securestore.Store, profile string) (Credentials, error) {
	data, err := store.Get(profile, credentialsKey)
	if err != nil {
		return Credentials{}, err
	}
	var credentials Credentials
	if err := json.Unmarshal(data, &credentials); err != nil {
		return Credentials{}, ErrInvalidCredentials
	}
	if err := ValidateCredentials(credentials); err != nil {
		return Credentials{}, err
	}
	return credentials, nil
}

// SaveCredentials validates and stores credentials for profile.
func SaveCredentials(store securestore.Store, profile string, credentials Credentials) error {
	if err := ValidateCredentials(credentials); err != nil {
		return err
	}
	data, err := json.Marshal(credentials)
	if err != nil {
		return fmt.Errorf("encode credentials: %w", err)
	}
	return store.Set(profile, credentialsKey, data)
}

// DeleteCredentials removes credentials for profile.
func DeleteCredentials(store securestore.Store, profile string) error {
	return store.Delete(profile, credentialsKey)
}

// LoadSession loads a validated session for profile.
func LoadSession(store securestore.Store, profile string) (Session, error) {
	data, err := store.Get(profile, sessionKey)
	if err != nil {
		return Session{}, err
	}
	var session Session
	if err := json.Unmarshal(data, &session); err != nil {
		return Session{}, ErrInvalidSession
	}
	if err := ValidateSession(session); err != nil {
		return Session{}, err
	}
	return session, nil
}

// SaveSession validates and stores a session for profile.
func SaveSession(store securestore.Store, profile string, session Session) error {
	if err := ValidateSession(session); err != nil {
		return err
	}
	data, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("encode session: %w", err)
	}
	return store.Set(profile, sessionKey, data)
}

// DeleteSession removes a session for profile.
func DeleteSession(store securestore.Store, profile string) error {
	return store.Delete(profile, sessionKey)
}

// StorageError reduces a secure-store failure to a safe sentinel, keeping the
// access-denied case distinct because the user can resolve it.
func StorageError(err error) error {
	if errors.Is(err, securestore.ErrAccessDenied) {
		return ErrStorageAccessDenied
	}
	return ErrStorageFailed
}
