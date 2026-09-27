// Package securestore provides a small abstraction for secret storage.
package securestore

import "errors"

// ErrNotFound indicates that a profile has no value for an account key.
var ErrNotFound = errors.New("secure store value not found")

// ErrLocked indicates that the store is locked and must be unlocked before any
// value can be read or written.
var ErrLocked = errors.New("secure store locked")

// ErrAccessDenied indicates that the backend refused access to a value that
// may exist: the store is locked, or the value belongs to another program and
// no one is present to approve access.
var ErrAccessDenied = errors.New("secure store access denied")

// Store stores secrets by profile-scoped account key.
type Store interface {
	Get(profile, key string) ([]byte, error)
	Set(profile, key string, value []byte) error
	Delete(profile, key string) error
}
