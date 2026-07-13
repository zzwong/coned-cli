// Package securestore provides a small abstraction for secret storage.
package securestore

import "errors"

// ErrNotFound indicates that a profile has no value for an account key.
var ErrNotFound = errors.New("secure store value not found")

// Store stores secrets by profile-scoped account key.
type Store interface {
	Get(profile, key string) ([]byte, error)
	Set(profile, key string, value []byte) error
	Delete(profile, key string) error
}
