package securestore

import (
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/zalando/go-keyring"
)

const serviceName = "coned-cli"

// KeyringStore stores values in the operating system keyring.
type KeyringStore struct{}

func account(profile, key string) string {
	encoding := base64.RawURLEncoding
	return encoding.EncodeToString([]byte(profile)) + "/" + encoding.EncodeToString([]byte(key))
}

func (KeyringStore) Get(profile, key string) ([]byte, error) {
	value, err := keyring.Get(serviceName, account(profile, key))
	if errors.Is(err, keyring.ErrNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get secure value: %w", err)
	}
	return []byte(value), nil
}

func (KeyringStore) Set(profile, key string, value []byte) error {
	if err := keyring.Set(serviceName, account(profile, key), string(value)); err != nil {
		return fmt.Errorf("set secure value: %w", err)
	}
	return nil
}

func (KeyringStore) Delete(profile, key string) error {
	if err := keyring.Delete(serviceName, account(profile, key)); errors.Is(err, keyring.ErrNotFound) {
		return ErrNotFound
	} else if err != nil {
		return fmt.Errorf("delete secure value: %w", err)
	}
	return nil
}
