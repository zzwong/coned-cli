package securestore

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const serviceName = "coned-cli"

const keyringBase64Prefix = "go-keyring-base64:"

const keyringHexPrefix = "go-keyring-encoded:"

var errInvalidKeyringValue = errors.New("invalid secure value encoding")

type keyringDriver interface {
	Get(service, account string) ([]byte, error)
	Set(service, account string, value []byte) error
	Delete(service, account string) error
}

// KeyringStore stores values in the operating system keyring.
type KeyringStore struct {
	driver keyringDriver
}

func (store KeyringStore) keyringDriver() keyringDriver {
	if store.driver != nil {
		return store.driver
	}
	return newKeyringDriver()
}

func decodeKeyringValue(value []byte) ([]byte, error) {
	trimmed := strings.TrimSpace(string(value))
	if strings.HasPrefix(trimmed, keyringBase64Prefix) {
		decoded, err := base64.StdEncoding.DecodeString(trimmed[len(keyringBase64Prefix):])
		if err != nil {
			return nil, errInvalidKeyringValue
		}
		return decoded, nil
	}
	if strings.HasPrefix(trimmed, keyringHexPrefix) {
		decoded, err := hex.DecodeString(trimmed[len(keyringHexPrefix):])
		if err != nil {
			return nil, errInvalidKeyringValue
		}
		return decoded, nil
	}
	return []byte(trimmed), nil
}

func encodeKeyringValue(value []byte) []byte {
	encoded := make([]byte, len(keyringBase64Prefix)+base64.StdEncoding.EncodedLen(len(value)))
	copy(encoded, keyringBase64Prefix)
	base64.StdEncoding.Encode(encoded[len(keyringBase64Prefix):], value)
	return encoded
}

func account(profile, key string) string {
	encoding := base64.RawURLEncoding
	return encoding.EncodeToString([]byte(profile)) + "/" + encoding.EncodeToString([]byte(key))
}

func (store KeyringStore) Get(profile, key string) ([]byte, error) {
	value, err := store.keyringDriver().Get(serviceName, account(profile, key))
	if errors.Is(err, ErrNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get secure value: %w", err)
	}
	return value, nil
}

func (store KeyringStore) Set(profile, key string, value []byte) error {
	if err := store.keyringDriver().Set(serviceName, account(profile, key), value); err != nil {
		return fmt.Errorf("set secure value: %w", err)
	}
	return nil
}

func (store KeyringStore) Delete(profile, key string) error {
	if err := store.keyringDriver().Delete(serviceName, account(profile, key)); errors.Is(err, ErrNotFound) {
		return ErrNotFound
	} else if err != nil {
		return fmt.Errorf("delete secure value: %w", err)
	}
	return nil
}
