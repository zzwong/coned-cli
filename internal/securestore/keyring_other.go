//go:build !darwin

package securestore

import (
	"errors"

	"github.com/zalando/go-keyring"
)

type goKeyringDriver struct{}

func newKeyringDriver() keyringDriver {
	return goKeyringDriver{}
}

func (goKeyringDriver) Get(service, account string) ([]byte, error) {
	value, err := keyring.Get(service, account)
	if errors.Is(err, keyring.ErrNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return []byte(value), nil
}

func (goKeyringDriver) Set(service, account string, value []byte) error {
	return keyring.Set(service, account, string(value))
}

func (goKeyringDriver) Delete(service, account string) error {
	err := keyring.Delete(service, account)
	if errors.Is(err, keyring.ErrNotFound) {
		return ErrNotFound
	}
	return err
}
