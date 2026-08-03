//go:build darwin && !cgo

package securestore

import "errors"

var errKeyringUnavailable = errors.New("secure keyring unavailable")

type darwinNoCGOKeyringDriver struct{}

func newKeyringDriver() keyringDriver {
	return darwinNoCGOKeyringDriver{}
}

func (darwinNoCGOKeyringDriver) Get(string, string) ([]byte, error) {
	return nil, errKeyringUnavailable
}

func (darwinNoCGOKeyringDriver) Set(string, string, []byte) error {
	return errKeyringUnavailable
}

func (darwinNoCGOKeyringDriver) Delete(string, string) error {
	return errKeyringUnavailable
}
