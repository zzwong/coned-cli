package securestore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// sealedDriver keeps each value in its own file, encrypted with a key held in
// the macOS Keychain.
//
// The Keychain pins an item to the code identity that created it, and coned
// builds are ad-hoc signed, so every upgrade is a new identity locked out of
// items the previous build wrote. The key is instead written and read through
// /usr/bin/security, whose identity never changes, so every build reaches it.
// Values stay out of that tool because it accepts a secret only on its command
// line, where other processes can see it, or as one line of its interactive
// mode, and a stored session runs to several kilobytes.
type sealedDriver struct {
	dir    string
	keys   keySource
	legacy keyringDriver
}

// keySource returns the value-encryption key for a service, creating it when
// create is set.
type keySource interface {
	Key(service string, create bool) ([]byte, error)
}

const sealedFormatVersion = 1

var errSealedStoreUnavailable = errors.New("sealed secret directory unavailable")

func (d sealedDriver) path(service, account string) (string, error) {
	if d.dir == "" {
		return "", errSealedStoreUnavailable
	}
	// Accounts are base64url segments joined by "/", and base64url has no ".".
	return filepath.Join(d.dir, service+"."+strings.ReplaceAll(account, "/", ".")), nil
}

func (d sealedDriver) Get(service, account string) ([]byte, error) {
	path, err := d.path(service, account)
	if err != nil {
		return nil, err
	}
	sealed, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return d.migrate(service, account)
	}
	if err != nil {
		return nil, err
	}
	if len(sealed) == 0 {
		return nil, ErrNotFound
	}
	key, err := d.keys.Key(service, false)
	if err != nil {
		return nil, err
	}
	value, err := open(key, service, account, sealed)
	if err != nil {
		// A value that will not open was sealed under a replaced key or is
		// damaged; either way it is lost. Reporting it as absent lets the
		// next write replace it. Authentication still keeps a forged value
		// from ever being returned.
		return nil, ErrNotFound
	}
	return value, nil
}

// migrate moves a value an earlier build stored directly in the Keychain into
// a sealed file, so it is read through the Keychain item at most once more.
func (d sealedDriver) migrate(service, account string) ([]byte, error) {
	if d.legacy == nil {
		return nil, ErrNotFound
	}
	value, err := d.legacy.Get(service, account)
	if err != nil {
		return nil, err
	}
	// Another process may have written a newer value since this one found no
	// file, and that value must win over the stale legacy one.
	if err := d.put(service, account, value, false); errors.Is(err, fs.ErrExist) {
		return d.Get(service, account)
	} else if err != nil {
		return nil, err
	}
	return value, nil
}

func (d sealedDriver) Set(service, account string, value []byte) error {
	return d.put(service, account, value, true)
}

func (d sealedDriver) put(service, account string, value []byte, replace bool) error {
	path, err := d.path(service, account)
	if err != nil {
		return err
	}
	key, err := d.keys.Key(service, true)
	if err != nil {
		return err
	}
	sealed, err := seal(key, service, account, value)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(path, sealed, replace); err != nil {
		return err
	}
	// The sealed file now takes precedence, so a legacy item that cannot be
	// removed is harmless.
	if d.legacy != nil {
		_ = d.legacy.Delete(service, account)
	}
	return nil
}

func (d sealedDriver) Delete(service, account string) error {
	path, err := d.path(service, account)
	if err != nil {
		return err
	}
	existing, _ := os.ReadFile(path)
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	legacyErr := error(ErrNotFound)
	if d.legacy != nil {
		legacyErr = d.legacy.Delete(service, account)
	}
	if legacyErr != nil && !errors.Is(legacyErr, ErrNotFound) {
		// A legacy item left behind would be migrated back by a later read.
		// An empty file stops that, since Get treats it as absent.
		if err := writeFileAtomic(path, nil, true); err != nil {
			return err
		}
		return legacyErr
	}
	if len(existing) > 0 || legacyErr == nil {
		return nil
	}
	return ErrNotFound
}

func additionalData(service, account string) []byte {
	return []byte(service + "\x00" + account)
}

func seal(key []byte, service, account string, value []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 1+aead.NonceSize(), 1+aead.NonceSize()+len(value)+aead.Overhead())
	out[0] = sealedFormatVersion
	if _, err := rand.Read(out[1:]); err != nil {
		return nil, err
	}
	return aead.Seal(out, out[1:], value, additionalData(service, account)), nil
}

func open(key []byte, service, account string, sealed []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	if len(sealed) < 1+aead.NonceSize() || sealed[0] != sealedFormatVersion {
		return nil, errInvalidKeyringValue
	}
	nonce := sealed[1 : 1+aead.NonceSize()]
	value, err := aead.Open(nil, nonce, sealed[1+aead.NonceSize():], additionalData(service, account))
	if err != nil {
		return nil, errInvalidKeyringValue
	}
	return value, nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errInvalidKeyringValue
	}
	return cipher.NewGCM(block)
}

// writeFileAtomic writes data under a temporary name and moves it into place.
// Without replace, an existing file is kept and fs.ErrExist is returned.
func writeFileAtomic(path string, data []byte, replace bool) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	// MkdirAll leaves an existing directory's mode alone.
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(dir, ".sealed-*")
	if err != nil {
		return err
	}
	temp := file.Name()
	defer func() { _ = os.Remove(temp) }()
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if !replace {
		return os.Link(temp, path)
	}
	return os.Rename(temp, path)
}
