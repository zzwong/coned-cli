package securestore

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeKeys struct {
	key   []byte
	err   error
	calls int
}

func (k *fakeKeys) Key(_ string, create bool) ([]byte, error) {
	k.calls++
	if k.err != nil {
		return nil, k.err
	}
	if k.key == nil {
		if !create {
			return nil, ErrNotFound
		}
		k.key = bytes.Repeat([]byte{9}, keyLength)
	}
	return k.key, nil
}

type fakeLegacy struct {
	values  map[string][]byte
	getErr  error
	deleted []string
}

func (l *fakeLegacy) Get(_, account string) ([]byte, error) {
	if l.getErr != nil {
		return nil, l.getErr
	}
	value, ok := l.values[account]
	if !ok {
		return nil, ErrNotFound
	}
	return value, nil
}
func (l *fakeLegacy) Set(_, account string, value []byte) error {
	l.values[account] = value
	return nil
}
func (l *fakeLegacy) Delete(_, account string) error {
	l.deleted = append(l.deleted, account)
	if _, ok := l.values[account]; !ok {
		return ErrNotFound
	}
	delete(l.values, account)
	return nil
}

func newTestSealed(t *testing.T) (sealedDriver, *fakeKeys, *fakeLegacy) {
	t.Helper()
	keys := &fakeKeys{}
	legacy := &fakeLegacy{values: map[string][]byte{}}
	return sealedDriver{dir: filepath.Join(t.TempDir(), "secrets"), keys: keys, legacy: legacy}, keys, legacy
}

func TestSealedDriverRoundTripsPrivately(t *testing.T) {
	driver, _, _ := newTestSealed(t)
	secret := []byte("synthetic-session-cookie")
	if err := driver.Set("coned-cli", "cHJvZmlsZQ/c2Vzc2lvbg", secret); err != nil {
		t.Fatal(err)
	}
	got, err := driver.Get("coned-cli", "cHJvZmlsZQ/c2Vzc2lvbg")
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("Get() = %q, %v", got, err)
	}
	path, _ := driver.path("coned-cli", "cHJvZmlsZQ/c2Vzc2lvbg")
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("sealed file mode = %v, %v; want 0600", info.Mode().Perm(), err)
	}
	if dir, err := os.Stat(driver.dir); err != nil || dir.Mode().Perm() != 0o700 {
		t.Fatalf("secret directory mode = %v, %v; want 0700", dir.Mode().Perm(), err)
	}
	if raw, _ := os.ReadFile(path); bytes.Contains(raw, secret) {
		t.Fatal("sealed file contains the plaintext")
	}
}

func TestSealedDriverLongAccountRoundTrips(t *testing.T) {
	for _, profile := range []struct {
		name  string
		value string
	}{
		{name: "ascii", value: strings.Repeat("p", 200)},
		{name: "multibyte", value: strings.Repeat("電", 80)},
	} {
		t.Run(profile.name, func(t *testing.T) {
			driver, _, _ := newTestSealed(t)
			account := account(profile.value, "session")
			secret := []byte("synthetic-long-profile-secret")
			if err := driver.Set("coned-cli", account, secret); err != nil {
				t.Fatalf("Set() with long account: %v", err)
			}
			got, err := driver.Get("coned-cli", account)
			if err != nil || !bytes.Equal(got, secret) {
				t.Fatalf("Get() = %q, %v", got, err)
			}
			path, err := driver.path("coned-cli", account)
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256([]byte(account))
			expectedName := "coned-cli.sha256-" + hex.EncodeToString(digest[:])
			if filepath.Base(path) != expectedName {
				t.Fatalf("sealed basename = %q; want %q", filepath.Base(path), expectedName)
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0o600 {
				t.Fatalf("sealed file mode = %v, %v; want 0600", info.Mode().Perm(), err)
			}
			info, err = os.Stat(driver.dir)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0o700 {
				t.Fatalf("sealed directory mode = %v, %v; want 0700", info.Mode().Perm(), err)
			}
			if raw, err := os.ReadFile(path); err != nil || bytes.Contains(raw, secret) {
				t.Fatalf("sealed file contains plaintext or cannot be read: %v", err)
			}
			if err := driver.Delete("coned-cli", account); err != nil {
				t.Fatalf("Delete() = %v", err)
			}
			if _, err := driver.Get("coned-cli", account); !errors.Is(err, ErrNotFound) {
				t.Fatalf("Get() after Delete() = %v, want ErrNotFound", err)
			}
		})
	}
}

func TestSealedDriverKeepsExistingFilenameThrough255Bytes(t *testing.T) {
	driver, _, _ := newTestSealed(t)
	profile := strings.Repeat("p", 177)
	key := strings.Repeat("k", 6)
	encodedAccount := account(profile, key)
	expected := "coned-cli." + strings.ReplaceAll(encodedAccount, "/", ".")
	if len(expected) != 255 {
		t.Fatalf("fixture filename is %d bytes; want exactly 255", len(expected))
	}
	path, err := driver.path("coned-cli", encodedAccount)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(path) != expected {
		t.Fatalf("path basename changed at the filesystem limit: got %q, want %q", filepath.Base(path), expected)
	}
	if err := driver.Set("coned-cli", encodedAccount, []byte("boundary-secret")); err != nil {
		t.Fatalf("Set() at the 255-byte limit: %v", err)
	}
	if got, err := driver.Get("coned-cli", encodedAccount); err != nil || string(got) != "boundary-secret" {
		t.Fatalf("Get() = %q, %v", got, err)
	}

	overAccount := account(strings.Repeat("p", 176), strings.Repeat("k", 7))
	overName := "coned-cli." + strings.ReplaceAll(overAccount, "/", ".")
	if len(overName) != 256 {
		t.Fatalf("oversized fixture filename is %d bytes; want exactly 256", len(overName))
	}
	digest := sha256.Sum256([]byte(overAccount))
	path, err = driver.path("coned-cli", overAccount)
	if err != nil {
		t.Fatal(err)
	}
	if want := "coned-cli.sha256-" + hex.EncodeToString(digest[:]); filepath.Base(path) != want {
		t.Fatalf("256-byte basename = %q; want bounded hash name %q", filepath.Base(path), want)
	}
}

func TestSealedDriverReadsCiphertextAtTheExistingShortFilename(t *testing.T) {
	driver, keys, _ := newTestSealed(t)
	service := "coned-cli"
	encodedAccount := account("existing-profile", "session")
	secret := []byte("preexisting-sealed-value")
	key, err := keys.Key(service, true)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := seal(key, service, encodedAccount, secret)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(driver.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	legacyPath := filepath.Join(driver.dir, service+"."+strings.ReplaceAll(encodedAccount, "/", "."))
	if err := os.WriteFile(legacyPath, sealed, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := driver.Get(service, encodedAccount)
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("Get() for existing filename = %q, %v", got, err)
	}
}

func TestSealedDriverSeparatesLongAccountsAndAuthenticatesTheirIdentity(t *testing.T) {
	driver, _, _ := newTestSealed(t)
	firstAccount := account(strings.Repeat("a", 200), "session")
	secondAccount := account(strings.Repeat("b", 200), "session")
	firstPath, err := driver.path("coned-cli", firstAccount)
	if err != nil {
		t.Fatal(err)
	}
	secondPath, err := driver.path("coned-cli", secondAccount)
	if err != nil {
		t.Fatal(err)
	}
	if firstPath == secondPath {
		t.Fatal("distinct long account identifiers share one sealed filename")
	}
	firstSecret := []byte("first-long-profile-secret")
	secondSecret := []byte("second-long-profile-secret")
	if err := driver.Set("coned-cli", firstAccount, firstSecret); err != nil {
		t.Fatal(err)
	}
	if err := driver.Set("coned-cli", secondAccount, secondSecret); err != nil {
		t.Fatal(err)
	}
	if got, err := driver.Get("coned-cli", firstAccount); err != nil || !bytes.Equal(got, firstSecret) {
		t.Fatalf("first Get() = %q, %v", got, err)
	}
	if got, err := driver.Get("coned-cli", secondAccount); err != nil || !bytes.Equal(got, secondSecret) {
		t.Fatalf("second Get() = %q, %v", got, err)
	}
	firstSealed, err := os.ReadFile(firstPath)
	if err != nil {
		t.Fatal(err)
	}
	secondSealed, err := os.ReadFile(secondPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(firstPath, secondSealed, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secondPath, firstSealed, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, encodedAccount := range []string{firstAccount, secondAccount} {
		if _, err := driver.Get("coned-cli", encodedAccount); !errors.Is(err, ErrNotFound) {
			t.Fatalf("Get() after swapping ciphertext for %q = %v, want ErrNotFound", encodedAccount[:12], err)
		}
	}
}

func TestSealedDriverMigratesLongLegacyItemsOnce(t *testing.T) {
	driver, _, legacy := newTestSealed(t)
	encodedAccount := account(strings.Repeat("l", 200), "session")
	secret := []byte("legacy-long-profile-secret")
	legacy.values[encodedAccount] = secret
	got, err := driver.Get("coned-cli", encodedAccount)
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("Get() = %q, %v", got, err)
	}
	if _, ok := legacy.values[encodedAccount]; ok {
		t.Fatal("legacy item remained after migration")
	}
	path, err := driver.path("coned-cli", encodedAccount)
	if err != nil {
		t.Fatal(err)
	}
	if len(filepath.Base(path)) > 255 {
		t.Fatalf("migrated basename is %d bytes; want at most 255", len(filepath.Base(path)))
	}
	legacy.getErr = errors.New("legacy must not be read again")
	if got, err := driver.Get("coned-cli", encodedAccount); err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("second Get() = %q, %v", got, err)
	}
}

func TestSealedDriverReadsUnopenableValuesAsAbsent(t *testing.T) {
	driver, keys, _ := newTestSealed(t)
	for _, account := range []string{"a/c2Vzc2lvbg", "a/Y3JlZGVudGlhbHM"} {
		if err := driver.Set("coned-cli", account, []byte("value-for-"+account)); err != nil {
			t.Fatal(err)
		}
	}
	session, _ := driver.path("coned-cli", "a/c2Vzc2lvbg")
	credentials, _ := driver.path("coned-cli", "a/Y3JlZGVudGlhbHM")
	raw, _ := os.ReadFile(credentials)
	if err := os.WriteFile(session, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := driver.Get("coned-cli", "a/c2Vzc2lvbg"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("value moved to another entry: err = %v, want ErrNotFound", err)
	}
	raw[len(raw)-1] ^= 1
	if err := os.WriteFile(credentials, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := driver.Get("coned-cli", "a/Y3JlZGVudGlhbHM"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("tampered value: err = %v, want ErrNotFound", err)
	}

	keys.key = bytes.Repeat([]byte{4}, keyLength)
	if _, err := driver.Get("coned-cli", "a/c2Vzc2lvbg"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("value sealed under a replaced key: err = %v, want ErrNotFound", err)
	}
	if err := driver.Set("coned-cli", "a/c2Vzc2lvbg", []byte("fresh")); err != nil {
		t.Fatal(err)
	}
	if got, err := driver.Get("coned-cli", "a/c2Vzc2lvbg"); err != nil || string(got) != "fresh" {
		t.Fatalf("after replacement: %q, %v", got, err)
	}
}

func TestSealedDriverDeleteStopsMigrationOfAStuckLegacyItem(t *testing.T) {
	for _, tc := range []struct {
		name    string
		account string
	}{
		{name: "short", account: "a/Y3JlZGVudGlhbHM"},
		{name: "long", account: account(strings.Repeat("p", 200), "credentials")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			driver, _, _ := newTestSealed(t)
			stuck := &stuckLegacy{fakeLegacy: fakeLegacy{values: map[string][]byte{tc.account: []byte("old-password")}}}
			driver.legacy = stuck
			if err := driver.Delete("coned-cli", tc.account); err != nil {
				t.Fatalf("Delete() = %v; a stuck legacy item must not fail logout", err)
			}
			if _, err := driver.Get("coned-cli", tc.account); !errors.Is(err, ErrNotFound) {
				t.Fatalf("Get() after logout = %v; the deleted value must not come back", err)
			}
		})
	}
}

type stuckLegacy struct{ fakeLegacy }

func (l *stuckLegacy) Delete(string, string) error { return ErrAccessDenied }

func TestSealedDriverMigrationNeverOverwritesANewerValue(t *testing.T) {
	driver, _, legacy := newTestSealed(t)
	legacy.values["a/c2Vzc2lvbg"] = []byte("stale-legacy")
	if err := driver.Set("coned-cli", "a/c2Vzc2lvbg", []byte("newer")); err != nil {
		t.Fatal(err)
	}
	legacy.values["a/c2Vzc2lvbg"] = []byte("stale-legacy")
	got, err := driver.migrate("coned-cli", "a/c2Vzc2lvbg")
	if err != nil || string(got) != "newer" {
		t.Fatalf("migrate() = %q, %v; want the newer sealed value", got, err)
	}
}

func TestSealedDriverTightensAnExistingDirectory(t *testing.T) {
	driver, _, _ := newTestSealed(t)
	if err := os.MkdirAll(driver.dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := driver.Set("coned-cli", "a/c2Vzc2lvbg", []byte("value")); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(driver.dir); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("directory mode = %v, %v; want 0700", info.Mode().Perm(), err)
	}
}

func TestSealedDriverMigratesLegacyItemsOnce(t *testing.T) {
	driver, _, legacy := newTestSealed(t)
	legacy.values["a/c2Vzc2lvbg"] = []byte("legacy-session")
	got, err := driver.Get("coned-cli", "a/c2Vzc2lvbg")
	if err != nil || string(got) != "legacy-session" {
		t.Fatalf("Get() = %q, %v", got, err)
	}
	if _, stillThere := legacy.values["a/c2Vzc2lvbg"]; stillThere {
		t.Fatal("legacy item was not removed after migration")
	}
	legacy.getErr = errors.New("legacy must not be read again")
	if got, err := driver.Get("coned-cli", "a/c2Vzc2lvbg"); err != nil || string(got) != "legacy-session" {
		t.Fatalf("second Get() = %q, %v", got, err)
	}
}

func TestSealedDriverReportsUnreadableLegacyItems(t *testing.T) {
	driver, _, legacy := newTestSealed(t)
	legacy.getErr = ErrAccessDenied
	if _, err := driver.Get("coned-cli", "a/c2Vzc2lvbg"); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("err = %v, want ErrAccessDenied so the user is told to log in", err)
	}
	if err := driver.Set("coned-cli", "a/c2Vzc2lvbg", []byte("fresh")); err != nil {
		t.Fatal(err)
	}
	if len(legacy.deleted) != 1 {
		t.Fatalf("legacy deletes = %v, want the stale item removed on write", legacy.deleted)
	}
	if got, err := driver.Get("coned-cli", "a/c2Vzc2lvbg"); err != nil || string(got) != "fresh" {
		t.Fatalf("Get() = %q, %v", got, err)
	}
}

func TestSealedDriverMissingKeyAndDelete(t *testing.T) {
	driver, keys, _ := newTestSealed(t)
	if _, err := driver.Get("coned-cli", "a/c2Vzc2lvbg"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty store: err = %v", err)
	}
	if err := driver.Set("coned-cli", "a/c2Vzc2lvbg", []byte("value")); err != nil {
		t.Fatal(err)
	}
	keys.key = nil
	if _, err := driver.Get("coned-cli", "a/c2Vzc2lvbg"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("value without its key: err = %v, want ErrNotFound", err)
	}
	if err := driver.Delete("coned-cli", "a/c2Vzc2lvbg"); err != nil {
		t.Fatal(err)
	}
	if err := driver.Delete("coned-cli", "a/c2Vzc2lvbg"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("repeated Delete() = %v, want ErrNotFound", err)
	}
	keys.err = ErrAccessDenied
	if err := driver.Set("coned-cli", "a/c2Vzc2lvbg", []byte("value")); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("locked keychain: Set() = %v", err)
	}
}
