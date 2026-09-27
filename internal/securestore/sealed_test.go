package securestore

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
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
	driver, _, _ := newTestSealed(t)
	stuck := &stuckLegacy{fakeLegacy: fakeLegacy{values: map[string][]byte{"a/Y3JlZGVudGlhbHM": []byte("old-password")}}}
	driver.legacy = stuck
	if err := driver.Delete("coned-cli", "a/Y3JlZGVudGlhbHM"); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("Delete() = %v, want the legacy failure reported", err)
	}
	if _, err := driver.Get("coned-cli", "a/Y3JlZGVudGlhbHM"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get() after logout = %v; the deleted value must not come back", err)
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
