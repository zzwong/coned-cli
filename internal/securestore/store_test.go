package securestore

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/zalando/go-keyring"
)

type recordingKeyringDriver struct {
	getService, getAccount       string
	setService, setAccount       string
	deleteService, deleteAccount string
	getValue                     []byte
	setValue                     []byte
	getErr, setErr, deleteErr    error
}

func (d *recordingKeyringDriver) Get(service, account string) ([]byte, error) {
	d.getService, d.getAccount = service, account
	return d.getValue, d.getErr
}

func (d *recordingKeyringDriver) Set(service, account string, value []byte) error {
	d.setService, d.setAccount = service, account
	d.setValue = append([]byte(nil), value...)
	return d.setErr
}

func (d *recordingKeyringDriver) Delete(service, account string) error {
	d.deleteService, d.deleteAccount = service, account
	return d.deleteErr
}

func TestKeyringAccountEncodesComponentsWithoutCollisions(t *testing.T) {
	if first, second := account("a/b", "c"), account("a", "b/c"); first == second {
		t.Fatalf("accounts collide: %q", first)
	}
	if first, second := account("one", "credentials"), account("two", "credentials"); first == second {
		t.Fatalf("different profiles collide: %q", first)
	}
}

func TestKeyringStoreGetForwardsExactIdentifiersThroughDriver(t *testing.T) {
	driver := &recordingKeyringDriver{getValue: []byte("synthetic-value")}
	store := KeyringStore{driver: driver}

	got, err := store.Get("a/b", "c")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("synthetic-value")) {
		t.Fatalf("Get() = %q, want %q", got, "synthetic-value")
	}
	if driver.getService != "coned-cli" || driver.getAccount != "YS9i/Yw" {
		t.Fatalf("driver identifiers = %q/%q, want %q/%q", driver.getService, driver.getAccount, "coned-cli", "YS9i/Yw")
	}
}

func TestKeyringStoreSetForwardsExactIdentifiersAndValueThroughDriver(t *testing.T) {
	driver := &recordingKeyringDriver{}
	store := KeyringStore{driver: driver}
	value := []byte{0, 1, 0xff}

	if err := store.Set("a/b", "c", value); err != nil {
		t.Fatal(err)
	}
	if driver.setService != "coned-cli" || driver.setAccount != "YS9i/Yw" {
		t.Fatalf("driver identifiers = %q/%q, want %q/%q", driver.setService, driver.setAccount, "coned-cli", "YS9i/Yw")
	}
	if !bytes.Equal(driver.setValue, value) {
		t.Fatalf("driver value = %x, want %x", driver.setValue, value)
	}
}

func TestKeyringStoreDeleteForwardsExactIdentifiersThroughDriver(t *testing.T) {
	driver := &recordingKeyringDriver{}
	store := KeyringStore{driver: driver}

	if err := store.Delete("a/b", "c"); err != nil {
		t.Fatal(err)
	}
	if driver.deleteService != "coned-cli" || driver.deleteAccount != "YS9i/Yw" {
		t.Fatalf("driver identifiers = %q/%q, want %q/%q", driver.deleteService, driver.deleteAccount, "coned-cli", "YS9i/Yw")
	}
}

func TestKeyringStoreMapsDriverNotFoundOnGet(t *testing.T) {
	store := KeyringStore{driver: &recordingKeyringDriver{getErr: ErrNotFound}}

	_, err := store.Get("profile", "key")
	if err != ErrNotFound {
		t.Fatalf("Get() error = %v, want ErrNotFound", err)
	}
}

func TestKeyringStoreMapsDriverNotFoundOnDelete(t *testing.T) {
	store := KeyringStore{driver: &recordingKeyringDriver{deleteErr: ErrNotFound}}

	if err := store.Delete("profile", "key"); err != ErrNotFound {
		t.Fatalf("Delete() error = %v, want ErrNotFound", err)
	}
}

func TestKeyringStoreWrapsDriverGetErrorPreservingIdentityAndContext(t *testing.T) {
	backendErr := errors.New("backend get failure")
	store := KeyringStore{driver: &recordingKeyringDriver{getErr: backendErr}}

	_, err := store.Get("profile", "key")
	if !errors.Is(err, backendErr) {
		t.Fatalf("Get() error = %v, want errors.Is(error, backendErr)", err)
	}
	if !strings.Contains(err.Error(), "get secure value") {
		t.Fatalf("Get() error = %v, want get operation context", err)
	}
}

func TestKeyringStoreWrapsGoKeyringSetErrorPreservingIdentityAndContext(t *testing.T) {
	store := KeyringStore{driver: &recordingKeyringDriver{setErr: keyring.ErrSetDataTooBig}}

	err := store.Set("profile", "key", []byte("synthetic-value"))
	if !errors.Is(err, keyring.ErrSetDataTooBig) {
		t.Fatalf("Set() error = %v, want errors.Is(error, keyring.ErrSetDataTooBig)", err)
	}
	if !strings.Contains(err.Error(), "set secure value") {
		t.Fatalf("Set() error = %v, want set operation context", err)
	}
}

func TestKeyringStoreWrapsDriverDeleteErrorPreservingIdentityAndContext(t *testing.T) {
	backendErr := errors.New("backend delete failure")
	store := KeyringStore{driver: &recordingKeyringDriver{deleteErr: backendErr}}

	err := store.Delete("profile", "key")
	if !errors.Is(err, backendErr) {
		t.Fatalf("Delete() error = %v, want errors.Is(error, backendErr)", err)
	}
	if !strings.Contains(err.Error(), "delete secure value") {
		t.Fatalf("Delete() error = %v, want delete operation context", err)
	}
}

func TestMemoryStoreProfileIsolation(t *testing.T) {
	store := NewMemoryStore()
	if err := store.Set("one", "credentials", []byte("secret-one")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get("two", "credentials"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get other profile error = %v, want ErrNotFound", err)
	}
	value, err := store.Get("one", "credentials")
	if err != nil || string(value) != "secret-one" {
		t.Fatalf("Get = %q, %v", value, err)
	}
}

func TestMemoryStoreDeleteAndNotFound(t *testing.T) {
	store := NewMemoryStore()
	if err := store.Delete("default", "session"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Delete missing error = %v, want ErrNotFound", err)
	}
	if err := store.Set("default", "session", []byte("token")); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete("default", "session"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get("default", "session"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get deleted error = %v, want ErrNotFound", err)
	}
	if err := store.Delete("default", "session"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second Delete error = %v, want ErrNotFound", err)
	}
}
