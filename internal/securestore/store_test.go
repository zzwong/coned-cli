package securestore

import (
	"errors"
	"testing"
)

func TestKeyringAccountEncodesComponentsWithoutCollisions(t *testing.T) {
	if first, second := account("a/b", "c"), account("a", "b/c"); first == second {
		t.Fatalf("accounts collide: %q", first)
	}
	if first, second := account("one", "credentials"), account("two", "credentials"); first == second {
		t.Fatalf("different profiles collide: %q", first)
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
