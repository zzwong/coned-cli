//go:build darwin && !cgo

package securestore

import (
	"errors"
	"strings"
	"testing"
)

func TestDarwinNoCGODriverFailsClosedWithoutSecretData(t *testing.T) {
	const secret = "synthetic-secret"
	driver := newKeyringDriver()

	if _, err := driver.Get("coned-cli", secret); err == nil || errors.Is(err, ErrNotFound) || strings.Contains(err.Error(), secret) {
		t.Fatalf("Get() error = %v, want sanitized unavailable error", err)
	}
	if err := driver.Set("coned-cli", secret, []byte(secret)); err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("Set() error = %v, want sanitized unavailable error", err)
	}
	if err := driver.Delete("coned-cli", secret); err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("Delete() error = %v, want sanitized unavailable error", err)
	}
}
