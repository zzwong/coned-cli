//go:build darwin && !cgo

package securestore

import "testing"

func TestDarwinNoCGODriverSealsWithoutLegacyMigration(t *testing.T) {
	driver, ok := newKeyringDriver().(sealedDriver)
	if !ok || driver.legacy != nil {
		t.Fatalf("newKeyringDriver() = %#v, want a sealed driver without legacy Keychain access", driver)
	}
}
