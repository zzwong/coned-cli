//go:build darwin && !cgo

package securestore

// Without cgo there is no native Keychain access, so values stored directly
// in the Keychain by earlier builds cannot be migrated.
func newKeyringDriver() keyringDriver {
	return newSealedDriver(nil)
}
