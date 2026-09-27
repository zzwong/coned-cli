//go:build darwin

package securestore

import (
	"os"
	"path/filepath"
)

func newSealedDriver(legacy keyringDriver) sealedDriver {
	dir := ""
	if base, err := os.UserConfigDir(); err == nil {
		dir = filepath.Join(base, "coned", "secrets")
	}
	return sealedDriver{dir: dir, keys: securityToolKeys{tool: "/usr/bin/security"}, legacy: legacy}
}
