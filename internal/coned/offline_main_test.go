package coned

import (
	"fmt"
	"github.com/zzwong/coned-cli/internal/testutil/offlinehttp"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	// Retain the existing explicitly opted-in live contract test. The ordinary
	// qualification suite always sets CONED_LIVE_TEST=0 and cannot use this path.
	if os.Getenv("CONED_LIVE_TEST") == "1" {
		os.Exit(m.Run())
	}
	check := offlinehttp.Install()
	code := m.Run()
	if !check() {
		fmt.Fprintln(os.Stderr, "offline suite attempted an unexpected non-loopback HTTP request")
		code = 1
	}
	os.Exit(code)
}
