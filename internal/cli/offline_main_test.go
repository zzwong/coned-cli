package cli

import (
	"fmt"
	"github.com/zzwong/coned-cli/internal/testutil/offlinehttp"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	check := offlinehttp.Install()
	code := m.Run()
	if !check() {
		fmt.Fprintln(os.Stderr, "offline suite attempted an unexpected non-loopback HTTP request")
		code = 1
	}
	os.Exit(code)
}
