package securestore

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// stubSecurityTool imitates /usr/bin/security: find-generic-password prints the
// stored password or exits 44, and interactive mode stores the -w value it
// reads on standard input. It records argv so tests can check the key never
// appears there.
func stubSecurityTool(t *testing.T, exitCode string) (string, string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("stub is a shell script")
	}
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	script := `#!/bin/sh
echo "$*" >> "` + state + `.argv"
if [ -n "` + exitCode + `" ]; then exit ` + exitCode + `; fi
case "$1" in
find-generic-password) [ -f "` + state + `" ] || exit 44; cat "` + state + `" ;;
-i) read -r cmd; set -- $cmd; while [ $# -gt 1 ]; do [ "$1" = "-w" ] && printf '%s\n' "$2" > "` + state + `"; shift; done ;;
esac
`
	tool := filepath.Join(dir, "security")
	if err := os.WriteFile(tool, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return tool, state + ".argv"
}

func TestSecurityToolKeysCreateOnceAndKeepTheKeyOffArgv(t *testing.T) {
	tool, argv := stubSecurityTool(t, "")
	keys := securityToolKeys{tool: tool}
	if _, err := keys.Key("coned-cli", false); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing key without create: err = %v", err)
	}
	first, err := keys.Key("coned-cli", true)
	if err != nil || len(first) != keyLength {
		t.Fatalf("created key = %d bytes, %v", len(first), err)
	}
	second, err := keys.Key("coned-cli", true)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatal("a second call replaced the stored key")
	}
	recorded, _ := os.ReadFile(argv)
	if bytes.Contains(recorded, []byte(base64.StdEncoding.EncodeToString(first))) {
		t.Fatalf("key appeared on a command line: %q", recorded)
	}
}

func TestSecurityToolKeysMapExitCodes(t *testing.T) {
	for code, want := range map[string]error{"36": ErrLocked, "51": ErrLocked, "128": ErrLocked, "1": errKeyTool} {
		tool, _ := stubSecurityTool(t, code)
		if _, err := (securityToolKeys{tool: tool}).Key("coned-cli", false); !errors.Is(err, want) {
			t.Fatalf("exit %s: err = %v, want %v", code, err, want)
		}
	}
}
