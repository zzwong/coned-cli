package cli

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

func TestStatusHelpClarifiesLocalScope(t *testing.T) {
	var output bytes.Buffer
	input := strings.NewReader("")
	// Construct the auth command directly: no production dependency setup or
	// configuration loading is needed to render help.
	cmd := newAuthCommand(&Options{}, Dependencies{}, bufio.NewReader(input), input)
	cmd.SetOut(&output)
	cmd.SetErr(&output)
	cmd.SetArgs([]string{"status", "--help"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"local validity and expiry checks",
		"reads the stored session from the configured credential storage",
		"not a passive storage-health check",
		"does not verify whether Con Edison currently accepts the session",
		"authentication timestamp records authentication, not an online verification",
	} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("status help missing %q: %s", want, output.String())
		}
	}
}
