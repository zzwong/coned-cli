package contracts

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestFixturesHaveVersionedProvenanceAndNoSecrets(t *testing.T) {
	files, err := filepath.Glob("../coned/testdata/contracts/*.json")
	if err != nil || len(files) == 0 {
		t.Fatal("fixtures missing")
	}
	email := regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+`)
	longDigits := regexp.MustCompile(`\b[0-9]{9,}\b`)
	for _, path := range files {
		data, _ := os.ReadFile(path)
		fixture, err := Parse(data)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		lower := strings.ToLower(string(data))
		if email.Match(data) || longDigits.Match(data) || strings.Contains(lower, "bearer ") || strings.Contains(lower, "sig=") || strings.Contains(lower, "cookie:") {
			t.Fatalf("possible secret in %s", path)
		}
		if fixture.Contract.LastVerified == "" || fixture.Contract.FixtureVersion < 1 {
			t.Fatal(path)
		}
	}
}
