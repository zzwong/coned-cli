package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestDefaults(t *testing.T) {
	cfg := Default()
	if cfg.BaseURL != DefaultBaseURL || cfg.Profile != "default" || cfg.RequestTimeout != DefaultRequestTimeout {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
	loaded, err := Load(filepath.Join(t.TempDir(), "missing.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(loaded, cfg) {
		t.Fatalf("missing config = %+v, want %+v", loaded, cfg)
	}
}

func TestLoadAppliesDefaultsToPartialConfig(t *testing.T) {
	tests := []struct {
		name string
		data string
		want Config
	}{
		{
			name: "empty object",
			data: "{}",
			want: Default(),
		},
		{
			name: "partial object",
			data: `{"base_url":"https://example.com"}`,
			want: Config{BaseURL: "https://example.com", Profile: "default", RequestTimeout: DefaultRequestTimeout},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, []byte(tt.data), 0600); err != nil {
				t.Fatal(err)
			}
			got, err := Load(path)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("Load = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestLoadRejectsInvalidValues(t *testing.T) {
	for _, data := range []string{
		`{"base_url":"not a URL"}`,
		`{"profile":"   "}`,
		`{"request_timeout":0}`,
	} {
		t.Run(data, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil {
				t.Fatalf("Load accepted invalid config %s", data)
			}
		})
	}
}

func TestSaveHas0600PermissionsAndAtomicReplacement(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	first := Config{BaseURL: "https://one.example", Profile: "one", RequestTimeout: time.Second}
	if err := first.Save(path); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if before.Mode().Perm() != 0600 {
		t.Fatalf("permissions = %o, want 600", before.Mode().Perm())
	}
	second := first
	second.BaseURL = "https://two.example"
	second.RequestTimeout = 2 * time.Hour
	if err := second.Save(path); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(before, after) {
		t.Fatal("replacement reused the original file instead of renaming a temporary file")
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(contents), "two.example") || strings.Contains(string(contents), "one.example") {
		t.Fatalf("unexpected replacement contents: %s", contents)
	}
}

func TestSaveRejectsInvalidValuesWithoutReplacingExistingConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	valid := Config{BaseURL: "https://valid.example", Profile: "valid", RequestTimeout: time.Second}
	if err := valid.Save(path); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	for _, tt := range []struct {
		name string
		cfg  Config
	}{
		{name: "base URL", cfg: Config{BaseURL: "not a URL", Profile: "valid", RequestTimeout: time.Second}},
		{name: "profile", cfg: Config{BaseURL: "https://valid.example", Profile: "   ", RequestTimeout: time.Second}},
		{name: "request timeout", cfg: Config{BaseURL: "https://valid.example", Profile: "valid", RequestTimeout: 0}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.cfg.Save(path); err == nil {
				t.Fatal("Save accepted invalid config")
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(after) != string(before) {
				t.Fatalf("invalid Save replaced config: got %q, want %q", after, before)
			}
		})
	}
}

func TestLoadRejectsMalformedJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte("{not json"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load accepted malformed JSON")
	}
}
