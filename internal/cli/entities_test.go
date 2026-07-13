package cli

import (
	"context"
	"encoding/json"
	"github.com/zzwong/coned-cli/internal/auth"
	"github.com/zzwong/coned-cli/internal/provider"
	"github.com/zzwong/coned-cli/internal/securestore"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeDiscovery struct{ calls int }

func (f *fakeDiscovery) Discover(context.Context, auth.Session) ([]provider.Entity, error) {
	f.calls++
	return []provider.Entity{{Type: "account", ProviderID: "raw-secret-account", Active: true, Provenance: "coned-live-verified"}, {Type: "meter", ProviderID: "raw-secret-meter", ParentProviderID: "raw-secret-account", Active: true, ServiceType: "ELECTRIC", Provenance: "coned-live-verified"}}, nil
}
func TestDemoEntitiesAreDeterministicAndOffline(t *testing.T) {
	deps := Dependencies{Store: securestore.NewMemoryStore(), Clock: time.Now, DemoDiscovery: &provider.Simulator{}}
	first, err := runWithDependencies(t, deps, "", "--demo --json entities list")
	if err != nil {
		t.Fatal(err)
	}
	second, err := runWithDependencies(t, deps, "", "--demo --json entities list")
	if err != nil || first != second || !strings.Contains(first, "\"demo\":true") || strings.Contains(first, "demo-account-a") {
		t.Fatalf("first=%q second=%q err=%v", first, second, err)
	}
}
func TestDemoUsageIsOffline(t *testing.T) {
	deps := Dependencies{Store: securestore.NewMemoryStore(), Clock: time.Now}
	out, err := runWithDependencies(t, deps, "", "--demo --json usage forecast")
	if err != nil || !strings.Contains(out, "account-demo0001") {
		t.Fatalf("out=%q err=%v", out, err)
	}
	out, err = runWithDependencies(t, deps, "", "--demo --json usage reads --aggregate day --from 2026-01-01 --to 2026-01-02")
	if err != nil || !strings.Contains(out, "1.25") {
		t.Fatalf("out=%q err=%v", out, err)
	}
}

func TestDemoRejectsCommandsWithoutOfflineImplementation(t *testing.T) {
	deps := Dependencies{Store: securestore.NewMemoryStore(), Clock: time.Now, DemoDiscovery: &provider.Simulator{}}
	if _, err := runWithDependencies(t, deps, "", "--demo bills list"); err == nil {
		t.Fatal("demo mode allowed live usage command")
	}
}

func TestEntityAliasesAndDefaultsStoreOnlyHandles(t *testing.T) {
	store := securestore.NewMemoryStore()
	if err := auth.SaveSession(store, "default", validSession(time.Now())); err != nil {
		t.Fatal(err)
	}
	discovery := &fakeDiscovery{}
	configPath := filepath.Join(t.TempDir(), "config.json")
	deps := Dependencies{Store: store, Bills: &fakeBills{}, Discovery: discovery, ConfigPath: configPath, Clock: time.Now}
	out, err := runWithDependencies(t, deps, "", "--json entities list")
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(out, "account-")
	handle := out[start : start+20]
	if _, err = runWithDependencies(t, deps, "", "entities alias "+handle+" home"); err != nil {
		t.Fatal(err)
	}
	if _, err = runWithDependencies(t, deps, "", "entities select home"); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(configPath)
	if strings.Contains(string(data), "raw-secret") || !strings.Contains(string(data), "home") || !strings.Contains(string(data), handle) {
		t.Fatalf("config=%s", data)
	}
}
func TestAccountAndMeterSelectorsResolveWithoutExposingProviderIDs(t *testing.T) {
	store := securestore.NewMemoryStore()
	if err := auth.SaveSession(store, "default", validSession(time.Now())); err != nil {
		t.Fatal(err)
	}
	discovery := &fakeDiscovery{}
	opower := &fakeOpower{}
	deps := Dependencies{Store: store, Bills: &fakeBills{}, Opower: opower, Discovery: discovery, Clock: time.Now}
	out, err := runWithDependencies(t, deps, "", "--json entities list")
	if err != nil {
		t.Fatal(err)
	}
	var records []entityRecord
	if json.Unmarshal([]byte(out), &records) != nil {
		t.Fatal(out)
	}
	var account, meter string
	for _, record := range records {
		if record.Type == "account" {
			account = record.Handle
		}
		if record.Type == "meter" {
			meter = record.Handle
		}
	}
	_, err = runWithDependencies(t, deps, "", "--account "+account+" --meter "+meter+" usage summary")
	if err != nil {
		t.Fatal(err)
	}
	if opower.selection.Account != "raw-secret-account" || opower.selection.Meter != "raw-secret-meter" {
		t.Fatalf("selection=%#v", opower.selection)
	}
}

func TestDemoDiagnosticsContainStructureNotValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "schema.json")
	deps := Dependencies{Store: securestore.NewMemoryStore(), Clock: func() time.Time { return time.Unix(0, 0) }, DemoDiscovery: &provider.Simulator{}}
	if _, err := runWithDependencies(t, deps, "", "--demo diagnostics schema --output "+path); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), "demo-account-a") || !strings.Contains(string(data), "schema_version") {
		t.Fatalf("diagnostic=%s", data)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode=%o", info.Mode().Perm())
	}
}
