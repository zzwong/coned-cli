package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zzwong/coned-cli/internal/auth"
	"github.com/zzwong/coned-cli/internal/coned"
	"github.com/zzwong/coned-cli/internal/config"
	"github.com/zzwong/coned-cli/internal/identity"
	"github.com/zzwong/coned-cli/internal/provider"
	"github.com/zzwong/coned-cli/internal/securestore"
)

type configProbeOpower struct {
	selection    coned.EntitySelection
	resource     string
	remaining    time.Duration
	usedSelected bool
}

func (p *configProbeOpower) Fetch(ctx context.Context, _ auth.Session, resource string) (any, error) {
	p.resource = resource
	if deadline, ok := ctx.Deadline(); ok {
		p.remaining = time.Until(deadline)
	}
	return []coned.UsageRead{{Start: "2026-01-01", End: "2026-01-02", Unit: "kWh", Value: 1}}, nil
}

func (p *configProbeOpower) FetchSelected(ctx context.Context, session auth.Session, resource string, selection coned.EntitySelection) (any, error) {
	p.selection = selection
	p.usedSelected = true
	return p.Fetch(ctx, session, resource)
}

type configProbeDiscovery struct{}

func (configProbeDiscovery) Discover(context.Context, auth.Session) ([]provider.Entity, error) {
	return []provider.Entity{{Type: "account", ProviderID: "synthetic-provider-account", Active: true}}, nil
}

func TestProductionEntryPointLoadsProfileTimeoutAndSelection(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	profile := "synthetic-profile"
	store := securestore.NewMemoryStore()
	manager, err := identity.Load(store, profile, true)
	if err != nil {
		t.Fatal(err)
	}
	accountHandle, err := manager.Handle(identity.Entity{Type: "account", Namespace: "coned-opower", ProviderID: "synthetic-provider-account"})
	if err != nil {
		t.Fatal(err)
	}
	session := auth.Session{AuthenticatedAt: time.Now(), Cookies: []auth.Cookie{{Name: "synthetic-session", Value: "synthetic-value"}}}
	if err := auth.SaveSession(store, profile, session); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Profile = profile
	cfg.RequestTimeout = 7 * time.Second
	cfg.Selections = map[string]config.Selection{profile: {DefaultAccount: accountHandle}}
	configPath := config.DefaultPath()
	if err := cfg.Save(configPath); err != nil {
		t.Fatal(err)
	}

	deps := productionDependencies()
	if deps.ConfigPath != configPath {
		t.Fatalf("production config path = %q, want %q", deps.ConfigPath, configPath)
	}
	deps.Store = store
	deps.Opower = &configProbeOpower{}
	deps.Discovery = configProbeDiscovery{}
	deps.Clock = time.Now
	var stdout, stderr bytes.Buffer
	code := execute([]string{"usage", "summary", "--json-envelope"}, bytes.NewReader(nil), &stdout, &stderr, deps)
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	var envelope struct {
		Command string `json:"command"`
		OK      bool   `json:"ok"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
		t.Fatalf("stdout is not a production envelope: %q: %v", stdout.String(), err)
	}
	probe := deps.Opower.(*configProbeOpower)
	if envelope.Command != "usage.summary" || !envelope.OK || !probe.usedSelected || probe.resource != "summary" || probe.selection.Account != "synthetic-provider-account" {
		t.Fatalf("profile or selection was not loaded: envelope=%#v probe=%#v", envelope, probe)
	}
	if probe.remaining < 6*time.Second || probe.remaining > 7*time.Second {
		t.Fatalf("configured request timeout was not applied: remaining=%s", probe.remaining)
	}
	if bytes.Contains(stdout.Bytes(), []byte("synthetic-provider-account")) || bytes.Contains(stdout.Bytes(), []byte("synthetic-value")) {
		t.Fatalf("private fixture value leaked to stdout: %q", stdout.String())
	}
	if _, err := os.Stat(configPath); err != nil {
		t.Fatal(err)
	}
}
