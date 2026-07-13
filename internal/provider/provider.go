// Package provider defines normalized entity discovery for live and simulated providers.
package provider

import (
	"context"
	"errors"

	"github.com/zzwong/coned-cli/internal/auth"
)

type Entity struct {
	Type             string `json:"type"`
	ProviderID       string `json:"-"`
	ParentProviderID string `json:"-"`
	ServiceType      string `json:"service_type,omitempty"`
	ReadResolution   string `json:"read_resolution,omitempty"`
	Unit             string `json:"unit,omitempty"`
	Active           bool   `json:"active"`
	Provenance       string `json:"provenance"`
	ContractVersion  int    `json:"contract_version"`
	LastVerified     string `json:"last_verified"`
}
type Discovery interface {
	Discover(context.Context, auth.Session) ([]Entity, error)
}

var ErrDemoFailure = errors.New("synthetic provider failure")

type Simulator struct {
	Scenario string
	calls    int
}

func (s *Simulator) Calls() int { return s.calls }
func (s *Simulator) Discover(context.Context, auth.Session) ([]Entity, error) {
	s.calls++
	if s.Scenario == "failure" {
		return nil, ErrDemoFailure
	}
	entities := []Entity{
		{Type: "account", ProviderID: "demo-account-a", Active: true, Provenance: "synthetic-adversarial"},
		{Type: "account", ProviderID: "demo-account-b", Active: false, Provenance: "synthetic-adversarial"},
		{Type: "premise", ProviderID: "demo-premise-a", ParentProviderID: "demo-account-a", Active: true, Provenance: "synthetic-adversarial"},
		{Type: "meter", ProviderID: "demo-meter-electric", ParentProviderID: "demo-account-a", ServiceType: "ELECTRIC", ReadResolution: "HOUR", Unit: "KWH", Active: true, Provenance: "synthetic-adversarial"},
		{Type: "meter", ProviderID: "demo-meter-gas", ParentProviderID: "demo-account-a", ServiceType: "GAS", ReadResolution: "DAY", Unit: "THERM", Active: true, Provenance: "synthetic-adversarial"},
		{Type: "register", ProviderID: "demo-register-import", ParentProviderID: "demo-meter-electric", ServiceType: "ELECTRIC", ReadResolution: "HOUR", Unit: "KWH", Active: true, Provenance: "synthetic-adversarial"},
	}
	for i := range entities {
		entities[i].ContractVersion = 1
		entities[i].LastVerified = "2026-07-12"
	}
	return entities, nil
}
