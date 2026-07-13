// Package contracts describes sanitized provider response fixtures and their provenance.
package contracts

import (
	"encoding/json"
	"errors"
	"time"
)

const SchemaVersion = 1

type Provenance string

const (
	ConEdLiveVerified    Provenance = "coned-live-verified"
	UpstreamObserved     Provenance = "upstream-opower-observed"
	GreenButtonStandard  Provenance = "green-button-standard"
	SyntheticAdversarial Provenance = "synthetic-adversarial"
)

type Metadata struct {
	SchemaVersion  int        `json:"schema_version"`
	FixtureVersion int        `json:"fixture_version"`
	Operation      string     `json:"operation"`
	Provenance     Provenance `json:"provenance"`
	LastVerified   string     `json:"last_verified"`
	SourceRevision string     `json:"source_revision,omitempty"`
	Claims         []string   `json:"claims,omitempty"`
	NonClaims      []string   `json:"non_claims,omitempty"`
}

type Fixture struct {
	Contract Metadata        `json:"contract"`
	Response json.RawMessage `json:"response"`
}

func Parse(data []byte) (Fixture, error) {
	var fixture Fixture
	if json.Unmarshal(data, &fixture) != nil {
		return Fixture{}, errors.New("invalid contract fixture")
	}
	m := fixture.Contract
	if m.SchemaVersion != SchemaVersion || m.FixtureVersion < 1 || m.Operation == "" || len(fixture.Response) == 0 {
		return Fixture{}, errors.New("invalid contract metadata")
	}
	switch m.Provenance {
	case ConEdLiveVerified, UpstreamObserved, GreenButtonStandard, SyntheticAdversarial:
	default:
		return Fixture{}, errors.New("invalid contract provenance")
	}
	if _, err := time.Parse("2006-01-02", m.LastVerified); err != nil {
		return Fixture{}, errors.New("invalid verification date")
	}
	return fixture, nil
}
