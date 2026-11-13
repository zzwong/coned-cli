package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zzwong/coned-cli/internal/auth"
	"github.com/zzwong/coned-cli/internal/provider"
)

type doctorForbiddenStore struct{}

func (doctorForbiddenStore) Get(string, string) ([]byte, error) { panic("doctor read a credential") }
func (doctorForbiddenStore) Set(string, string, []byte) error   { panic("doctor wrote a credential") }
func (doctorForbiddenStore) Delete(string, string) error        { panic("doctor deleted a credential") }

// Nil embedded operational interfaces panic on any method invocation. The
// local command must not use even a read-only provider service.
type doctorForbiddenServices struct {
	auth.Authenticator
	BillService
	OpowerService
	provider.Discovery
}

func doctorDependencies() Dependencies {
	service := doctorForbiddenServices{}
	return Dependencies{Store: doctorForbiddenStore{}, Authenticator: service, Bills: service, Opower: service, Discovery: service, Clock: func() time.Time { return time.Unix(0, 0) }}
}

func TestDoctorLocalEnvelopeNeverClaimsReadiness(t *testing.T) {
	var out, errout bytes.Buffer
	if code := ExecuteCLI([]string{"doctor", "--json-envelope"}, strings.NewReader(""), &out, &errout, doctorDependencies()); code != 0 {
		t.Fatalf("code %d: %s", code, errout.String())
	}
	var envelope struct {
		OK      bool         `json:"ok"`
		Command string       `json:"command"`
		Data    doctorReport `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if !envelope.OK || envelope.Command != "doctor" || envelope.Data.Ready != nil || envelope.Data.Mode != "local" {
		t.Fatalf("unexpected report: %s", out.String())
	}
	want := []string{"build", "platform", "storage.backend", "config", "session.live", "selection.account", "selection.meter", "destination.metadata"}
	if len(envelope.Data.Checks) != len(want) {
		t.Fatal(envelope.Data)
	}
	for i, id := range want {
		if envelope.Data.Checks[i].ID != id {
			t.Fatal(envelope.Data)
		}
	}
	if errout.Len() != 0 {
		t.Fatalf("stderr: %s", errout.String())
	}
}

func TestDoctorInvalidConfigurationKeepsSafeCompleteReport(t *testing.T) {
	var out, errout bytes.Buffer
	deps := doctorDependencies()
	deps.ConfigPath = filepath.Join(t.TempDir(), "private-config-marker.json")
	if err := os.WriteFile(deps.ConfigPath, []byte(`{"private-config-marker":`), 0600); err != nil {
		t.Fatal(err)
	}
	code := ExecuteCLI([]string{"doctor", "--profile=private-profile-marker", "--json-envelope"}, strings.NewReader(""), &out, &errout, deps)
	if code != 1 {
		t.Fatalf("code %d: %s", code, out.String())
	}
	var envelope struct {
		OK    bool         `json:"ok"`
		Data  doctorReport `json:"data"`
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(out.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.OK || envelope.Data.Ready == nil || *envelope.Data.Ready || len(envelope.Data.Checks) != 8 || envelope.Data.Checks[3].Status != "failed" || envelope.Error.Code != "internal_error" {
		t.Fatal(out.String())
	}
	for _, marker := range []string{"private-config-marker", "private-profile-marker"} {
		if strings.Contains(out.String()+errout.String(), marker) {
			t.Fatal("private marker leaked")
		}
	}
}

func TestDoctorHumanAndJSONLocalResults(t *testing.T) {
	for _, args := range [][]string{{"doctor"}, {"doctor", "--json"}} {
		var out, errout bytes.Buffer
		if code := ExecuteCLI(args, strings.NewReader(""), &out, &errout, doctorDependencies()); code != 0 {
			t.Fatalf("%v: %d %s", args, code, errout.String())
		}
		if !strings.Contains(out.String(), "session.live") || !strings.Contains(out.String(), "not_checked") {
			t.Fatal(out.String())
		}
	}
}

func TestDoctorRejectsUnsupportedOnlineAndDestinationModes(t *testing.T) {
	for _, flag := range []string{"--online", "--directory=/synthetic"} {
		var out, errout bytes.Buffer
		if code := ExecuteCLI([]string{"doctor", flag, "--json-envelope"}, strings.NewReader(""), &out, &errout, doctorDependencies()); code != 2 {
			t.Fatalf("%s: code %d %s", flag, code, out.String())
		}
	}
}

func TestDoctorHumanArgumentsAreSafeAndExitTwo(t *testing.T) {
	for _, args := range [][]string{{"doctor", "private-marker"}, {"doctor", "--timeout=private-marker"}, {"doctor", "--private-marker"}, {"doctor", "--directory=private-marker"}} {
		var out, errout bytes.Buffer
		code := ExecuteCLI(args, strings.NewReader(""), &out, &errout, doctorDependencies())
		if code != 2 {
			t.Fatalf("%v: code %d, %s %s", args, code, out.String(), errout.String())
		}
		if strings.Contains(out.String()+errout.String(), "private-marker") {
			t.Fatal("argument marker leaked")
		}
	}
}
