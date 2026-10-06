package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zzwong/coned-cli/internal/auth"
	"github.com/zzwong/coned-cli/internal/coned"
	"github.com/zzwong/coned-cli/internal/identity"
	"github.com/zzwong/coned-cli/internal/provider"
	"github.com/zzwong/coned-cli/internal/securestore"
)

type envelopeListBills struct{ err error }

func (b envelopeListBills) ListBills(context.Context, auth.Session) ([]coned.Bill, error) {
	if b.err != nil {
		return nil, b.err
	}
	return []coned.Bill{{ID: "bill-public-1", Date: "2026-02-15"}}, nil
}
func (envelopeListBills) DownloadBill(context.Context, auth.Session, string, io.Writer) error {
	return nil
}

func executeEnvelopeForTest(t *testing.T, deps Dependencies, input string, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := ExecuteCLI(args, strings.NewReader(input), &stdout, &stderr, deps)
	return code, stdout.String(), stderr.String()
}

func decodeEnvelopeForTest(t *testing.T, output string) map[string]any {
	t.Helper()
	var got map[string]any
	if err := json.Unmarshal([]byte(output), &got); err != nil {
		t.Fatalf("stdout is not one JSON envelope: %q: %v", output, err)
	}
	return got
}

func TestExecuteCLIEnvelopeInterceptsCobraFailures(t *testing.T) {
	deps := billsDependencies(t, envelopeListBills{})
	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "unknown flag after command", args: []string{"bills", "list", "--json-envelope", "--secret-canary-flag"}},
		{name: "unknown command", args: []string{"--json-envelope", "not-a-command"}},
		{name: "unexpected argument", args: []string{"--json-envelope", "bills", "list", "extra-secret-canary"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := executeEnvelopeForTest(t, deps, "", tc.args...)
			got := decodeEnvelopeForTest(t, stdout)
			if code != 2 || got["ok"] != false || got["schema_version"] != float64(1) {
				t.Fatalf("code=%d envelope=%#v", code, got)
			}
			if got["error"].(map[string]any)["code"] != "invalid_argument" {
				t.Fatalf("error = %#v", got["error"])
			}
			if stderr != "" || strings.Contains(stdout, "secret-canary") || strings.Contains(stdout, "Usage:") {
				t.Fatalf("unsanitized failure output: stdout=%q stderr=%q", stdout, stderr)
			}
		})
	}
}

func TestEnvelopeUsageHistoryRejectsExtraArgumentsBeforeSessionAccess(t *testing.T) {
	for _, command := range []string{"reads", "costs"} {
		t.Run(command, func(t *testing.T) {
			code, stdout, stderr := executeEnvelopeForTest(t, Dependencies{Store: securestore.NewMemoryStore()}, "", "--json-envelope", "usage", command, "extra-secret-canary")
			got := decodeEnvelopeForTest(t, stdout)
			if code != 2 || got["command"] != "usage."+command || got["error"].(map[string]any)["code"] != "invalid_argument" || stderr != "" || strings.Contains(stdout+stderr, "extra-secret-canary") {
				t.Fatalf("extra argument was not rejected safely before session access: code=%d envelope=%#v stderr=%q", code, got, stderr)
			}
		})
	}
}

func TestExecuteCLIEnvelopeMapsUnknownErrorWithoutLeaking(t *testing.T) {
	const canary = "https://private.example/account?token=secret-canary"
	deps := billsDependencies(t, envelopeListBills{err: errors.New(canary)})
	code, stdout, stderr := executeEnvelopeForTest(t, deps, "", "--json-envelope", "bills", "list")
	got := decodeEnvelopeForTest(t, stdout)
	if code != 1 || got["command"] != "bills.list" || got["ok"] != false {
		t.Fatalf("code=%d envelope=%#v", code, got)
	}
	if got["error"].(map[string]any)["code"] != "internal_error" {
		t.Fatalf("error = %#v", got["error"])
	}
	if strings.Contains(stdout+stderr, canary) || stderr != "" {
		t.Fatalf("error detail leaked: stdout=%q stderr=%q", stdout, stderr)
	}
}

func TestCapabilitiesIsOfflineAndEnvelopeValidatesItsFlags(t *testing.T) {
	deps := Dependencies{ConfigPath: filepath.Join(t.TempDir(), "must-not-be-read.json")}
	code, stdout, stderr := executeEnvelopeForTest(t, deps, "", "capabilities", "--json-envelope")
	got := decodeEnvelopeForTest(t, stdout)
	if code != 0 || got["ok"] != true || got["command"] != "capabilities" || stderr != "" {
		t.Fatalf("code=%d envelope=%#v stderr=%q", code, got, stderr)
	}
	data := got["data"].(map[string]any)
	if data["schema_versions"] == nil || data["commands"] == nil || data["error_codes"] == nil {
		t.Fatalf("capabilities is incomplete: %#v", data)
	}
	code, stdout, stderr = executeEnvelopeForTest(t, deps, "", "capabilities", "--json-envelope", "--help")
	got = decodeEnvelopeForTest(t, stdout)
	if code != 0 || stderr != "" || !strings.Contains(got["data"].(map[string]any)["text"].(string), "--json-envelope") {
		t.Fatalf("offline help does not advertise envelope flag: code=%d envelope=%#v stderr=%q", code, got, stderr)
	}

	code, stdout, stderr = executeEnvelopeForTest(t, deps, "", "capabilities", "--json-envelope", "--unknown-canary")
	got = decodeEnvelopeForTest(t, stdout)
	if code != 2 || got["ok"] != false || stderr != "" || strings.Contains(stdout, "unknown-canary") {
		t.Fatalf("capability flag error was bypassed or leaked: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestEnvelopeNoCommandAndCommandGroupsReturnJSONHelp(t *testing.T) {
	for _, args := range [][]string{{"--json-envelope"}, {"usage", "--json-envelope"}} {
		code, stdout, stderr := executeEnvelopeForTest(t, Dependencies{Clock: time.Now}, "", args...)
		got := decodeEnvelopeForTest(t, stdout)
		if code != 0 || got["ok"] != true || stderr != "" {
			t.Fatalf("args=%q code=%d envelope=%#v stderr=%q", args, code, got, stderr)
		}
		data := got["data"].(map[string]any)
		if data["text"] == nil {
			t.Fatalf("args=%q did not return help text: %#v", args, got)
		}
	}
}

func TestExecuteCLIEnvelopeExportsNonJSONAsJSONData(t *testing.T) {
	deps := opowerDeps(t, &fakeOpower{})
	code, stdout, stderr := executeEnvelopeForTest(t, deps, "", "usage", "export", "--format", "csv", "--json-envelope")
	got := decodeEnvelopeForTest(t, stdout)
	if code != 0 || got["command"] != "usage.export" || got["ok"] != true || stderr != "" {
		t.Fatalf("code=%d envelope=%#v stderr=%q", code, got, stderr)
	}
	data := got["data"].(map[string]any)
	if data["format"] != "csv" || !strings.Contains(data["content"].(string), "start") || strings.Contains(stdout, "end,start,unit,value\n") {
		t.Fatalf("CSV escaped envelope data: %#v; stdout=%q", data, stdout)
	}
}

func TestExecuteCLIEnvelopeBillDownloadMetadata(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bill.pdf")
	deps := billsDependencies(t, &fakeBills{})
	code, stdout, stderr := executeEnvelopeForTest(t, deps, "", "--json-envelope", "bills", "download", publicBillID("2026-02-15"), "--output", path)
	got := decodeEnvelopeForTest(t, stdout)
	if code != 0 || got["command"] != "bills.download" || got["ok"] != true || stderr != "" {
		t.Fatalf("code=%d envelope=%#v stderr=%q", code, got, stderr)
	}
	data := got["data"].(map[string]any)
	if data["bill_id"] != publicBillID("2026-02-15") || data["path"] != path || data["bytes"] != float64(len("%PDF-synthetic")) || len(data["sha256"].(string)) != 64 {
		t.Fatalf("download metadata = %#v", data)
	}
}

func TestEnvelopeOneShotSuccessesCoverEveryOrdinaryCommandFamily(t *testing.T) {
	store := securestore.NewMemoryStore()
	if err := auth.SaveSession(store, "default", validSession(time.Now())); err != nil {
		t.Fatal(err)
	}
	base := Dependencies{Store: store, Authenticator: &fakeAuthenticator{}, Bills: &fakeBills{}, Opower: &fakeOpower{}, Clock: time.Now}
	inspectPath := filepath.Join(t.TempDir(), "diagnostics.json")
	if err := os.WriteFile(inspectPath, []byte("[]"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, command string
		args          []string
		deps          Dependencies
	}{
		{name: "auth.status", command: "auth.status", args: []string{"auth", "status", "--json-envelope"}, deps: Dependencies{Store: securestore.NewMemoryStore(), Clock: time.Now}},
		{name: "auth.init", command: "auth.init", args: []string{"auth", "init", "--json-envelope"}, deps: base},
		{name: "auth.logout", command: "auth.logout", args: []string{"auth", "logout", "--json-envelope"}, deps: Dependencies{Store: securestore.NewMemoryStore(), Clock: time.Now}},
		{name: "bills.list", command: "bills.list", args: []string{"bills", "list", "--json-envelope"}, deps: billsDependencies(t, envelopeListBills{})},
		{name: "accounts.list", command: "accounts.list", args: []string{"accounts", "list", "--json-envelope"}, deps: base},
		{name: "usage.bills", command: "usage.bills", args: []string{"usage", "bills", "--json-envelope"}, deps: base},
		{name: "usage.weather", command: "usage.weather", args: []string{"usage", "weather", "--json-envelope"}, deps: base},
		{name: "usage.neighbors", command: "usage.neighbors", args: []string{"usage", "neighbors", "--json-envelope"}, deps: base},
		{name: "usage.meters", command: "usage.meters", args: []string{"usage", "meters", "--json-envelope"}, deps: base},
		{name: "usage.realtime", command: "usage.realtime", args: []string{"usage", "realtime", "--json-envelope"}, deps: base},
		{name: "usage.summary", command: "usage.summary", args: []string{"usage", "summary", "--json-envelope"}, deps: base},
		{name: "usage.export", command: "usage.export", args: []string{"usage", "export", "--json-envelope"}, deps: base},
		{name: "usage.forecast", command: "usage.forecast", args: []string{"usage", "forecast", "--json-envelope"}, deps: base},
		{name: "usage.reads", command: "usage.reads", args: []string{"usage", "reads", "--aggregate", "day", "--from", "2026-01-01", "--to", "2026-01-02", "--json-envelope"}, deps: base},
		{name: "usage.costs", command: "usage.costs", args: []string{"usage", "costs", "--aggregate", "day", "--from", "2026-01-01", "--to", "2026-01-02", "--json-envelope"}, deps: base},
		{name: "entities.list", command: "entities.list", args: []string{"entities", "list", "--demo", "--json-envelope"}, deps: Dependencies{Store: securestore.NewMemoryStore(), Clock: time.Now, DemoDiscovery: &provider.Simulator{}}},
		{name: "diagnostics.schema", command: "diagnostics.schema", args: []string{"diagnostics", "schema", "--demo", "--json-envelope"}, deps: Dependencies{Store: securestore.NewMemoryStore(), Clock: time.Now, DemoDiscovery: &provider.Simulator{}}},
		{name: "diagnostics.inspect", command: "diagnostics.inspect", args: []string{"diagnostics", "inspect", inspectPath, "--json-envelope"}, deps: base},
		{name: "version", command: "version", args: []string{"version", "--json-envelope"}, deps: Dependencies{Clock: time.Now}},
		{name: "capabilities", command: "capabilities", args: []string{"capabilities", "--json-envelope"}, deps: Dependencies{ConfigPath: filepath.Join(t.TempDir(), "not-read.json"), Clock: time.Now}},
		{name: "completion.bash", command: "completion.bash", args: []string{"completion", "bash", "--json-envelope"}, deps: Dependencies{Clock: time.Now}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := executeEnvelopeForTest(t, tc.deps, "", tc.args...)
			got := decodeEnvelopeForTest(t, stdout)
			if code != 0 || got["ok"] != true || got["command"] != tc.command || stderr != "" {
				t.Fatalf("code=%d envelope=%#v stderr=%q", code, got, stderr)
			}
			if tc.command != "auth.init" {
				if _, ok := got["data"]; !ok {
					t.Fatalf("success envelope has no data: %#v", got)
				}
			}
		})
	}
}

func TestEntityMutationEnvelopeResultsAreTyped(t *testing.T) {
	store := securestore.NewMemoryStore()
	if err := auth.SaveSession(store, "default", validSession(time.Now())); err != nil {
		t.Fatal(err)
	}
	manager, err := identity.Load(store, "default", true)
	if err != nil {
		t.Fatal(err)
	}
	account, err := manager.Handle(identity.Entity{Type: "account", Namespace: "coned-opower", ProviderID: "raw-secret-account"})
	if err != nil {
		t.Fatal(err)
	}
	deps := Dependencies{Store: store, Bills: &fakeBills{}, Discovery: &fakeDiscovery{}, ConfigPath: filepath.Join(t.TempDir(), "profile.json"), Clock: time.Now}
	code, stdout, stderr := executeEnvelopeForTest(t, deps, "", "entities", "alias", account, "home", "--json-envelope")
	got := decodeEnvelopeForTest(t, stdout)
	if code != 0 || got["data"].(map[string]any)["status"] != "alias_updated" || stderr != "" || strings.Contains(stdout, account) {
		t.Fatalf("alias: code=%d envelope=%#v stderr=%q", code, got, stderr)
	}
	code, stdout, stderr = executeEnvelopeForTest(t, deps, "", "entities", "select", "home", "--json-envelope")
	got = decodeEnvelopeForTest(t, stdout)
	if code != 0 || got["data"].(map[string]any)["status"] != "selection_updated" || stderr != "" || strings.Contains(stdout, account) {
		t.Fatalf("select: code=%d envelope=%#v stderr=%q", code, got, stderr)
	}
}

func TestAuthBrowserImportFailureIsSanitized(t *testing.T) {
	const canary = "https://not-loopback.example/path?token=secret-canary"
	code, stdout, stderr := executeEnvelopeForTest(t, Dependencies{Store: securestore.NewMemoryStore(), Clock: time.Now}, "", "auth", "import-browser", "--endpoint", canary, "--json-envelope")
	got := decodeEnvelopeForTest(t, stdout)
	if code != 1 || got["command"] != "auth.import-browser" || got["error"].(map[string]any)["code"] != "internal_error" || stderr != "" || strings.Contains(stdout+stderr, canary) {
		t.Fatalf("code=%d envelope=%#v stderr=%q", code, got, stderr)
	}
}

func TestJSONEnvelopeFalseKeepsLegacyExecution(t *testing.T) {
	deps := billsDependencies(t, envelopeListBills{})
	code, stdout, stderr := executeEnvelopeForTest(t, deps, "", "--json-envelope=false", "--json", "bills", "list")
	if code != 0 || stderr != "" || strings.HasPrefix(stdout, "{\"schema_version\"") || !strings.HasPrefix(stdout, "[{\"id\"") {
		t.Fatalf("--json-envelope=false changed legacy output: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestEnvelopeSwitchHandlesBooleanAndEndOfOptions(t *testing.T) {
	deps := billsDependencies(t, envelopeListBills{})
	for _, args := range [][]string{
		{"--json-envelope=", "version"},
		{"--json-envelope=maybe", "--json-envelope=false", "version"},
	} {
		code, stdout, stderr := executeEnvelopeForTest(t, deps, "", args...)
		got := decodeEnvelopeForTest(t, stdout)
		if code != 2 || got["ok"] != false || got["error"].(map[string]any)["code"] != "invalid_argument" || stderr != "" {
			t.Fatalf("malformed switch args=%q code=%d stdout=%q stderr=%q", args, code, stdout, stderr)
		}
	}
	code, stdout, stderr := executeEnvelopeForTest(t, deps, "", "--profile", "--json-envelope", "version")
	if strings.HasPrefix(stdout, "{\"schema_version\"") {
		t.Fatalf("flag value was stripped as envelope switch: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	code, stdout, stderr = executeEnvelopeForTest(t, deps, "", "bills", "list", "--", "--json-envelope")
	if strings.HasPrefix(stdout, "{\"schema_version\"") {
		t.Fatalf("flag after end-of-options activated envelope: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestExecuteCLIEnvelopeHelpAndCompletionFailuresStayJSON(t *testing.T) {
	deps := Dependencies{ConfigPath: filepath.Join(t.TempDir(), "unused.json")}
	for _, tc := range []struct {
		name string
		args []string
		code int
		want string
	}{
		{name: "root help", args: []string{"--json-envelope", "--help"}, code: 0, want: "coned"},
		{name: "unknown help topic", args: []string{"--json-envelope", "help", "secret-topic"}, code: 2, want: "help"},
		{name: "completion extra arg", args: []string{"completion", "bash", "--json-envelope", "secret-argument"}, code: 2, want: "completion.bash"},
		{name: "auth help", args: []string{"--json-envelope", "auth", "login", "--help"}, code: 0, want: "auth.login"},
		{name: "version help", args: []string{"--json-envelope", "version", "--help"}, code: 0, want: "version"},
		{name: "bills help", args: []string{"bills", "list", "--json-envelope", "--help"}, code: 0, want: "bills.list"},
		{name: "Green Button export help", args: []string{"green-button", "export", "--json-envelope", "--help"}, code: 0, want: "green-button.export"},
		{name: "completion help", args: []string{"--json-envelope", "completion", "--help"}, code: 0, want: "completion"},
		{name: "capabilities help", args: []string{"--json-envelope", "capabilities", "--help"}, code: 0, want: "capabilities"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := executeEnvelopeForTest(t, deps, "", tc.args...)
			got := decodeEnvelopeForTest(t, stdout)
			if code != tc.code || got["command"] != tc.want || stderr != "" {
				t.Fatalf("code=%d command=%v stderr=%q envelope=%#v", code, got["command"], stderr, got)
			}
			if strings.Contains(stdout, "secret-topic") || strings.Contains(stdout, "secret-argument") {
				t.Fatalf("input canary leaked: %q", stdout)
			}
		})
	}
}

func TestEnvelopeDoesNotInventJSONDataFromPlainOutput(t *testing.T) {
	if _, err := envelopeData("bills.list", nil, nil, []byte("not JSON output")); err == nil {
		t.Fatal("malformed successful JSON was accepted as text")
	}
	if _, err := envelopeData("entities.alias", nil, nil, []byte("selected account-secret")); err == nil {
		t.Fatal("unexpected plain command output was accepted as data")
	}
}

func TestSuccessEnvelopeMarshalFailureProducesOneSanitizedFailure(t *testing.T) {
	var stdout bytes.Buffer
	code := writeEnvelopeSuccess(&stdout, "usage.forecast", map[string]any{"unsupported": func() {}}, Dependencies{Clock: time.Now})
	got := decodeEnvelopeForTest(t, stdout.String())
	if code != 1 || got["ok"] != false || got["error"].(map[string]any)["code"] != "internal_error" || strings.Count(stdout.String(), "\n") != 1 || strings.Contains(stdout.String(), "unsupported") {
		t.Fatalf("marshal failure was not a single sanitized failure: code=%d output=%q", code, stdout.String())
	}
}

func TestEnvelopeFileConflictAndInvalidBillIDAreTyped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bill.pdf")
	const existing = "preserve-existing-synthetic-file"
	if err := os.WriteFile(path, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}
	deps := billsDependencies(t, &fakeBills{})
	code, stdout, stderr := executeEnvelopeForTest(t, deps, "", "--json-envelope", "bills", "download", publicBillID("2026-02-15"), "--output", path)
	got := decodeEnvelopeForTest(t, stdout)
	if code != 1 || got["error"].(map[string]any)["code"] != "output_conflict" || stderr != "" {
		t.Fatalf("conflict code=%d envelope=%#v stderr=%q", code, got, stderr)
	}
	body, err := os.ReadFile(path)
	if err != nil || string(body) != existing {
		t.Fatalf("existing output changed: %q err=%v", body, err)
	}

	code, stdout, stderr = executeEnvelopeForTest(t, Dependencies{Store: securestore.NewMemoryStore(), Clock: time.Now}, "", "--json-envelope", "bills", "download", "bad-id")
	got = decodeEnvelopeForTest(t, stdout)
	if code != 2 || got["error"].(map[string]any)["code"] != "invalid_argument" || stderr != "" {
		t.Fatalf("invalid id did not precede credential access: code=%d envelope=%#v stderr=%q", code, got, stderr)
	}
}

func TestEnvelopeErrorClassificationClampsRetries(t *testing.T) {
	for _, tc := range []struct {
		name      string
		err       error
		code      string
		retryable bool
	}{
		{name: "deadline", err: context.DeadlineExceeded, code: "timeout", retryable: true},
		{name: "canceled", err: context.Canceled, code: "canceled", retryable: false},
		{name: "TLS forged retry", err: &coned.TransportError{Kind: coned.TransportTLS, Retryable: true}, code: "transport_failed", retryable: false},
		{name: "unknown forged retry", err: &coned.TransportError{Kind: coned.TransportUnknown, Retryable: true}, code: "transport_failed", retryable: false},
		{name: "DNS without transient cause", err: &coned.TransportError{Kind: coned.TransportDNS, Retryable: true}, code: "transport_failed", retryable: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mapped := mapEnvelopeError(tc.err, false)
			if mapped.value.Code != tc.code || mapped.value.Retryable != tc.retryable {
				t.Fatalf("mapped = %#v", mapped.value)
			}
		})
	}
	protocol := &coned.ProtocolError{Status: 502, RequestID: "private-canary"}
	mapped := mapEnvelopeError(protocol, false)
	if mapped.value.Code != "provider_protocol_changed" || mapped.value.HTTPStatus == nil || *mapped.value.HTTPStatus != 502 {
		t.Fatalf("protocol metadata = %#v", mapped.value)
	}
}

func TestEnvelopeUsageKeepsMissingFieldsNullableAndLegacyJSONStable(t *testing.T) {
	f := &fakeOpower{
		forecasts: []coned.Forecast{{Account: "****1234", ForecastUsage: 0, ForecastCost: 0, AvailabilityKnown: true, ForecastUsagePresent: false, ForecastCostPresent: true}},
		costs:     []coned.CostRead{{Account: "****1234", Value: 0, Cost: 0, AvailabilityKnown: true, ValuePresent: true, CostPresent: false}},
		reads:     []coned.HistoricalRead{{Account: "****1234", Value: 0, AvailabilityKnown: true, ValuePresent: true, UnitPresent: false}},
	}
	deps := opowerDeps(t, f)
	for _, tc := range []struct {
		args    []string
		field   string
		missing string
	}{
		{args: []string{"usage", "forecast", "--json-envelope"}, field: "forecast_usage", missing: "currency"},
		{args: []string{"usage", "costs", "--json-envelope", "--aggregate", "bill"}, field: "cost", missing: "unit"},
		{args: []string{"usage", "reads", "--json-envelope", "--aggregate", "bill"}, field: "value", missing: "unit"},
	} {
		code, stdout, stderr := executeEnvelopeForTest(t, deps, "", tc.args...)
		got := decodeEnvelopeForTest(t, stdout)
		if code != 0 || got["ok"] != true || stderr != "" {
			t.Fatalf("code=%d envelope=%#v stderr=%q", code, got, stderr)
		}
		rows, ok := got["data"].([]any)
		if !ok || len(rows) != 1 {
			t.Fatalf("data is not a row array: %#v", got["data"])
		}
		row := rows[0].(map[string]any)
		if _, exists := row[tc.field]; !exists || row[tc.field] != nil && tc.field != "value" {
			t.Fatalf("missing field did not stay nullable: %#v", row)
		}
		if tc.field == "cost" && row["value"] != float64(0) || tc.field == "forecast_usage" && row["forecast_cost"] != float64(0) || tc.field == "value" && row["value"] != float64(0) {
			t.Fatalf("explicit zero was lost: %#v", row)
		}
		if row[tc.missing] != nil {
			t.Fatalf("unknown provenance field %q is not null: %#v", tc.missing, row)
		}
	}
	legacy, err := runWithDependencies(t, deps, "", "--json usage costs --aggregate bill")
	if err != nil || !strings.Contains(legacy, `"cost":0`) || strings.Contains(legacy, `"currency"`) || strings.Contains(legacy, `"unit"`) {
		t.Fatalf("legacy JSON shape changed: %q err=%v", legacy, err)
	}
}

func TestAuthEnvelopeStreamsBeforePromptAndTerminatesOnce(t *testing.T) {
	store := securestore.NewMemoryStore()
	if err := auth.SaveCredentials(store, "default", auth.Credentials{Email: "synthetic@example.test", Password: "synthetic-password"}); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	prompter := &envelopeTimingPrompter{stdout: &stdout, code: "654321"}
	deps := Dependencies{
		Store: store, Authenticator: &mfaAuthenticator{fakeAuthenticator: fakeAuthenticator{session: validSession(time.Now())}},
		Clock: time.Now, Prompter: prompter, PasswordTerminal: &fakeTerminal{}, ConfigPath: filepath.Join(t.TempDir(), "unused.json"),
	}
	code := ExecuteCLI([]string{"auth", "login", "--no-store", "--json-envelope"}, strings.NewReader(""), &stdout, &stderr, deps)
	if code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("events = %q", stdout.String())
	}
	var first, last map[string]any
	if json.Unmarshal([]byte(lines[0]), &first) != nil || json.Unmarshal([]byte(lines[1]), &last) != nil {
		t.Fatalf("invalid NDJSON: %q", stdout.String())
	}
	if first["event"] != "mfa_required" || last["event"] != "authenticated" || last["ok"] != true || first["command"] != "auth.login" || prompter.calls != 1 {
		t.Fatalf("events/prompts = %#v %#v calls=%d", first, last, prompter.calls)
	}
	if !strings.Contains(stderr.String(), "Verification required") || strings.Contains(stdout.String(), "synthetic-password") || strings.Contains(stdout.String(), prompter.code) {
		t.Fatalf("prompt or secret placement is wrong: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}

	code, stdoutText, stderrText := executeEnvelopeForTest(t, deps, "", "--json-envelope", "auth", "login", "--help")
	help := decodeEnvelopeForTest(t, stdoutText)
	if code != 0 || help["command"] != "auth.login" || !strings.Contains(help["data"].(map[string]any)["text"].(string), "Authenticate with Con Edison") || stderrText != "" {
		t.Fatalf("auth help escaped the envelope: code=%d envelope=%#v stderr=%q", code, help, stderrText)
	}
}

type envelopeTimingPrompter struct {
	stdout *bytes.Buffer
	code   string
	calls  int
}

func (p *envelopeTimingPrompter) Email() (string, error) { return "", nil }
func (p *envelopeTimingPrompter) MFACode() (string, error) {
	p.calls++
	if !strings.Contains(p.stdout.String(), `"event":"mfa_required"`) {
		return "", errors.New("MFA prompt happened before its event")
	}
	return p.code, nil
}
func (p *envelopeTimingPrompter) ConfirmSave() (bool, error) { return false, nil }

func TestAuthEnvelopeWrongCodeAndEOFEmitOneFailureTerminal(t *testing.T) {
	for _, tc := range []struct {
		name   string
		prompt auth.Prompter
		input  string
		code   string
	}{
		{name: "wrong code", prompt: &fakePrompter{mfaCode: "wrong-secret-code"}, code: "invalid_credentials"},
		{name: "EOF", prompt: nil, input: "", code: "invalid_argument"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := securestore.NewMemoryStore()
			if err := auth.SaveCredentials(store, "default", auth.Credentials{Email: "synthetic@example.test", Password: "synthetic-password"}); err != nil {
				t.Fatal(err)
			}
			failing := &rejectingMFA{mfaAuthenticator: &mfaAuthenticator{fakeAuthenticator: fakeAuthenticator{session: validSession(time.Now())}}}
			deps := Dependencies{Store: store, Authenticator: failing, Clock: time.Now, Prompter: tc.prompt, PasswordTerminal: &fakeTerminal{}, ConfigPath: filepath.Join(t.TempDir(), "unused.json")}
			code, stdout, stderr := executeEnvelopeForTest(t, deps, tc.input, "--json-envelope", "auth", "login", "--no-store")
			lines := strings.Split(strings.TrimSpace(stdout), "\n")
			if len(lines) != 2 {
				t.Fatalf("exit=%d events=%q stderr=%q", code, stdout, stderr)
			}
			var failure map[string]any
			if err := json.Unmarshal([]byte(lines[1]), &failure); err != nil {
				t.Fatal(err)
			}
			expectedExit := 1
			if tc.code == "invalid_argument" {
				expectedExit = 2
			}
			if code != expectedExit || failure["event"] != "failure" || failure["error"].(map[string]any)["code"] != tc.code {
				t.Fatalf("exit=%d terminal=%#v", code, failure)
			}
			if strings.Contains(stdout+stderr, "wrong-secret-code") || strings.Contains(stdout+stderr, "synthetic-password") {
				t.Fatalf("auth secret leaked: stdout=%q stderr=%q", stdout, stderr)
			}
		})
	}
}

func TestAuthEnvelopeFlagFailureEmitsOneNDJSONTerminal(t *testing.T) {
	deps := Dependencies{Store: securestore.NewMemoryStore(), Clock: time.Now}
	code, stdout, stderr := executeEnvelopeForTest(t, deps, "", "auth", "login", "--json-envelope", "--secret-canary")
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if code != 2 || len(lines) != 1 || stderr != "" || strings.Contains(stdout+stderr, "secret-canary") {
		t.Fatalf("exit=%d lines=%q stderr=%q", code, lines, stderr)
	}
	var terminal map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &terminal); err != nil {
		t.Fatal(err)
	}
	if terminal["event"] != "failure" || terminal["command"] != "auth.login" || terminal["error"].(map[string]any)["code"] != "invalid_argument" {
		t.Fatalf("terminal=%#v", terminal)
	}
}

func TestAuthEnvelopeCancellationAndStorageFailureAreTerminalEvents(t *testing.T) {
	store := securestore.NewMemoryStore()
	if err := auth.SaveCredentials(store, "default", auth.Credentials{Email: "synthetic@example.test", Password: "synthetic-password"}); err != nil {
		t.Fatal(err)
	}
	deps := Dependencies{Store: store, Authenticator: &fakeAuthenticator{err: context.Canceled}, Clock: time.Now, Prompter: &fakePrompter{}, PasswordTerminal: &fakeTerminal{}}
	code, stdout, stderr := executeEnvelopeForTest(t, deps, "", "auth", "login", "--no-store", "--json-envelope")
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if code != 1 || len(lines) != 1 || stderr != "" {
		t.Fatalf("canceled login: exit=%d output=%q stderr=%q", code, stdout, stderr)
	}
	var event map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &event); err != nil {
		t.Fatal(err)
	}
	if event["event"] != "failure" || event["error"].(map[string]any)["code"] != "canceled" {
		t.Fatalf("canceled terminal event = %#v", event)
	}

	locked := failingStore{Store: securestore.NewMemoryStore(), getErr: securestore.ErrLocked, getKey: "session"}
	deps = Dependencies{Store: locked, Authenticator: &fakeAuthenticator{}, Clock: time.Now, Prompter: &fakePrompter{}, PasswordTerminal: &fakeTerminal{}}
	code, stdout, stderr = executeEnvelopeForTest(t, deps, "", "auth", "init", "--json-envelope")
	lines = strings.Split(strings.TrimSpace(stdout), "\n")
	if code != 1 || len(lines) != 1 || stderr != "" {
		t.Fatalf("storage failure: exit=%d output=%q stderr=%q", code, stdout, stderr)
	}
	if err := json.Unmarshal([]byte(lines[0]), &event); err != nil {
		t.Fatal(err)
	}
	if event["command"] != "auth.init" || event["event"] != "failure" || event["error"].(map[string]any)["code"] != "storage_locked" {
		t.Fatalf("storage terminal event = %#v", event)
	}
}

type rejectingMFA struct{ *mfaAuthenticator }

func (a *rejectingMFA) VerifyMFA(context.Context, string) (auth.Session, error) {
	return auth.Session{}, coned.ErrInvalidCredentials
}

func TestGreenButtonExportsAndDownloadsAreEnvelopeData(t *testing.T) {
	_, deps := greenButtonDeps(t)
	for _, format := range []string{"csv", "xml", "json"} {
		code, stdout, stderr := executeEnvelopeForTest(t, deps, "", "green-button", "export", "--format", format, "--json-envelope")
		got := decodeEnvelopeForTest(t, stdout)
		if code != 0 || got["command"] != "green-button.export" || got["ok"] != true || stderr != "" {
			t.Fatalf("format=%s code=%d envelope=%#v stderr=%q", format, code, got, stderr)
		}
		data := got["data"].(map[string]any)
		if data["format"] != format || data["content"] == nil || strings.Contains(stdout, "<usage>") || strings.Contains(stdout, "TYPE,DATE,USAGE\n") {
			t.Fatalf("format=%s data=%#v stdout=%q", format, data, stdout)
		}
	}
	path := filepath.Join(t.TempDir(), "usage.zip")
	code, stdout, stderr := executeEnvelopeForTest(t, deps, "", "--json-envelope", "green-button", "download", "--output", path)
	got := decodeEnvelopeForTest(t, stdout)
	if code != 0 || got["command"] != "green-button.download" || got["ok"] != true || stderr != "" {
		t.Fatalf("download code=%d envelope=%#v stderr=%q", code, got, stderr)
	}
	data := got["data"].(map[string]any)
	if data["path"] != path || data["bytes"].(float64) == 0 || len(data["sha256"].(string)) != 64 {
		t.Fatalf("download data=%#v", data)
	}
}

func TestSafeTranslationBoundariesKeepUnknownFailuresInternal(t *testing.T) {
	const canary = "https://private.example/api?session=redacted-canary"
	deps := billsDependencies(t, envelopeListBills{err: errors.New(canary)})
	code, stdout, stderr := executeEnvelopeForTest(t, deps, "", "--json-envelope", "bills", "list")
	got := decodeEnvelopeForTest(t, stdout)
	if code != 1 || got["error"].(map[string]any)["code"] != "internal_error" || strings.Contains(stdout+stderr, canary) {
		t.Fatalf("billing safe boundary = code %d, %q %q", code, stdout, stderr)
	}
	f := &fakeOpower{err: errors.New(canary)}
	code, stdout, stderr = executeEnvelopeForTest(t, opowerDeps(t, f), "", "--json-envelope", "usage", "bills")
	got = decodeEnvelopeForTest(t, stdout)
	if code != 1 || got["error"].(map[string]any)["code"] != "internal_error" || strings.Contains(stdout+stderr, canary) {
		t.Fatalf("usage safe boundary = code %d, %q %q", code, stdout, stderr)
	}
	store := securestore.NewMemoryStore()
	if err := auth.SaveCredentials(store, "default", auth.Credentials{Email: "synthetic@example.test", Password: "synthetic-password"}); err != nil {
		t.Fatal(err)
	}
	deps = Dependencies{Store: store, Authenticator: &fakeAuthenticator{err: errors.New(canary)}, Clock: time.Now, Prompter: &fakePrompter{}, PasswordTerminal: &fakeTerminal{}, ConfigPath: filepath.Join(t.TempDir(), "unused.json")}
	code, stdout, stderr = executeEnvelopeForTest(t, deps, "", "--json-envelope", "auth", "login", "--no-store")
	if code != 1 || !strings.Contains(stdout, `"code":"internal_error"`) || strings.Contains(stdout+stderr, canary) || strings.Contains(stdout+stderr, "synthetic-password") {
		t.Fatalf("auth safe boundary = code %d, %q %q", code, stdout, stderr)
	}
	green, deps := greenButtonDeps(t)
	green.err = errors.New(canary)
	code, stdout, stderr = executeEnvelopeForTest(t, deps, "", "--json-envelope", "green-button", "export")
	got = decodeEnvelopeForTest(t, stdout)
	if code != 1 || got["error"].(map[string]any)["code"] != "internal_error" || strings.Contains(stdout+stderr, canary) {
		t.Fatalf("Green Button safe boundary = code %d, %q %q", code, stdout, stderr)
	}
}
