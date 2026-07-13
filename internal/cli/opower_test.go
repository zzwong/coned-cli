package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zzwong/coned-cli/internal/auth"
	"github.com/zzwong/coned-cli/internal/coned"
	"github.com/zzwong/coned-cli/internal/securestore"
)

type fakeOpower struct {
	resource  string
	options   coned.ReadOptions
	selection coned.EntitySelection
	err       error
}

func (f *fakeOpower) Fetch(_ context.Context, _ auth.Session, resource string) (any, error) {
	f.resource = resource
	if f.err != nil {
		return nil, f.err
	}
	return []coned.UsageRead{{Start: "2026-01-01", End: "2026-01-02", Unit: "kWh", Value: 1.5}}, nil
}
func (f *fakeOpower) FetchSelected(ctx context.Context, session auth.Session, resource string, selection coned.EntitySelection) (any, error) {
	f.selection = selection
	return f.Fetch(ctx, session, resource)
}
func (f *fakeOpower) Forecast(context.Context, auth.Session) ([]coned.Forecast, error) {
	return []coned.Forecast{{Account: "****1234", ForecastUsage: 10}}, f.err
}
func (f *fakeOpower) HistoricalReads(_ context.Context, _ auth.Session, options coned.ReadOptions) ([]coned.HistoricalRead, error) {
	f.options = options
	return []coned.HistoricalRead{{Account: "****1234", Start: "a", End: "b", Value: 2}}, f.err
}
func (f *fakeOpower) HistoricalCosts(_ context.Context, _ auth.Session, options coned.ReadOptions) ([]coned.CostRead, error) {
	f.options = options
	return []coned.CostRead{{Account: "****1234", Start: "a", End: "b", Value: 2, Cost: 1}}, f.err
}
func opowerDeps(t *testing.T, f *fakeOpower) Dependencies {
	t.Helper()
	s := securestore.NewMemoryStore()
	if err := auth.SaveSession(s, "default", validSession(time.Now())); err != nil {
		t.Fatal(err)
	}
	return Dependencies{Store: s, Opower: f, Clock: time.Now}
}
func TestOpowerCommandsJSONCSVAndAtomicOutput(t *testing.T) {
	f := &fakeOpower{}
	d := opowerDeps(t, f)
	out, err := runWithDependencies(t, d, "", "--json usage bills")
	if err != nil || f.resource != "usage-bills" || !strings.Contains(out, "2026-01-01") {
		t.Fatalf("out=%q resource=%q err=%v", out, f.resource, err)
	}
	out, err = runWithDependencies(t, d, "", "usage export --format csv")
	if err != nil || !strings.HasPrefix(out, "end,start,unit,value\n") {
		t.Fatalf("csv=%q err=%v", out, err)
	}
	p := filepath.Join(t.TempDir(), "usage.json")
	out, err = runWithDependencies(t, d, "", "usage export --format json --output "+p)
	if err != nil || out != "" {
		t.Fatalf("output=%q err=%v", out, err)
	}
	b, _ := os.ReadFile(p)
	if !strings.Contains(string(b), "kWh") {
		t.Fatalf("file=%q", b)
	}
	if _, err = runWithDependencies(t, d, "", "usage export --format xml"); !errors.Is(err, coned.ErrProtocolChanged) {
		t.Fatalf("format error=%v", err)
	}
}
func TestUsageQueryCommandsAndValidation(t *testing.T) {
	f := &fakeOpower{}
	deps := opowerDeps(t, f)
	out, err := runWithDependencies(t, deps, "", "--json usage forecast")
	if err != nil || !strings.Contains(out, "forecast_usage") {
		t.Fatalf("forecast=%q err=%v", out, err)
	}
	out, err = runWithDependencies(t, deps, "", "--json usage reads --aggregate hour --from 2026-01-01 --to 2026-01-02")
	if err != nil || f.options.Aggregate != "hour" || f.options.From != "2026-01-01" || !strings.Contains(out, "****1234") {
		t.Fatalf("reads=%q options=%#v err=%v", out, f.options, err)
	}
	out, err = runWithDependencies(t, deps, "", "usage costs --aggregate bill")
	if err != nil || !strings.Contains(out, "cost") {
		t.Fatalf("costs=%q err=%v", out, err)
	}
	for _, command := range []string{
		"usage reads --aggregate week", "usage reads --aggregate day", "usage costs --aggregate hour --from bad --to 2026-01-02", "usage reads --aggregate day --from 2026-02-01 --to 2026-01-01",
	} {
		if _, err = runWithDependencies(t, deps, "", command); !errors.Is(err, coned.ErrProtocolChanged) {
			t.Fatalf("command %q error=%v", command, err)
		}
	}
}

func TestRealtimeUnavailableIsSafe(t *testing.T) {
	f := &fakeOpower{err: coned.ErrRealtimeUnavailable}
	_, err := runWithDependencies(t, opowerDeps(t, f), "", "usage realtime")
	if !errors.Is(err, coned.ErrRealtimeUnavailable) {
		t.Fatalf("error=%v", err)
	}
}
