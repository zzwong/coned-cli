package coned

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/zzwong/coned-cli/internal/contracts"
)

func TestForecastParsesAndMasksAccount(t *testing.T) {
	client, err := NewClient(Options{Transport: opowerRT(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "www.coned.com" {
			return opowerResponse(`"fresh-token"`), nil
		}
		var payload struct {
			Operation string `json:"operationName"`
		}
		_ = json.NewDecoder(r.Body).Decode(&payload)
		if payload.Operation != "GetBillForecast" {
			t.Fatalf("operation = %q", payload.Operation)
		}
		return opowerResponse(`{"data":{"billingAccountsConnection":{"edges":[{"node":{"billForecast":{"timeInterval":"2026-07-01/2026-08-01","currentDateTime":"2026-07-12","segments":[{"serviceAgreement":{"uuid":"account-secret-1234"},"estimatedUsage":{"value":100,"unit":"KWH"},"estimatedUsageCharges":{"value":30},"soFarUsage":{"value":40},"soFarUsageCharges":{"value":12},"priorYearUsage":{"value":90},"priorYearUsageCharges":{"value":27}}]}}}]}}}`), nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	forecasts, err := client.Forecast(context.Background(), opowerSession(false))
	if err != nil {
		t.Fatal(err)
	}
	if len(forecasts) != 1 || forecasts[0].Account != "****1234" || forecasts[0].ForecastCost != 30 || forecasts[0].UsageToDate != 40 {
		t.Fatalf("forecast = %#v", forecasts)
	}
}

func TestForecastTracksAbsentAndExplicitZeroValues(t *testing.T) {
	for _, tc := range []struct {
		name      string
		estimate  string
		charges   string
		wantValue bool
		wantCost  bool
	}{
		{name: "absent", estimate: `{"unit":"kWh"}`, charges: `{}`, wantValue: false, wantCost: false},
		{name: "explicit zero", estimate: `{"value":0,"unit":"kWh"}`, charges: `{"value":0}`, wantValue: true, wantCost: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"data":{"billingAccountsConnection":{"edges":[{"node":{"billForecast":{"timeInterval":"2026-07-01/2026-08-01","currentDateTime":"2026-07-12","segments":[{"serviceAgreement":{"uuid":"synthetic-account-1234"},"estimatedUsage":` + tc.estimate + `,"estimatedUsageCharges":` + tc.charges + `,"soFarUsage":{},"soFarUsageCharges":{},"priorYearUsage":{},"priorYearUsageCharges":{}}]}}}]}}}`
			client, err := NewClient(Options{Transport: opowerRT(func(r *http.Request) (*http.Response, error) {
				if r.URL.Host == "www.coned.com" {
					return opowerResponse(`"fresh-token"`), nil
				}
				return opowerResponse(body), nil
			})})
			if err != nil {
				t.Fatal(err)
			}
			got, err := client.Forecast(context.Background(), opowerSession(false))
			if err != nil || len(got) != 1 {
				t.Fatalf("forecasts=%#v err=%v", got, err)
			}
			if !got[0].AvailabilityKnown || got[0].ForecastUsagePresent != tc.wantValue || got[0].ForecastCostPresent != tc.wantCost {
				t.Fatalf("presence=%#v", got[0])
			}
			if got[0].ForecastUsage != 0 || got[0].ForecastCost != 0 {
				t.Fatalf("values=%#v, absent and zero both retain legacy numeric zero", got[0])
			}
			legacyJSON, err := json.Marshal(got[0])
			if err != nil || !strings.Contains(string(legacyJSON), `"forecast_usage":0`) || strings.Contains(string(legacyJSON), "AvailabilityKnown") {
				t.Fatalf("legacy JSON shape changed: %s, err=%v", legacyJSON, err)
			}
		})
	}
}

func TestHistoricalReadsPreserveExplicitZeroAndSourceUnit(t *testing.T) {
	client, err := NewClient(Options{Transport: opowerRT(func(r *http.Request) (*http.Response, error) {
		switch {
		case r.URL.Host == "www.coned.com":
			return opowerResponse(`"fresh-token"`), nil
		case strings.Contains(r.URL.Path, "/customers"):
			return opowerResponse(`{"customers":[{"uuid":"customer","utilityAccounts":[{"uuid":"account-1234"}]}]}`), nil
		case strings.HasSuffix(r.URL.Path, "/reads"):
			return opowerResponse(`{"reads":[{"startTime":"a","endTime":"b","value":0,"consumption":{"value":5,"unit":"kWh"}}]}`), nil
		default:
			t.Fatalf("unexpected request %s", r.URL)
			return nil, nil
		}
	})})
	if err != nil {
		t.Fatal(err)
	}
	reads, err := client.HistoricalReads(context.Background(), opowerSession(false), ReadOptions{Aggregate: "day", From: "2026-01-01", To: "2026-01-01"})
	if err != nil || len(reads) != 1 {
		t.Fatalf("reads=%#v err=%v", reads, err)
	}
	if reads[0].Value != 0 || !reads[0].ValuePresent || reads[0].Unit != "kWh" || !reads[0].UnitPresent || !reads[0].AvailabilityKnown {
		t.Fatalf("read lost value/unit provenance: %#v", reads[0])
	}
}

func TestHistoricalCostsPreserveMissingAndExplicitZeroCost(t *testing.T) {
	for _, tc := range []struct {
		name         string
		providedCost string
		wantPresent  bool
	}{
		{name: "missing", providedCost: "", wantPresent: false},
		{name: "explicit zero", providedCost: `,"providedCost":0`, wantPresent: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, err := NewClient(Options{Transport: opowerRT(func(r *http.Request) (*http.Response, error) {
				switch {
				case r.URL.Host == "www.coned.com":
					return opowerResponse(`"fresh-token"`), nil
				case strings.Contains(r.URL.Path, "/customers"):
					return opowerResponse(`{"customers":[{"uuid":"customer","utilityAccounts":[{"uuid":"account-1234"}]}]}`), nil
				case strings.Contains(r.URL.Path, "/cost/"):
					return opowerResponse(`{"reads":[{"startTime":"a","endTime":"b","value":0` + tc.providedCost + `}]}`), nil
				case strings.HasSuffix(r.URL.Path, "/reads"):
					return opowerResponse(`{"reads":[{"startTime":"a","endTime":"b","value":9}]}`), nil
				default:
					t.Fatalf("unexpected request %s", r.URL)
					return nil, nil
				}
			})})
			if err != nil {
				t.Fatal(err)
			}
			costs, err := client.HistoricalCosts(context.Background(), opowerSession(false), ReadOptions{Aggregate: "day", From: "2026-01-01", To: "2026-01-01"})
			if err != nil || len(costs) != 1 {
				t.Fatalf("costs=%#v err=%v", costs, err)
			}
			if costs[0].Value != 0 || !costs[0].ValuePresent || costs[0].CostPresent != tc.wantPresent || costs[0].Cost != 0 {
				t.Fatalf("cost provenance=%#v", costs[0])
			}
		})
	}
}

func TestHistoricalReadsUseRESTAndBatchRanges(t *testing.T) {
	var readRequests int
	client, err := NewClient(Options{Transport: opowerRT(func(r *http.Request) (*http.Response, error) {
		switch {
		case r.URL.Host == "www.coned.com":
			return opowerResponse(`"fresh-token"`), nil
		case strings.Contains(r.URL.Path, "/customers"):
			return opowerResponse(`{"customers":[{"uuid":"customer-uuid","utilityAccounts":[{"uuid":"utility-account-9876"}]}]}`), nil
		case strings.HasSuffix(r.URL.Path, "/reads"):
			readRequests++
			if r.URL.Query().Get("aggregateType") != "hour" || r.URL.Query().Get("startDate") == "" || r.URL.Query().Get("endDate") == "" {
				t.Fatalf("query = %s", r.URL.RawQuery)
			}
			if !strings.Contains(r.Header.Get("Opower-Selected-Entities"), "customer-uuid") {
				t.Fatal("customer entity missing")
			}
			return opowerResponse(`{"reads":[{"startTime":"2026-01-01T00:00:00-05:00","endTime":"2026-01-01T01:00:00-05:00","value":1.5}]}`), nil
		default:
			t.Fatalf("unexpected request %s", r.URL)
			return nil, nil
		}
	})})
	if err != nil {
		t.Fatal(err)
	}
	reads, err := client.HistoricalReads(context.Background(), opowerSession(false), ReadOptions{Aggregate: "hour", From: "2026-01-01", To: "2026-02-01"})
	if err != nil {
		t.Fatal(err)
	}
	if readRequests != 2 || len(reads) != 2 || reads[0].Account != "****9876" || reads[0].Value != 1.5 {
		t.Fatalf("requests=%d reads=%#v", readRequests, reads)
	}
}

func TestHistoricalCostsFallBackToUsageForNonBill(t *testing.T) {
	var usageRequests int
	client, err := NewClient(Options{Transport: opowerRT(func(r *http.Request) (*http.Response, error) {
		switch {
		case r.URL.Host == "www.coned.com":
			return opowerResponse(`"fresh-token"`), nil
		case strings.Contains(r.URL.Path, "/customers"):
			return opowerResponse(`{"customers":[{"uuid":"customer","utilityAccounts":[{"uuid":"account"}]}]}`), nil
		case strings.Contains(r.URL.Path, "/cost/"):
			return &http.Response{StatusCode: 500, Header: make(http.Header), Body: http.NoBody}, nil
		case strings.HasSuffix(r.URL.Path, "/reads"):
			usageRequests++
			return opowerResponse(`{"reads":[{"startTime":"a","endTime":"b","value":2}]}`), nil
		default:
			t.Fatalf("unexpected request %s", r.URL)
			return nil, nil
		}
	})})
	if err != nil {
		t.Fatal(err)
	}
	costs, err := client.HistoricalCosts(context.Background(), opowerSession(false), ReadOptions{Aggregate: "day", From: "2026-01-01", To: "2026-01-02"})
	if err != nil {
		t.Fatal(err)
	}
	if usageRequests != 1 || len(costs) != 1 || costs[0].Value != 2 || costs[0].Cost != 0 {
		t.Fatalf("usage=%d costs=%#v", usageRequests, costs)
	}
}

func TestCustomerContractFixturesReplayThroughProductionParser(t *testing.T) {
	for _, name := range []string{"opower-customers-v1.json", "opower-customers-adversarial-v1.json"} {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile("testdata/contracts/" + name)
			if err != nil {
				t.Fatal(err)
			}
			fixture, err := contracts.Parse(data)
			if err != nil {
				t.Fatal(err)
			}
			client, _ := NewClient(Options{Transport: opowerRT(func(r *http.Request) (*http.Response, error) {
				if r.URL.Host == "www.coned.com" {
					return opowerResponse(`"fresh-token"`), nil
				}
				if strings.Contains(r.URL.Path, "/customers") {
					return opowerResponse(string(fixture.Response)), nil
				}
				return opowerResponse(`{"reads":[]}`), nil
			})})
			_, err = client.HistoricalReads(context.Background(), opowerSession(false), ReadOptions{Aggregate: "bill"})
			if name == "opower-customers-v1.json" && err != nil {
				t.Fatal(err)
			}
			if name == "opower-customers-adversarial-v1.json" && err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestReadWindowsValidation(t *testing.T) {
	for _, options := range []ReadOptions{{Aggregate: "week"}, {Aggregate: "day"}, {Aggregate: "hour", From: "bad", To: "2026-01-01"}, {Aggregate: "day", From: "2026-02-01", To: "2026-01-01"}} {
		if _, err := readWindows(options); err == nil {
			t.Fatalf("accepted %#v", options)
		}
	}
	if windows, err := readWindows(ReadOptions{Aggregate: "bill"}); err != nil || len(windows) != 1 {
		t.Fatalf("bill windows=%#v err=%v", windows, err)
	}
}
