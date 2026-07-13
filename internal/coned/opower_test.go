package coned

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/zzwong/coned-cli/internal/auth"
)

type opowerRT func(*http.Request) (*http.Response, error)

func (f opowerRT) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func opowerResponse(s string) *http.Response {
	return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewBufferString(s))}
}
func opowerSession(token bool) auth.Session {
	c := []auth.Cookie{{Name: "CE_AUTH", Value: "synthetic-session", Domain: "www.coned.com", Path: "/"}}
	if token {
		c = append(c, auth.Cookie{Name: "OPOWER_AUTH_TOKEN", Value: "synthetic-token", Domain: "www.coned.com", Path: "/"})
	}
	return auth.Session{Cookies: c}
}
func TestOpowerAccountsMaskIDsAndRejectPartialErrors(t *testing.T) {
	client, err := NewClient(Options{Transport: opowerRT(func(r *http.Request) (*http.Response, error) {
		var q struct {
			OperationName string `json:"operationName"`
		}
		if json.NewDecoder(r.Body).Decode(&q) != nil || q.OperationName != "WBAS_BillingAccounts" {
			t.Error("invalid graphql request")
		}
		if r.Header.Get("Authorization") != "Bearer synthetic-token" {
			t.Error("missing bearer token")
		}
		return opowerResponse(`{"data":{"billingAccountsConnection":{"edges":[{"node":{"urn":"urn:synthetic-5678","name":"Home","utilityCode":"SYN","customerClass":"RES","serviceAgreementsConnection":{"totalCount":1}}}]}}}`), nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	accounts, err := client.ListAccounts(context.Background(), opowerSession(true))
	if err != nil || len(accounts) != 1 || accounts[0].ID != "****5678" {
		t.Fatalf("accounts=%#v err=%v", accounts, err)
	}
	client.httpClient.Transport = opowerRT(func(*http.Request) (*http.Response, error) {
		return opowerResponse(`{"data":{},"errors":[{"message":"synthetic private detail"}]}`), nil
	})
	_, err = client.ListAccounts(context.Background(), opowerSession(true))
	if !errors.Is(err, ErrOpowerUnavailable) {
		t.Fatalf("partial error=%v", err)
	}
	_, err = client.ListAccounts(context.Background(), opowerSession(false))
	if !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("missing token=%v", err)
	}
}
func TestOpowerUsageResourcesEndToEnd(t *testing.T) {
	responses := map[string]string{
		"WBAS_BillingAccounts":          `{"data":{"billingAccountsConnection":{"edges":[{"node":{"urn":"urn:synthetic:account","name":"Home","utilityCode":"SYN","customerClass":"RES","serviceAgreementsConnection":{"totalCount":1}}}]}}}`,
		"WRTAMI_GetMetadata":            `{"data":{"billingAccountByAuthContext":{"serviceAgreementsConnection":{"edges":[{"node":{"uuid":"sa-1","serviceType":"ELECTRIC","servicePointsConnection":{"edges":[{"node":{"uuid":"sp-1","premise":{"uuid":"premise-1"},"registers":[{"readResolution":"HOUR","unitOfMeasure":"kWh","availableReadsTimeInterval":"2026-01-01/2026-02-01"}]}}]}}}]}}}}`,
		"WDB_GetCostUsageReadsForBills": `{"data":{"billingAccountByAuthContext":{"bills":[{"timeInterval":"2026-01-01/2026-02-01","segments":[{"usageInterval":"2026-01-01/2026-02-01","estimated":true,"serviceQuantities":[{"unit":"kWh","serviceQuantity":{"value":10}}],"usageCharges":{"value":3.5}}]}]}}}`,
		"WDB_GetWeather":                `{"data":{"billingAccountByAuthContext":{"premisesConnection":{"edges":[{"node":{"weather":[{"timeInterval":"2026-01-01/2026-01-02","minTemperature":{"value":20},"meanTemperature":{"value":30},"maxTemperature":{"value":40}}]}}]}}}}`,
		"WDB_GetNeighborComparisons":    `{"data":{"billingAccountByAuthContext":{"premisesConnection":{"edges":[{"elec":[{"meterType":"ELEC","timeInterval":"2026-01-01/2026-02-01","youUsage":{"unit":"kWh","value":10},"efficientNeighborsThresholdUsage":{"unit":"kWh","value":8},"averageOfAllNeighborsUsage":{"unit":"kWh","value":12},"numberOfNeighbors":100}]}]}}}}`,
		"WRTAMI_GetRegisters":           `{"data":{"billingAccountByAuthContext":{"serviceAgreementsConnection":{"edges":[{"node":{"servicePointsConnection":{"edges":[{"node":{"intervalReads":[{"registerId":"register-1"}]}}]}}}]}}}}`,
		"WRTAMI_GetRegisterUsage":       `{"data":{"billingAccountByAuthContext":{"serviceAgreementsConnection":{"edges":[{"node":{"servicePointsConnection":{"edges":[{"node":{"intervalReads":[{"unit":"kWh","reads":[{"timeInterval":"2026-01-01T00:00:00Z/2026-01-01T01:00:00Z","measuredAmount":{"value":1.25}}]}]}}]}}}]}}}}`,
	}
	client, err := NewClient(Options{Transport: opowerRT(func(request *http.Request) (*http.Response, error) {
		var query struct {
			OperationName string `json:"operationName"`
		}
		if err := json.NewDecoder(request.Body).Decode(&query); err != nil {
			t.Fatal(err)
		}
		body, ok := responses[query.OperationName]
		if !ok {
			t.Fatalf("unexpected operation %q", query.OperationName)
		}
		return opowerResponse(body), nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	session := opowerSession(true)
	selection := EntitySelection{Account: "urn:synthetic:account", Meter: "sp-1"}
	for _, resource := range []string{"accounts", "usage-bills", "weather", "neighbors", "meters", "realtime", "summary", "export"} {
		value, err := client.FetchSelected(context.Background(), session, resource, selection)
		if err != nil {
			t.Fatalf("%s: %v", resource, err)
		}
		if value == nil {
			t.Fatalf("%s returned nil", resource)
		}
	}
	reads, err := client.UsageRealtime(context.Background(), session, UsageOptions{Account: selection.Account})
	if err != nil || len(reads) != 1 || reads[0].Value != 1.25 {
		t.Fatalf("reads=%#v err=%v", reads, err)
	}
	summary, err := client.UsageSummary(context.Background(), session, UsageOptions{Account: selection.Account})
	if err != nil || summary.Bills != 1 || summary.Usage.Value != 10 || summary.Charges != 3.5 {
		t.Fatalf("summary=%#v err=%v", summary, err)
	}
	if _, err := client.FetchSelected(context.Background(), session, "unknown", selection); !errors.Is(err, ErrProtocolChanged) {
		t.Fatalf("unknown resource: %v", err)
	}
}

func TestRealtimeEmptyIsUnavailable(t *testing.T) {
	client, err := NewClient(Options{Transport: opowerRT(func(*http.Request) (*http.Response, error) {
		return opowerResponse(`{"data":{"billingAccountByAuthContext":{"serviceAgreementsConnection":{"edges":[]}}}}`), nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.UsageRealtime(context.Background(), opowerSession(true), UsageOptions{})
	if !errors.Is(err, ErrRealtimeUnavailable) {
		t.Fatalf("error=%v", err)
	}
}
