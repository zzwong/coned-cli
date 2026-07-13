package coned

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
)

func TestDiscoverBuildsDeduplicatedHierarchy(t *testing.T) {
	client, err := NewClient(Options{Transport: opowerRT(func(request *http.Request) (*http.Response, error) {
		var query struct {
			OperationName string `json:"operationName"`
		}
		if err := json.NewDecoder(request.Body).Decode(&query); err != nil {
			t.Fatal(err)
		}
		switch query.OperationName {
		case "WBAS_BillingAccounts":
			return opowerResponse(`{"data":{"billingAccountsConnection":{"edges":[{"node":{"urn":"account-1"}}]}}}`), nil
		case "WRTAMI_GetMetadata":
			return opowerResponse(`{"data":{"billingAccountByAuthContext":{"serviceAgreementsConnection":{"edges":[{"node":{"uuid":"sa-1","serviceType":"ELECTRIC","servicePointsConnection":{"edges":[{"node":{"uuid":"meter-1","premise":{"uuid":"premise-1"},"registers":[{"serviceQuantityIdentifier":"register-1","readResolution":"HOUR","unitOfMeasure":"kWh"}]}},{"node":{"uuid":"meter-2","premise":{"uuid":"premise-1"},"registers":[{"readResolution":"DAY","unitOfMeasure":"kWh"}]}}]}}}]}}}}`), nil
		default:
			t.Fatalf("unexpected operation %q", query.OperationName)
			return nil, errors.New("unexpected operation")
		}
	})})
	if err != nil {
		t.Fatal(err)
	}
	entities, err := client.Discover(context.Background(), opowerSession(true))
	if err != nil {
		t.Fatal(err)
	}
	if len(entities) != 6 {
		t.Fatalf("entities=%#v", entities)
	}
	counts := map[string]int{}
	for _, entity := range entities {
		counts[entity.Type]++
		if entity.ContractVersion != 1 || entity.LastVerified == "" {
			t.Fatalf("missing contract metadata: %#v", entity)
		}
	}
	if counts["account"] != 1 || counts["premise"] != 1 || counts["meter"] != 2 || counts["register"] != 2 {
		t.Fatalf("counts=%v", counts)
	}
}

func TestDiscoverRejectsEmptyAccounts(t *testing.T) {
	client, err := NewClient(Options{Transport: opowerRT(func(*http.Request) (*http.Response, error) {
		return opowerResponse(`{"data":{"billingAccountsConnection":{"edges":[]}}}`), nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Discover(context.Background(), opowerSession(true)); !errors.Is(err, ErrProtocolChanged) {
		t.Fatalf("error=%v", err)
	}
}
