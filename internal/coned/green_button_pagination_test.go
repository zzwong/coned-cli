package coned

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

// Fixture version 1: authored synthetic pagination cases, last reviewed 2026-10-19.
// These fixtures make no claim of live provider verification.
// The injected transport cannot reach the network.
func greenInspectClient(t *testing.T, page func(*http.Request, string) (*http.Response, error)) *Client {
	t.Helper()
	client, err := NewClient(Options{Transport: opowerRT(func(r *http.Request) (*http.Response, error) {
		var q struct {
			OperationName string         `json:"operationName"`
			Variables     map[string]any `json:"variables"`
		}
		if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
			t.Fatal(err)
		}
		switch q.OperationName {
		case "WBAS_BillingAccounts":
			return opowerResponse(`{"data":{"billingAccountsConnection":{"edges":[{"node":{"urn":"synthetic-account-canary"}}]}}}`), nil
		case "WRTAMI_GetMetadata":
			return opowerResponse(`{"data":{"billingAccountByAuthContext":{"serviceAgreementsConnection":{"edges":[]}}}}`), nil
		case "WUE_GetMetadata":
			return opowerResponse(`{"data":{"billingAccountByAuthContext":{"customerClass":"synthetic-class-canary"}}}`), nil
		case "WUE_GetUsageExportBills":
			return opowerResponse(`{"data":{"billingAccountByAuthContext":{"bills":[{"timeInterval":"synthetic-bill-canary"}]}}}`), nil
		case "WUE_GetUsageExportAvailableAMIReadsTimeInterval":
			cursor, _ := q.Variables["nextCursor"].(string)
			return page(r, cursor)
		default:
			t.Fatalf("unexpected operation %q", q.OperationName)
			return nil, ErrProtocolChanged
		}
	})})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func greenInspectPage(connection string) *http.Response {
	return opowerResponse(`{"data":{"billingAccountByAuthContext":{"serviceAgreementsConnection":` + connection + `}}}`)
}

func TestGreenButtonInspectPagination(t *testing.T) {
	const edges = `"edges":[{"node":{"servicePoints":[{"registers":[{"availableReadsTimeInterval":"synthetic-interval-canary"}]}]}}]`
	for _, tc := range []struct {
		name      string
		pages     []string
		cursors   []string
		wantError bool
		intervals int
	}{
		{"missing page info", []string{`{` + edges + `}`}, []string{""}, true, 0},
		{"null page info", []string{`{"pageInfo":null,` + edges + `}`}, []string{""}, true, 0},
		{"missing next flag", []string{`{"pageInfo":{"endCursor":"a"},` + edges + `}`}, []string{""}, true, 0},
		{"null next flag", []string{`{"pageInfo":{"hasNextPage":null},` + edges + `}`}, []string{""}, true, 0},
		{"missing cursor", []string{`{"pageInfo":{"hasNextPage":true},` + edges + `}`}, []string{""}, true, 0},
		{"null cursor", []string{`{"pageInfo":{"hasNextPage":true,"endCursor":null},` + edges + `}`}, []string{""}, true, 0},
		{"empty cursor", []string{`{"pageInfo":{"hasNextPage":true,"endCursor":""},` + edges + `}`}, []string{""}, true, 0},
		{"terminal missing cursor", []string{`{"pageInfo":{"hasNextPage":false},"edges":[]}`}, []string{""}, false, 0},
		{"terminal null cursor", []string{`{"pageInfo":{"hasNextPage":false,"endCursor":null},"edges":[]}`}, []string{""}, false, 0},
		{"terminal empty cursor", []string{`{"pageInfo":{"hasNextPage":false,"endCursor":""},"edges":[]}`}, []string{""}, false, 0},
		{"nonempty then terminal empty", []string{`{"pageInfo":{"hasNextPage":true,"endCursor":"a"},` + edges + `}`, `{"pageInfo":{"hasNextPage":false},"edges":[]}`}, []string{"", "a"}, false, 1},
		{"opaque cursor and terminal reuse", []string{`{"pageInfo":{"hasNextPage":true,"endCursor":" a+/= "},` + edges + `}`, `{"pageInfo":{"hasNextPage":false,"endCursor":" a+/= "},` + edges + `}`}, []string{"", " a+/= "}, false, 2},
		{"same cursor", []string{`{"pageInfo":{"hasNextPage":true,"endCursor":"a"},` + edges + `}`, `{"pageInfo":{"hasNextPage":true,"endCursor":"a"},` + edges + `}`}, []string{"", "a"}, true, 0},
		{"cursor cycle", []string{`{"pageInfo":{"hasNextPage":true,"endCursor":"a"},` + edges + `}`, `{"pageInfo":{"hasNextPage":true,"endCursor":"b"},` + edges + `}`, `{"pageInfo":{"hasNextPage":true,"endCursor":"a"},` + edges + `}`}, []string{"", "a", "b"}, true, 0},
		{"later malformed page", []string{`{"pageInfo":{"hasNextPage":true,"endCursor":"a"},` + edges + `}`, `{"pageInfo":{"hasNextPage":true},` + edges + `}`}, []string{"", "a"}, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var cursors []string
			client := greenInspectClient(t, func(_ *http.Request, cursor string) (*http.Response, error) {
				index := len(cursors)
				cursors = append(cursors, cursor)
				if index >= len(tc.pages) {
					t.Fatal("unexpected extra page request")
				}
				return greenInspectPage(tc.pages[index]), nil
			})
			got, err := client.GreenButtonInspect(context.Background(), opowerSession(true))
			if !reflect.DeepEqual(cursors, tc.cursors) {
				t.Fatalf("cursors=%q want=%q", cursors, tc.cursors)
			}
			if tc.wantError {
				if !errors.Is(err, ErrProtocolChanged) || !reflect.DeepEqual(got, GreenButtonMetadata{}) {
					t.Fatalf("expected protocol failure without partial metadata: got=%#v err=%v", got, err)
				}
				if strings.Contains(err.Error(), "canary") {
					t.Fatal("provider value leaked")
				}
			} else if err != nil || len(got.AMIIntervals) != tc.intervals || got.CustomerClass != "synthetic-class-canary" || len(got.BillIntervals) != 1 {
				t.Fatalf("got=%#v err=%v", got, err)
			}
		})
	}
}

func TestGreenButtonInspectPaginationFailuresDiscardPartialData(t *testing.T) {
	for _, kind := range []string{"cancel", "session", "transport", "deadline"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			client := greenInspectClient(t, func(_ *http.Request, _ string) (*http.Response, error) {
				calls++
				if calls == 1 {
					if kind == "cancel" {
						cancel()
					}
					return greenInspectPage(`{"pageInfo":{"hasNextPage":true,"endCursor":"synthetic-cursor-canary"},"edges":[]}`), nil
				}
				if calls > 2 {
					t.Fatal("unexpected retry")
				}
				if kind == "session" {
					response := opowerResponse(`{}`)
					response.StatusCode = http.StatusUnauthorized
					return response, nil
				}
				if kind == "deadline" {
					return nil, context.DeadlineExceeded
				}
				return nil, errors.New("synthetic-transport-canary")
			})
			got, err := client.GreenButtonInspect(ctx, opowerSession(true))
			if err == nil || !reflect.DeepEqual(got, GreenButtonMetadata{}) || strings.Contains(err.Error(), "canary") {
				t.Fatalf("got=%#v err=%v", got, err)
			}
			wantCalls := 2
			switch kind {
			case "cancel":
				wantCalls = 1
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("error=%v", err)
				}
			case "session":
				if !errors.Is(err, ErrSessionExpired) {
					t.Fatalf("error=%v", err)
				}
			case "deadline":
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("error=%v", err)
				}
			case "transport":
				if _, ok := AsSafeTransportError(err); !ok {
					t.Fatalf("error=%v", err)
				}
			}
			if calls != wantCalls {
				t.Fatalf("calls=%d want=%d", calls, wantCalls)
			}
		})
	}
}
