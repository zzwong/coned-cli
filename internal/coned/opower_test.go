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
