package coned

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zzwong/coned-cli/internal/auth"
)

func billSession(t *testing.T, rawURL string) auth.Session {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	return auth.Session{Cookies: []auth.Cookie{{Name: "CE_AUTH", Value: "synthetic", Domain: u.Hostname(), Path: "/"}}, AuthenticatedAt: time.Now()}
}

func TestListBillsUsesAuthenticatedHistoryAndReturnsPublicNewestFirst(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := r.Cookie("CE_AUTH"); err != nil {
			t.Error("history request lacked session cookie")
		}
		switch r.URL.Path {
		case billHistoryPath:
			io.WriteString(w, readFixture(t, "bill_history.html"))
		case residentialBillHistoryPath:
			body, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(body), "synthetic-maid") {
				t.Error("metadata was not forwarded")
			}
			io.WriteString(w, `{"data":[{"BillDate":"01/15/2026","Cycle":"January","DocumentId":"opaque-one","DocumentType":"bill"},{"BillDate":"2026-02-15","Cycle":"February","DocumentId":"opaque-two","DocumentType":"bill"}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	bills, err := testClient(t, server).ListBills(context.Background(), billSession(t, server.URL))
	if err != nil {
		t.Fatal(err)
	}
	if len(bills) != 2 || bills[0].Date != "2026-02-15" || !strings.HasPrefix(bills[0].ID, "2026-02-15-") {
		t.Fatalf("bills = %#v", bills)
	}
	encoded := string(mustJSON(t, bills))
	if strings.Contains(encoded, "opaque") || strings.Contains(encoded, "synthetic-maid") {
		t.Fatalf("private metadata exposed: %s", encoded)
	}
}

func TestDownloadBillValidatesURLSizeAndPDF(t *testing.T) {
	for _, tc := range []struct {
		name, documentURL, pdf string
		status, pdfStatus      int
		want                   error
	}{
		{"valid", "https://synthetic.blob.core.windows.net/bill.pdf?sig=secret", "%PDF-synthetic", 0, 0, nil},
		{"wrong host", "https://example.test/bill.pdf?sig=secret", "%PDF-synthetic", 0, 0, ErrProtocolChanged},
		{"http", "http://synthetic.blob.core.windows.net/bill.pdf", "%PDF-synthetic", 0, 0, ErrProtocolChanged},
		{"not pdf", "https://synthetic.blob.core.windows.net/bill.pdf", "not a pdf", 0, 0, ErrProtocolChanged},
		{"expired before document", "", "", http.StatusUnauthorized, 0, ErrSessionExpired},
		{"expired signed document", "https://synthetic.blob.core.windows.net/bill.pdf?sig=secret", "", 0, http.StatusUnauthorized, ErrSessionExpired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case billHistoryPath:
					io.WriteString(w, readFixture(t, "bill_history.html"))
				case residentialBillHistoryPath:
					io.WriteString(w, `[{"BillDate":"2026-02-15","DocumentId":"opaque","DocumentType":"bill"}]`)
				case billInsertImagePath:
					if tc.status != 0 {
						w.WriteHeader(tc.status)
						return
					}
					io.WriteString(w, `{"url":"`+tc.documentURL+`"}`)
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			client := testClient(t, server)
			client.httpClient.Transport = roundTripperFunc(func(r *http.Request) (*http.Response, error) {
				if r.URL.Hostname() == "synthetic.blob.core.windows.net" {
					status := tc.pdfStatus
					if status == 0 {
						status = http.StatusOK
					}
					return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(tc.pdf)), Request: r}, nil
				}
				return http.DefaultTransport.RoundTrip(r)
			})
			var output bytes.Buffer
			err := client.DownloadBill(context.Background(), billSession(t, server.URL), localBillID("2026-02-15"), &output)
			if !errors.Is(err, tc.want) {
				t.Fatalf("DownloadBill() = %v, want %v", err, tc.want)
			}
			if err == nil && output.String() != tc.pdf {
				t.Fatalf("PDF = %q", output.String())
			}
			if strings.Contains(errString(err), "secret") {
				t.Fatalf("SAS leaked: %v", err)
			}
		})
	}
}

func TestBillDownloadErrorPreservesSafeProtocolStatus(t *testing.T) {
	id := localBillID("2026-02-15")
	protocol := &ProtocolError{Status: http.StatusBadGateway, RequestID: "request-123"}
	err := billDownloadError(id, fmt.Errorf("%w: https://blob.example/bill.pdf?sig=secret", protocol))
	var got *ProtocolError
	if !errors.As(err, &got) || got.Status != http.StatusBadGateway || got.RequestID != "" {
		t.Fatalf("error = %#v", err)
	}
	if !strings.Contains(err.Error(), "status 502") || strings.Contains(err.Error(), "blob.example") || strings.Contains(err.Error(), "secret") {
		t.Fatalf("unsafe download error: %v", err)
	}
}

func TestDownloadErrorsNeverEchoUntrustedBillID(t *testing.T) {
	untrusted := "opaque-provider-document-987"
	err := billDownloadError(untrusted, fmt.Errorf("%w: %s", ErrBillNotFound, untrusted))
	if !errors.Is(err, ErrBillNotFound) || strings.Contains(err.Error(), untrusted) || strings.Contains(errors.Unwrap(err).Error(), untrusted) {
		t.Fatalf("error leaked untrusted ID or lost category: %v", err)
	}

	client := NewDefaultClient()
	err = client.DownloadBill(context.Background(), auth.Session{}, untrusted, io.Discard)
	if !errors.Is(err, ErrProtocolChanged) || strings.Contains(err.Error(), untrusted) {
		t.Fatalf("invalid ID error leaked input or lost category: %v", err)
	}
}

func TestBillSessionExpiryAndMissingBill(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case billHistoryPath:
			io.WriteString(w, readFixture(t, "bill_history.html"))
		case residentialBillHistoryPath:
			io.WriteString(w, `[{"BillDate":"2026-02-15","DocumentId":"opaque"}]`)
		}
	}))
	defer server.Close()
	client := testClient(t, server)
	if _, err := client.ListBills(context.Background(), auth.Session{}); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("expired session = %v", err)
	}
	if err := client.DownloadBill(context.Background(), billSession(t, server.URL), localBillID("2026-01-01"), io.Discard); !errors.Is(err, ErrBillNotFound) {
		t.Fatalf("missing bill = %v", err)
	}
}

func TestBillParsersRejectMalformedAndOversizedPDF(t *testing.T) {
	if document, err := parseDocumentURL([]byte(readFixture(t, "bill_document.json"))); err != nil || !validAzureBlobURL(document) {
		t.Fatalf("fixture document = %v, %v", document, err)
	}
	if _, err := parseBillRecords([]byte(`{"DocumentId":"opaque","BillDate":"not-a-date"}`)); err != nil {
		t.Fatal(err)
	}
	records, err := parseBillRecords([]byte(readFixture(t, "bill_history_nested_metadata.json")))
	if err != nil || len(records) != 0 {
		t.Fatalf("unrelated nested metadata produced records = %#v, %v", records, err)
	}
	records, err = parseBillRecords([]byte(readFixture(t, "bill_history_async.html")))
	if err != nil || len(records) != 1 || records[0].Date != "2026-06-30" || records[0].documentID != "synthetic-document" {
		t.Fatalf("HTML bill history = %#v, %v", records, err)
	}
	if _, err := parseDocumentURL([]byte(`{"url":"%"}`)); err == nil {
		t.Fatal("accepted malformed URL")
	}
	var dst bytes.Buffer
	if err := copyPDF(&dst, io.MultiReader(strings.NewReader("%PDF-"), endlessReader{})); !errors.Is(err, ErrProtocolChanged) {
		t.Fatalf("oversize = %v", err)
	}
}

type shortPrefixWriter struct{}

func (shortPrefixWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }

func TestCopyPDFRejectsShortPrefixWrite(t *testing.T) {
	err := copyPDF(shortPrefixWriter{}, strings.NewReader("%PDF-content"))
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("copyPDF() = %v, want %v", err, io.ErrShortWrite)
	}
}

type endlessReader struct{}

func (endlessReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	return len(p), nil
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func TestBillingOperationsSerializeSessionRestore(t *testing.T) {
	firstHistory := make(chan string, 1)
	secondHistory := make(chan string, 1)
	releaseFirst := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(releaseFirst) })
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case billHistoryPath:
			cookie, err := r.Cookie("CE_AUTH")
			if err != nil {
				t.Errorf("history cookie: %v", err)
				return
			}
			if cookie.Value == "first" {
				firstHistory <- cookie.Value
				<-releaseFirst
			} else {
				secondHistory <- cookie.Value
			}
			io.WriteString(w, `<input name="AccountMAID" value="synthetic-maid">`)
		case residentialBillHistoryPath:
			io.WriteString(w, `[{"BillDate":"2026-02-15","DocumentId":"opaque"}]`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := testClient(t, server)
	firstSession := billSessionWithCookie(t, server.URL, "first")
	secondSession := billSessionWithCookie(t, server.URL, "second")
	results := make(chan error, 2)
	go func() {
		_, err := client.ListBills(context.Background(), firstSession)
		results <- err
	}()
	select {
	case <-firstHistory:
	case <-time.After(time.Second):
		t.Fatal("first operation did not reach history")
	}
	go func() {
		_, err := client.ListBills(context.Background(), secondSession)
		results <- err
	}()
	select {
	case value := <-secondHistory:
		t.Fatalf("second operation reached history before first completed with cookie %q", value)
	case <-time.After(50 * time.Millisecond):
	}
	releaseOnce.Do(func() { close(releaseFirst) })
	for range 2 {
		if err := <-results; err != nil {
			t.Fatalf("ListBills() = %v", err)
		}
	}
	select {
	case value := <-secondHistory:
		if value != "second" {
			t.Fatalf("second operation used cookie %q", value)
		}
	case <-time.After(time.Second):
		t.Fatal("second operation did not reach history")
	}
}

func billSessionWithCookie(t *testing.T, rawURL, value string) auth.Session {
	session := billSession(t, rawURL)
	session.Cookies[0].Value = value
	return session
}

func TestSameDateIDsAreSafeAndAmbiguousDownloadsAreRejected(t *testing.T) {
	var history, insert int
	var payload map[string]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case billHistoryPath:
			history++
			io.WriteString(w, readFixture(t, "bill_history.html"))
		case residentialBillHistoryPath:
			io.WriteString(w, `[{"BillDate":"2026-02-15","DocumentId":"opaque-one","DocumentType":"bill"},{"BillDate":"2026-02-15","DocumentId":"opaque-two","DocumentType":"bill"}]`)
		case billInsertImagePath:
			insert++
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			io.WriteString(w, `{"url":"https://synthetic.blob.core.windows.net/bill.pdf?sig=synthetic"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := testClient(t, server)
	client.httpClient.Transport = roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Hostname() == "synthetic.blob.core.windows.net" {
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("%PDF-test")), Request: r}, nil
		}
		return http.DefaultTransport.RoundTrip(r)
	})
	id := localBillID("2026-02-15")
	if err := client.DownloadBill(context.Background(), billSession(t, server.URL), id, io.Discard); !errors.Is(err, ErrProtocolChanged) {
		t.Fatalf("ambiguous same-date download = %v", err)
	}
	if history != 1 || insert != 0 {
		t.Fatalf("history=%d insert=%d; expected one history fetch and no download", history, insert)
	}
	if len(payload) != 0 {
		t.Fatalf("unexpected payload = %#v", payload)
	}
	records, err := parseBillRecords([]byte(`[{"BillDate":"2026-02-15","DocumentId":"opaque-one"},{"BillDate":"2026-02-15","DocumentId":"opaque-two"}]`))
	if err != nil || len(records) != 2 || records[0].ID != records[1].ID || records[0].ID != id {
		t.Fatalf("same-date records = %#v, %v", records, err)
	}
}
