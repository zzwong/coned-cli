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
			_, _ = io.WriteString(w, readFixture(t, "bill_history.html"))
		case residentialBillHistoryPath:
			body, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(body), "synthetic-maid") {
				t.Error("metadata was not forwarded")
			}
			_, _ = io.WriteString(w, `{"data":[{"BillDate":"01/15/2026","Cycle":"January","DocumentId":"opaque-one","DocumentType":"bill"},{"BillDate":"2026-02-15","Cycle":"February","DocumentId":"opaque-two","DocumentType":"bill"}]}`)
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

func TestListBillsForSyncRejectsSameDayProviderDocumentCollision(t *testing.T) {
	listCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case billHistoryPath:
			_, _ = io.WriteString(w, readFixture(t, "bill_history.html"))
		case residentialBillHistoryPath:
			listCalls++
			_, _ = io.WriteString(w, `{"data":[{"BillDate":"2026-02-15","DocumentId":"opaque-source-one","DocumentType":"bill"},{"BillDate":"2026-02-15","DocumentId":"opaque-source-two","DocumentType":"bill"}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := testClient(t, server)
	session := billSession(t, server.URL)
	legacy, err := client.ListBills(context.Background(), session)
	if err != nil || len(legacy) != 1 {
		t.Fatalf("legacy listing changed: bills=%#v err=%v", legacy, err)
	}
	syncBills, err := client.ListBillsForSync(context.Background(), session)
	if !errors.Is(err, ErrSelectionRequired) || len(syncBills) != 0 {
		t.Fatalf("strict sync list=%#v err=%v, want selection required", syncBills, err)
	}
	if listCalls != 2 {
		t.Fatalf("history list calls=%d, want legacy and strict requests", listCalls)
	}
}

func TestListBillsForSyncRejectsConflictingBillingMetadataBeforeList(t *testing.T) {
	var listCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case billHistoryPath:
			_, _ = io.WriteString(w, `<div data-account-maid="synthetic-one" data-maid="synthetic-two" data-sc-id="synthetic-sitecore"></div>`)
		case residentialBillHistoryPath:
			listCalls++
			_, _ = io.WriteString(w, `[]`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := testClient(t, server)
	bills, err := client.ListBillsForSync(context.Background(), billSession(t, server.URL))
	if !errors.Is(err, ErrSelectionRequired) || len(bills) != 0 || listCalls != 0 {
		t.Fatalf("strict scope was not rejected before provider list: bills=%#v err=%v calls=%d", bills, err, listCalls)
	}
}

func TestListBillsForSyncRejectsOversizedHistoryResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case billHistoryPath:
			_, _ = io.WriteString(w, readFixture(t, "bill_history.html"))
		case residentialBillHistoryPath:
			_, _ = io.WriteString(w, "[]"+strings.Repeat(" ", maxBillHistoryBodyBytes))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := testClient(t, server)
	bills, err := client.ListBillsForSync(context.Background(), billSession(t, server.URL))
	if !errors.Is(err, ErrProtocolChanged) || len(bills) != 0 {
		t.Fatalf("oversized strict history accepted: bills=%#v err=%v", bills, err)
	}
}

func TestDownloadBillForSyncRechecksScopeAndDocuments(t *testing.T) {
	for _, mode := range []string{"conflicting scope", "scope changed", "same-date source collision"} {
		t.Run(mode, func(t *testing.T) {
			historyPageCalls := 0
			listCalls := 0
			documentCalls := 0
			pdfCalls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case billHistoryPath:
					historyPageCalls++
					if mode == "conflicting scope" && historyPageCalls > 1 {
						_, _ = io.WriteString(w, `<div data-account-maid="synthetic-one" data-maid="synthetic-two" data-sc-id="synthetic-sitecore"></div>`)
						return
					}
					if mode == "scope changed" && historyPageCalls > 1 {
						_, _ = io.WriteString(w, `<div data-account-maid="synthetic-other" data-sc-id="synthetic-sitecore"></div>`)
						return
					}
					_, _ = io.WriteString(w, readFixture(t, "bill_history.html"))
				case residentialBillHistoryPath:
					listCalls++
					if mode == "same-date source collision" && listCalls > 1 {
						_, _ = io.WriteString(w, `[{"BillDate":"2026-02-15","DocumentId":"opaque-one"},{"BillDate":"2026-02-15","DocumentId":"opaque-two"}]`)
						return
					}
					_, _ = io.WriteString(w, `[{"BillDate":"2026-02-15","DocumentId":"opaque-one"}]`)
				case billInsertImagePath:
					documentCalls++
					_, _ = io.WriteString(w, `{"url":"https://synthetic.blob.core.windows.net/bill.pdf?sig=secret"}`)
				case "/bill.pdf":
					pdfCalls++
					_, _ = io.WriteString(w, "%PDF-synthetic")
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			client := testClient(t, server)
			session := billSession(t, server.URL)
			bills, err := client.ListBillsForSync(context.Background(), session)
			if err != nil || len(bills) != 1 {
				t.Fatalf("initial strict list=%#v err=%v", bills, err)
			}
			err = client.DownloadBillForSync(context.Background(), session, localBillID("2026-02-15"), io.Discard)
			if !errors.Is(err, ErrSelectionRequired) || strings.Contains(errString(err), "opaque-") || strings.Contains(errString(err), "secret") {
				t.Fatalf("strict download error=%v, want safe selection required", err)
			}
			if documentCalls != 0 || pdfCalls != 0 {
				t.Fatalf("ambiguous selection reached document endpoints: document=%d pdf=%d", documentCalls, pdfCalls)
			}
			if mode == "scope changed" && listCalls != 1 {
				t.Fatalf("changed scope reached a second bill-list request: calls=%d", listCalls)
			}
		})
	}
}

func TestStrictBillSyncParserRejectsInvalidDateAndConflictingSameDateRows(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want error
	}{
		{name: "invalid date", body: `[{"DocumentId":"opaque","BillDate":"not-a-date"}]`, want: ErrProtocolChanged},
		{name: "duplicate JSON key", body: `[{"DocumentId":"opaque-one","DocumentId":"opaque-two","BillDate":"2026-02-15"}]`, want: ErrProtocolChanged},
		{name: "conflicting normalized JSON keys", body: `[{"DocumentId":"opaque-one","document-id":"opaque-two","BillDate":"2026-02-15"}]`, want: ErrSelectionRequired},
		{name: "conflicting date aliases", body: `[{"DocumentId":"opaque-one","BillDate":"2026-02-15","date":"2026-02-16"}]`, want: ErrSelectionRequired},
		{name: "conflicting HTML document attributes", body: `<a data-document-id="opaque-one" data-document-id="opaque-two" data-bill-date="2026-02-15"></a>`, want: ErrSelectionRequired},
		{name: "same-date source collision", body: `[{"DocumentId":"opaque-one","BillDate":"2026-02-15"},{"DocumentId":"opaque-two","BillDate":"2026-02-15"}]`, want: ErrSelectionRequired},
		{name: "same source conflicting metadata", body: `[{"DocumentId":"opaque-one","BillDate":"2026-02-15","Cycle":"one"},{"DocumentId":"opaque-one","BillDate":"2026-02-15","Cycle":"two"}]`, want: ErrSelectionRequired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			records, err := parseBillRecordsForSync([]byte(tc.body))
			if !errors.Is(err, tc.want) || len(records) != 0 {
				t.Fatalf("strict parse = %#v, %v; want %v", records, err, tc.want)
			}
		})
	}
}

func TestStrictBillSyncParserAcceptsRecognizedEmptyHistoriesOnly(t *testing.T) {
	for _, body := range []string{`[]`, `{"data":[]}`, `{"data":{"bills":[]}}`} {
		records, err := parseBillRecordsForSync([]byte(body))
		if err != nil || len(records) != 0 {
			t.Fatalf("recognized empty history %s = %#v, %v", body, records, err)
		}
	}
	for _, body := range []string{`{}`, `{"unrelated":[]}`, `{"data":{"unexpected":[]}}`, `{"wrapper":{"items":[]}}`} {
		records, err := parseBillRecordsForSync([]byte(body))
		if !errors.Is(err, ErrProtocolChanged) || len(records) != 0 {
			t.Fatalf("unknown empty shape %s accepted: %#v, %v", body, records, err)
		}
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
					_, _ = io.WriteString(w, readFixture(t, "bill_history.html"))
				case residentialBillHistoryPath:
					_, _ = io.WriteString(w, `[{"BillDate":"2026-02-15","DocumentId":"opaque","DocumentType":"bill"}]`)
				case billInsertImagePath:
					if tc.status != 0 {
						w.WriteHeader(tc.status)
						return
					}
					_, _ = io.WriteString(w, `{"url":"`+tc.documentURL+`"}`)
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
			_, _ = io.WriteString(w, readFixture(t, "bill_history.html"))
		case residentialBillHistoryPath:
			_, _ = io.WriteString(w, `[{"BillDate":"2026-02-15","DocumentId":"opaque"}]`)
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
	if document, err := parseDocumentURL([]byte(readFixture(t, "bill_document.json"))); err != nil || checkDocumentURL(document) != nil {
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
			_, _ = io.WriteString(w, `<input name="AccountMAID" value="synthetic-maid">`)
		case residentialBillHistoryPath:
			_, _ = io.WriteString(w, `[{"BillDate":"2026-02-15","DocumentId":"opaque"}]`)
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
			_, _ = io.WriteString(w, readFixture(t, "bill_history.html"))
		case residentialBillHistoryPath:
			_, _ = io.WriteString(w, `[{"BillDate":"2026-02-15","DocumentId":"opaque-one","DocumentType":"bill"},{"BillDate":"2026-02-15","DocumentId":"opaque-two","DocumentType":"bill"}]`)
		case billInsertImagePath:
			insert++
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			_, _ = io.WriteString(w, `{"url":"https://synthetic.blob.core.windows.net/bill.pdf?sig=synthetic"}`)
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

const opowerTokenPath = "/sitecore/api/ssc/ConEd-Cms-Services-Controllers-Opower/OpowerService/0/GetOPowerToken"

func TestBillHistoryServerErrorIsResolvedAgainstTheSession(t *testing.T) {
	for _, tc := range []struct {
		name        string
		tokenStatus int
		want        error
	}{
		{name: "ended session", tokenStatus: http.StatusForbidden, want: ErrSessionExpired},
		{name: "provider fault", tokenStatus: http.StatusOK, want: ErrProtocolChanged},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case billHistoryPath:
					_, _ = io.WriteString(w, readFixture(t, "bill_history.html"))
				case residentialBillHistoryPath:
					w.WriteHeader(http.StatusInternalServerError)
				case opowerTokenPath:
					w.WriteHeader(tc.tokenStatus)
					_, _ = io.WriteString(w, `"synthetic-token"`)
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			_, err := testClient(t, server).ListBills(context.Background(), billSession(t, server.URL))
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if tc.want == ErrProtocolChanged {
				if protocol, ok := AsSafeProtocolError(err); !ok || protocol.Status != http.StatusInternalServerError {
					t.Fatalf("provider fault lost its status: %v", err)
				}
			}
		})
	}
}

func TestVerifySessionUsesTheTokenEndpoint(t *testing.T) {
	for _, tc := range []struct {
		status int
		want   error
	}{
		{status: http.StatusOK},
		{status: http.StatusForbidden, want: ErrSessionExpired},
		{status: http.StatusBadGateway, want: ErrProtocolChanged},
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != opowerTokenPath {
				http.NotFound(w, r)
				return
			}
			if _, err := r.Cookie("CE_AUTH"); err != nil {
				t.Error("verification did not send the stored session")
			}
			w.WriteHeader(tc.status)
			_, _ = io.WriteString(w, `"synthetic-token"`)
		}))
		err := testClient(t, server).VerifySession(context.Background(), billSession(t, server.URL))
		server.Close()
		if !errors.Is(err, tc.want) {
			t.Fatalf("status %d: err = %v, want %v", tc.status, err, tc.want)
		}
	}
	if err := (&Client{}).VerifySession(context.Background(), auth.Session{}); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("empty session: err = %v", err)
	}
}

func TestTokenEndpointOnlyTreatsRejectionAsAnEndedSession(t *testing.T) {
	for status, want := range map[int]error{
		http.StatusForbidden:       ErrSessionExpired,
		http.StatusUnauthorized:    ErrSessionExpired,
		http.StatusTooManyRequests: ErrProtocolChanged,
		http.StatusNotFound:        ErrProtocolChanged,
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
		}))
		err := testClient(t, server).VerifySession(context.Background(), billSession(t, server.URL))
		server.Close()
		if !errors.Is(err, want) {
			t.Fatalf("status %d: err = %v, want %v", status, err, want)
		}
	}
}

func TestVerifySessionLeavesTheClientJarUntouched(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()
	client := testClient(t, server)
	before := client.jar
	_ = client.VerifySession(context.Background(), billSession(t, server.URL))
	if client.jar != before || client.httpClient.Jar != before {
		t.Fatal("verification left the checked session's cookies in the client")
	}
}

func TestDocumentFailuresNameTheBrokenContractSafely(t *testing.T) {
	for _, tc := range []struct {
		response, reason, host string
	}{
		{response: `<html>not json</html>`, reason: documentNotJSON},
		{response: `{"data":{"file":"synthetic"}}`, reason: documentNoURL},
		{response: `{"url":"http://synthetic.blob.core.windows.net/b.pdf?sig=secret-signature"}`, reason: documentBadURL},
		{response: `{"url":"https://bills.example.net/b.pdf?sig=secret-signature"}`, reason: documentBadHost, host: "bills.example.net"},
		{response: `{"url":"https://synthetic.blob.core.windows.net/b.pdf?sv=unsigned"}`, reason: documentUnsigned},
	} {
		u, err := parseDocumentURL([]byte(tc.response))
		if err == nil {
			err = checkDocumentURL(u)
		}
		safe := billDownloadError(localBillID("2026-01-01"), err)
		var document *DocumentError
		if !errors.As(safe, &document) || document.Reason != tc.reason || document.Host != tc.host {
			t.Fatalf("%s: error = %#v", tc.response, safe)
		}
		if !errors.Is(safe, ErrProtocolChanged) {
			t.Fatalf("%s: no longer matches ErrProtocolChanged", tc.response)
		}
		if message := safe.Error(); !strings.Contains(message, tc.reason) || strings.Contains(message, "secret-signature") {
			t.Fatalf("%s: message = %q", tc.response, message)
		}
	}
	if err := copyPDF(io.Discard, strings.NewReader("<html>")); !errors.As(err, new(*DocumentError)) {
		t.Fatalf("non-PDF body = %v", err)
	}
	unsafe := billDownloadError(localBillID("2026-01-01"), &DocumentError{Reason: documentBadHost, Host: "evil.example/?sig=x"})
	if strings.Contains(unsafe.Error(), "sig=") {
		t.Fatalf("unvalidated host leaked: %q", unsafe.Error())
	}
}
