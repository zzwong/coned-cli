package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zzwong/coned-cli/internal/auth"
	"github.com/zzwong/coned-cli/internal/coned"
	"github.com/zzwong/coned-cli/internal/securestore"
)

type fakeBills struct {
	bills        []coned.Bill
	downloadErr  error
	downloadedID string
	onDownload   func()
}

func (f *fakeBills) ListBills(context.Context, auth.Session) ([]coned.Bill, error) {
	return f.bills, nil
}
func (f *fakeBills) DownloadBill(_ context.Context, _ auth.Session, id string, dst io.Writer) error {
	f.downloadedID = id
	if f.onDownload != nil {
		f.onDownload()
	}
	if f.downloadErr != nil {
		return f.downloadErr
	}
	_, err := io.WriteString(dst, "%PDF-synthetic")
	return err
}

func billsDependencies(t *testing.T, service BillService) Dependencies {
	t.Helper()
	store := securestore.NewMemoryStore()
	if err := auth.SaveSession(store, "default", validSession(time.Now())); err != nil {
		t.Fatal(err)
	}
	return Dependencies{Store: store, Bills: service, Clock: time.Now}
}

func TestBillsListTableJSONAndNewestFirst(t *testing.T) {
	service := &fakeBills{bills: []coned.Bill{{ID: "old", Date: "2026-01-01", Cycle: "A", DocumentType: "bill"}, {ID: "new", Date: "2026-02-01", Cycle: "B", DocumentType: "bill"}}}
	deps := billsDependencies(t, service)
	output, err := runWithDependencies(t, deps, "", "bills list")
	if err != nil || !strings.HasPrefix(output, "ID\tDATE\tCYCLE\tTYPE\nnew\t") {
		t.Fatalf("output = %q, %v", output, err)
	}
	output, err = runWithDependencies(t, deps, "", "--json bills list")
	if err != nil || strings.Contains(output, "opaque") || !strings.HasPrefix(output, "[{\"id\":\"new\"") {
		t.Fatalf("JSON = %q, %v", output, err)
	}
}

func TestBillsListSanitizesTableCellsButNotJSON(t *testing.T) {
	cycle := "January\t\x1b[31m\nFebruary"
	documentType := "bill\r\x00\u009b31m"
	deps := billsDependencies(t, &fakeBills{bills: []coned.Bill{{ID: "id", Date: "2026-02-01", Cycle: cycle, DocumentType: documentType}}})

	table, err := runWithDependencies(t, deps, "", "bills list")
	if err != nil {
		t.Fatal(err)
	}
	if table != "ID\tDATE\tCYCLE\tTYPE\nid\t2026-02-01\tJanuary[31mFebruary\tbill31m\n" {
		t.Fatalf("unsafe table output = %q", table)
	}

	output, err := runWithDependencies(t, deps, "", "--json bills list")
	if err != nil {
		t.Fatal(err)
	}
	var bills []coned.Bill
	if err := json.Unmarshal([]byte(output), &bills); err != nil {
		t.Fatal(err)
	}
	if len(bills) != 1 || bills[0].Cycle != cycle || bills[0].DocumentType != documentType {
		t.Fatalf("JSON changed bill values = %#v", bills)
	}
}

func TestBillsDownloadAtomicPermissionsAndOverwriteRules(t *testing.T) {
	directory := t.TempDir()
	output := filepath.Join(directory, "bill.pdf")
	service := &fakeBills{}
	deps := billsDependencies(t, service)
	id := publicBillID("2026-02-15")
	out, err := runWithDependencies(t, deps, "", "bills download "+id+" --output "+output)
	if err != nil || out != output+"\n" {
		t.Fatalf("download = %q, %v", out, err)
	}
	info, err := os.Stat(output)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o", info.Mode().Perm())
	}
	body, _ := os.ReadFile(output)
	if string(body) != "%PDF-synthetic" {
		t.Fatalf("body = %q", body)
	}
	if _, err := runWithDependencies(t, deps, "", "bills download "+id+" --output "+output); !errors.Is(err, coned.ErrProtocolChanged) {
		t.Fatalf("without force = %v", err)
	}
	if _, err := runWithDependencies(t, deps, "", "bills download "+id+" --output "+output+" --force"); err != nil {
		t.Fatalf("force = %v", err)
	}
	if _, err := runWithDependencies(t, deps, "", "bills download id --output "+directory); !errors.Is(err, coned.ErrProtocolChanged) {
		t.Fatalf("directory = %v", err)
	}
}

func publicBillID(date string) string {
	sum := sha256.Sum256([]byte(date))
	return date + "-" + hex.EncodeToString(sum[:])[:8]
}

func TestBillDateFromIDValidatesDateAndHashShape(t *testing.T) {
	if date, ok := billDateFromID(publicBillID("2026-02-15")); !ok || date != "2026-02-15" {
		t.Fatalf("valid ID = %q, %v", date, ok)
	}
	for _, id := range []string{"not-an-id", "2026-99-15-abcdef12", "2026-02-15-abcdef12", "2026-02-15-secret"} {
		if _, ok := billDateFromID(id); ok {
			t.Fatalf("accepted invalid ID %q", id)
		}
	}
}

func TestBillsDownloadDefaultFilenameRejectsInvalidIDDate(t *testing.T) {
	directory := t.TempDir()
	t.Chdir(directory)
	deps := billsDependencies(t, &fakeBills{})
	_, err := runWithDependencies(t, deps, "", "bills download not-an-id")
	if !errors.Is(err, coned.ErrProtocolChanged) {
		t.Fatalf("invalid ID error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(directory, "coned-bill.pdf")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unexpected default output: %v", err)
	}
}

func TestSafeBillErrorPreservesProtocolStatusSafely(t *testing.T) {
	wrapped := fmt.Errorf("%w: https://blob.example/bill.pdf?sig=secret", &coned.ProtocolError{Status: http.StatusBadGateway, RequestID: "safe-request"})
	err := safeBillError(wrapped)
	var protocol *coned.ProtocolError
	if !errors.As(err, &protocol) || protocol.Status != http.StatusBadGateway || protocol.RequestID != "" {
		t.Fatalf("safeBillError() = %#v", err)
	}
	if !strings.Contains(err.Error(), "status 502") || strings.Contains(err.Error(), "blob.example") || strings.Contains(err.Error(), "secret") {
		t.Fatalf("unsafe CLI error: %v", err)
	}
}

func TestBillsDownloadFailureLeavesNoOutputAndErrorsStaySafe(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"malformed document response", fmt.Errorf("%w: opaque-document-123", coned.ErrProtocolChanged)},
		{"non-PDF response", fmt.Errorf("%w: not-a-pdf", coned.ErrProtocolChanged)},
		{"oversized response", fmt.Errorf("%w: oversized", coned.ErrProtocolChanged)},
		{"untrusted service error", errors.New("https://blob.example/?sig=secret")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			directory := t.TempDir()
			output := filepath.Join(directory, "bill.pdf")
			deps := billsDependencies(t, &fakeBills{downloadErr: tc.err})
			text, err := runWithDependencies(t, deps, "", "bills download "+publicBillID("2026-02-15")+" --output "+output)
			if !errors.Is(err, coned.ErrProtocolChanged) || strings.Contains(text, "opaque-document-123") || strings.Contains(err.Error(), "opaque-document-123") || strings.Contains(err.Error(), "secret") {
				t.Fatalf("error=%v output=%q", err, text)
			}
			if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("output remains: %v", err)
			}
			matches, _ := filepath.Glob(filepath.Join(directory, ".coned-bill-*"))
			if len(matches) != 0 {
				t.Fatalf("temporary files remain: %v", matches)
			}
		})
	}
}

type cliRoundTripper func(*http.Request) (*http.Response, error)

func (f cliRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type cliEndlessReader struct{}

func (cliEndlessReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	return len(p), nil
}

func TestConcreteDownloadFailuresCleanUpAtCLILayer(t *testing.T) {
	for _, tc := range []struct {
		name             string
		documentResponse string
		pdf              func() io.Reader
	}{
		{"malformed document response", `{`, func() io.Reader { return strings.NewReader("%PDF-ok") }},
		{"non-PDF response", `{"url":"https://synthetic.blob.core.windows.net/bill.pdf?sig=synthetic"}`, func() io.Reader { return strings.NewReader("not a pdf") }},
		{"oversized response", `{"url":"https://synthetic.blob.core.windows.net/bill.pdf?sig=synthetic"}`, func() io.Reader { return io.MultiReader(strings.NewReader("%PDF-"), cliEndlessReader{}) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/en/accounts-billing/billing-history":
					_, _ = io.WriteString(w, `<input name="AccountMAID" value="synthetic-maid">`)
				case "/sitecore/api/ssc/ConEdWeb-Foundation-MyAccount-Areas-BillingHistory-BillingHistoryAPI/User/0/GetResidentialBillHistory":
					_, _ = io.WriteString(w, `[{"BillDate":"2026-02-15","DocumentId":"opaque-synthetic"}]`)
				case "/sitecore/api/ssc/ConEdWeb-Foundation-MyAccount-Areas-BillingHistory-BillingHistoryAPI/User/0/BillInsertImage":
					_, _ = io.WriteString(w, tc.documentResponse)
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			client, err := coned.NewClient(coned.Options{BaseURL: server.URL, InsecureLoopbackForTests: true, Transport: cliRoundTripper(func(r *http.Request) (*http.Response, error) {
				if r.URL.Hostname() == "synthetic.blob.core.windows.net" {
					return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(tc.pdf()), Request: r}, nil
				}
				return http.DefaultTransport.RoundTrip(r)
			})})
			if err != nil {
				t.Fatal(err)
			}
			u, err := url.Parse(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			store := securestore.NewMemoryStore()
			session := auth.Session{Cookies: []auth.Cookie{{Name: "CE_AUTH", Value: "synthetic", Domain: u.Hostname(), Path: "/"}}}
			if err := auth.SaveSession(store, "default", session); err != nil {
				t.Fatal(err)
			}
			output := filepath.Join(t.TempDir(), "bill.pdf")
			_, err = runWithDependencies(t, Dependencies{Store: store, Bills: client, Clock: time.Now}, "", "bills download "+publicBillID("2026-02-15")+" --output "+output)
			if !errors.Is(err, coned.ErrProtocolChanged) {
				t.Fatalf("download error = %v", err)
			}
			if _, statErr := os.Stat(output); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("output remains: %v", statErr)
			}
			matches, _ := filepath.Glob(filepath.Join(filepath.Dir(output), ".coned-bill-*"))
			if len(matches) != 0 {
				t.Fatalf("temporary files remain: %v", matches)
			}
		})
	}
}

func TestBillsDownloadRenameFailureCleansTempFile(t *testing.T) {
	directory := t.TempDir()
	output := filepath.Join(directory, "bill.pdf")
	service := &fakeBills{onDownload: func() {
		if err := os.Mkdir(output, 0o700); err != nil {
			t.Errorf("create raced destination: %v", err)
		}
	}}
	_, err := runWithDependencies(t, billsDependencies(t, service), "", "bills download "+publicBillID("2026-02-15")+" --output "+output+" --force")
	if !errors.Is(err, coned.ErrProtocolChanged) {
		t.Fatalf("publish race error = %v", err)
	}
	matches, _ := filepath.Glob(filepath.Join(directory, ".coned-bill-*"))
	if len(matches) != 0 {
		t.Fatalf("temporary files remain after publish failure: %v", matches)
	}
}

func TestBillsListRejectsPersistedExpiredSession(t *testing.T) {
	clock := time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC)
	store := securestore.NewMemoryStore()
	session := auth.Session{Cookies: []auth.Cookie{{Name: "CE_AUTH", Value: "synthetic", Expires: clock.Add(-time.Second)}}}
	if err := auth.SaveSession(store, "default", session); err != nil {
		t.Fatal(err)
	}
	deps := Dependencies{Store: store, Bills: &fakeBills{}, Clock: func() time.Time { return clock }}
	output, err := runWithDependencies(t, deps, "", "bills list")
	if !errors.Is(err, coned.ErrSessionExpired) || strings.Contains(output, "synthetic") {
		t.Fatalf("persisted expired session: output=%q err=%v", output, err)
	}
}
