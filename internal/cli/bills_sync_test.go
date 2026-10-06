package cli

import (
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
	"github.com/zzwong/coned-cli/internal/securestore"
)

type syncBillsFixture struct {
	items           []coned.Bill
	listErr         error
	legacyCalls     int
	downloads       []string
	pdfs            map[string]string
	errByID         map[string]error
	onDownload      func(string)
	afterWrite      func(string, io.Writer)
	waitForContext  bool
	listWaitContext bool
}

func (f *syncBillsFixture) ListBills(context.Context, auth.Session) ([]coned.Bill, error) {
	f.legacyCalls++
	return f.items, nil
}

func (f *syncBillsFixture) ListBillsForSync(ctx context.Context, _ auth.Session) ([]coned.Bill, error) {
	if f.listWaitContext {
		<-ctx.Done()
	}
	return f.items, f.listErr
}

func (f *syncBillsFixture) DownloadBill(ctx context.Context, _ auth.Session, id string, dst io.Writer) error {
	f.downloads = append(f.downloads, id)
	if f.onDownload != nil {
		f.onDownload(id)
	}
	if err := f.errByID[id]; err != nil {
		return err
	}
	if f.waitForContext {
		if _, err := io.WriteString(dst, "%PDF-partial"); err != nil {
			return err
		}
		<-ctx.Done()
		return ctx.Err()
	}
	pdf, ok := f.pdfs[id]
	if !ok {
		pdf = "%PDF-synthetic-" + id
	}
	_, err := io.WriteString(dst, pdf)
	if f.afterWrite != nil {
		f.afterWrite(id, dst)
	}
	return err
}

func (f *syncBillsFixture) DownloadBillForSync(ctx context.Context, session auth.Session, id string, dst io.Writer) error {
	return f.DownloadBill(ctx, session, id, dst)
}

func syncTestDependencies(t *testing.T, service BillService) Dependencies {
	t.Helper()
	deps := billsDependencies(t, service)
	deps.Clock = func() time.Time { return time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC) }
	return deps
}

func syncData(t *testing.T, envelope map[string]any) map[string]any {
	t.Helper()
	data, ok := envelope["data"].(map[string]any)
	if !ok {
		t.Fatalf("envelope data = %#v", envelope["data"])
	}
	return data
}

func TestBillSyncLatestOnlyUsesStrictServiceAndVerifiedManifest(t *testing.T) {
	directory := t.TempDir()
	service := &syncBillsFixture{items: []coned.Bill{
		{ID: publicBillID("2026-01-01"), Date: "2026-01-01"},
		{ID: publicBillID("2026-03-01"), Date: "2026-03-01"},
		{ID: publicBillID("2026-02-01"), Date: "2026-02-01"},
	}}
	code, stdout, stderr := executeEnvelopeForTest(t, syncTestDependencies(t, service), "", "--json-envelope", "bills", "sync", "--directory", directory)
	got := decodeEnvelopeForTest(t, stdout)
	if code != 0 || got["ok"] != true || got["command"] != "bills.sync" || stderr != "" {
		t.Fatalf("code=%d envelope=%#v stderr=%q", code, got, stderr)
	}
	if len(service.downloads) != 1 || service.downloads[0] != publicBillID("2026-03-01") {
		t.Fatalf("latest-only downloads = %#v", service.downloads)
	}
	data := syncData(t, got)
	results := data["results"].([]any)
	expectedDirectory, err := filepath.EvalSymlinks(directory)
	if err != nil {
		t.Fatal(err)
	}
	if data["since"] != nil || data["directory"] != expectedDirectory || data["downloaded"] != float64(1) || len(results) != 1 {
		t.Fatalf("manifest = %#v", data)
	}
	result := results[0].(map[string]any)
	if result["status"] != "downloaded" || result["bill_id"] != publicBillID("2026-03-01") || result["bytes"] == nil || result["sha256"] == nil {
		t.Fatalf("download result lacks verified public metadata: %#v", result)
	}
	if strings.Contains(stdout, "DocumentId") || strings.Contains(stdout, "synthetic") {
		t.Fatalf("provider/private data leaked: %q", stdout)
	}
	path := filepath.Join(directory, "coned-bill-"+publicBillID("2026-03-01")+".pdf")
	if body, err := os.ReadFile(path); err != nil || !strings.HasPrefix(string(body), "%PDF-") {
		t.Fatalf("published PDF = %q, %v", body, err)
	}
}

func TestBillSyncSinceIsExclusiveAndOrdersOldestFirst(t *testing.T) {
	directory := t.TempDir()
	service := &syncBillsFixture{items: []coned.Bill{
		{ID: publicBillID("2026-03-01"), Date: "2026-03-01"},
		{ID: publicBillID("2026-02-01"), Date: "2026-02-01"},
		{ID: publicBillID("2026-01-31"), Date: "2026-01-31"},
	}}
	code, stdout, stderr := executeEnvelopeForTest(t, syncTestDependencies(t, service), "", "bills", "sync", "--since", "2026-01-31", "--directory", directory, "--json-envelope")
	got := decodeEnvelopeForTest(t, stdout)
	if code != 0 || got["ok"] != true || stderr != "" {
		t.Fatalf("code=%d envelope=%#v stderr=%q", code, got, stderr)
	}
	want := []string{publicBillID("2026-02-01"), publicBillID("2026-03-01")}
	if len(service.downloads) != len(want) || service.downloads[0] != want[0] || service.downloads[1] != want[1] {
		t.Fatalf("downloads = %#v, want %#v", service.downloads, want)
	}
	data := syncData(t, got)
	if data["since"] != "2026-01-31" || data["downloaded"] != float64(2) || data["existing"] != float64(0) {
		t.Fatalf("manifest = %#v", data)
	}
}

func TestBillSyncEmptyHistoryIsSuccessfulEmptyManifest(t *testing.T) {
	directory := t.TempDir()
	service := &syncBillsFixture{}
	code, stdout, stderr := executeEnvelopeForTest(t, syncTestDependencies(t, service), "", "--json-envelope", "bills", "sync", "--directory", directory)
	got := decodeEnvelopeForTest(t, stdout)
	if code != 0 || got["ok"] != true || stderr != "" {
		t.Fatalf("empty sync: code=%d envelope=%#v stderr=%q", code, got, stderr)
	}
	data := syncData(t, got)
	if results, ok := data["results"].([]any); !ok || len(results) != 0 || data["failed"] != float64(0) || data["not_attempted"] != float64(0) {
		t.Fatalf("empty manifest = %#v", data)
	}
}

func TestBillSyncTimeoutRemovesTemporaryFileAndMarksRemainingUnattempted(t *testing.T) {
	directory := t.TempDir()
	first := publicBillID("2026-03-10")
	second := publicBillID("2026-03-11")
	service := &syncBillsFixture{
		items:          []coned.Bill{{ID: second, Date: "2026-03-11"}, {ID: first, Date: "2026-03-10"}},
		waitForContext: true,
	}
	code, stdout, stderr := executeEnvelopeForTest(t, syncTestDependencies(t, service), "", "--json-envelope", "--timeout=20ms", "bills", "sync", "--since", "2026-03-01", "--directory", directory)
	got := decodeEnvelopeForTest(t, stdout)
	if code != 1 || got["error"].(map[string]any)["code"] != "timeout" || stderr != "" {
		t.Fatalf("timeout sync: code=%d envelope=%#v stderr=%q", code, got, stderr)
	}
	data := syncData(t, got)
	results := data["results"].([]any)
	if data["failed"] != float64(1) || data["not_attempted"] != float64(1) || results[0].(map[string]any)["status"] != "failed" || results[1].(map[string]any)["status"] != "not_attempted" {
		t.Fatalf("timeout manifest = %#v", data)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		t.Fatalf("timeout leaked a temporary file: entries=%#v err=%v", entries, err)
	}
}

func TestBillSyncTimeoutDuringListDoesNotReportEmptySuccess(t *testing.T) {
	directory := t.TempDir()
	first := publicBillID("2026-03-20")
	second := publicBillID("2026-03-21")
	service := &syncBillsFixture{
		items:           []coned.Bill{{ID: first, Date: "2026-03-20"}, {ID: second, Date: "2026-03-21"}},
		listWaitContext: true,
	}
	code, stdout, stderr := executeEnvelopeForTest(t, syncTestDependencies(t, service), "", "--json-envelope", "--timeout=20ms", "bills", "sync", "--since", "2026-03-01", "--directory", directory)
	got := decodeEnvelopeForTest(t, stdout)
	if code != 1 || got["error"].(map[string]any)["code"] != "timeout" || stderr != "" {
		t.Fatalf("list timeout: code=%d envelope=%#v stderr=%q", code, got, stderr)
	}
	data := syncData(t, got)
	results := data["results"].([]any)
	if data["failed"] != float64(0) || data["not_attempted"] != float64(2) || len(results) != 2 || results[0].(map[string]any)["status"] != "not_attempted" || results[1].(map[string]any)["status"] != "not_attempted" {
		t.Fatalf("list-timeout manifest = %#v", data)
	}
	if len(service.downloads) != 0 {
		t.Fatalf("list timeout reached downloads: %#v", service.downloads)
	}
}

func TestBillSyncDemoModeIsOfflineAndHumanModeUsesManifestStatuses(t *testing.T) {
	directory := t.TempDir()
	code, stdout, stderr := executeEnvelopeForTest(t, Dependencies{Store: securestore.NewMemoryStore()}, "", "--json-envelope", "--demo", "bills", "sync", "--directory", directory)
	got := decodeEnvelopeForTest(t, stdout)
	if code != 0 || got["ok"] != true || got["command"] != "bills.sync" || stderr != "" {
		t.Fatalf("offline demo sync: code=%d envelope=%#v stderr=%q", code, got, stderr)
	}
	data := syncData(t, got)
	results := data["results"].([]any)
	if data["downloaded"] != float64(1) || len(results) != 1 || results[0].(map[string]any)["status"] != "downloaded" {
		t.Fatalf("demo manifest = %#v", data)
	}
	path := filepath.Join(directory, results[0].(map[string]any)["filename"].(string))
	if body, err := os.ReadFile(path); err != nil || !strings.HasPrefix(string(body), "%PDF-") {
		t.Fatalf("demo did not write synthetic PDF: %q err=%v", body, err)
	}

	service := &syncBillsFixture{items: []coned.Bill{{ID: publicBillID("2026-03-12"), Date: "2026-03-12"}}}
	human, err := runWithDependencies(t, syncTestDependencies(t, service), "", "bills sync --directory "+directory)
	if err != nil || !strings.Contains(human, "STATUS\tDATE\tBILL_ID\tFILE\tBYTES\tSHA256\tERROR") || !strings.Contains(human, "downloaded\t2026-03-12\t") {
		t.Fatalf("human sync table does not reflect result statuses: output=%q err=%v", human, err)
	}
}

func TestBillSyncRerunVerifiesExistingAndDoesNotDownloadAgain(t *testing.T) {
	directory := t.TempDir()
	id := publicBillID("2026-04-02")
	service := &syncBillsFixture{items: []coned.Bill{{ID: id, Date: "2026-04-02"}}}
	deps := syncTestDependencies(t, service)
	args := []string{"--json-envelope", "bills", "sync", "--directory", directory}
	code, first, _ := executeEnvelopeForTest(t, deps, "", args...)
	if code != 0 {
		t.Fatalf("first sync code=%d: %s", code, first)
	}
	code, second, stderr := executeEnvelopeForTest(t, deps, "", args...)
	got := decodeEnvelopeForTest(t, second)
	if code != 0 || got["ok"] != true || stderr != "" || len(service.downloads) != 1 {
		t.Fatalf("repeat sync code=%d envelope=%#v downloads=%#v stderr=%q", code, got, service.downloads, stderr)
	}
	data := syncData(t, got)
	result := data["results"].([]any)[0].(map[string]any)
	if data["existing"] != float64(1) || data["downloaded"] != float64(0) || result["status"] != "existing" || result["sha256"] == nil || result["bytes"] == nil {
		t.Fatalf("existing result not re-verified: %#v", data)
	}
}

func TestBillSyncPartialRetrySkipsVerifiedFilesAndCompletesMissing(t *testing.T) {
	directory := t.TempDir()
	first := publicBillID("2026-04-10")
	second := publicBillID("2026-04-11")
	third := publicBillID("2026-04-12")
	service := &syncBillsFixture{
		items:   []coned.Bill{{ID: third, Date: "2026-04-12"}, {ID: first, Date: "2026-04-10"}, {ID: second, Date: "2026-04-11"}},
		errByID: map[string]error{second: &coned.TransportError{Kind: coned.TransportConnection}},
	}
	deps := syncTestDependencies(t, service)
	args := []string{"--json-envelope", "bills", "sync", "--since", "2026-04-01", "--directory", directory}
	code, firstOutput, _ := executeEnvelopeForTest(t, deps, "", args...)
	firstEnvelope := decodeEnvelopeForTest(t, firstOutput)
	if code != 1 || firstEnvelope["error"].(map[string]any)["code"] != "transport_failed" {
		t.Fatalf("first partial sync code=%d envelope=%#v", code, firstEnvelope)
	}
	firstResults := syncData(t, firstEnvelope)["results"].([]any)
	if firstResults[0].(map[string]any)["status"] != "downloaded" || firstResults[1].(map[string]any)["status"] != "failed" || firstResults[2].(map[string]any)["status"] != "not_attempted" {
		t.Fatalf("first partial results = %#v", firstResults)
	}
	delete(service.errByID, second)
	code, secondOutput, stderr := executeEnvelopeForTest(t, deps, "", args...)
	secondEnvelope := decodeEnvelopeForTest(t, secondOutput)
	if code != 0 || secondEnvelope["ok"] != true || stderr != "" {
		t.Fatalf("retry code=%d envelope=%#v stderr=%q", code, secondEnvelope, stderr)
	}
	data := syncData(t, secondEnvelope)
	results := data["results"].([]any)
	if data["existing"] != float64(1) || data["downloaded"] != float64(2) || data["failed"] != float64(0) || results[0].(map[string]any)["status"] != "existing" || results[1].(map[string]any)["status"] != "downloaded" || results[2].(map[string]any)["status"] != "downloaded" {
		t.Fatalf("retry manifest = %#v", data)
	}
	if strings.Join(service.downloads, ",") != strings.Join([]string{first, second, second, third}, ",") {
		t.Fatalf("retry download attempts = %#v", service.downloads)
	}
}

func TestBillSyncOversizedSyntheticPDFIsRejectedAndTempRemoved(t *testing.T) {
	directory := t.TempDir()
	id := publicBillID("2026-04-20")
	service := &syncBillsFixture{
		items: []coned.Bill{{ID: id, Date: "2026-04-20"}},
		afterWrite: func(_ string, output io.Writer) {
			writer := output.(*billSyncWriter)
			if err := writer.file.Truncate(billSyncMaxBytes + 1); err != nil {
				t.Errorf("truncate synthetic PDF: %v", err)
			}
		},
	}
	code, stdout, stderr := executeEnvelopeForTest(t, syncTestDependencies(t, service), "", "--json-envelope", "bills", "sync", "--directory", directory)
	got := decodeEnvelopeForTest(t, stdout)
	if code != 1 || got["error"].(map[string]any)["code"] != "provider_protocol_changed" || stderr != "" {
		t.Fatalf("oversized response: code=%d envelope=%#v stderr=%q", code, got, stderr)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		t.Fatalf("oversized temporary file leaked: entries=%#v err=%v", entries, err)
	}
}

func TestBillSyncDoesNotOverwriteExistingInvalidPDF(t *testing.T) {
	directory := t.TempDir()
	id := publicBillID("2026-04-21")
	path := filepath.Join(directory, "coned-bill-"+id+".pdf")
	const canary = "keep invalid file intact"
	if err := os.WriteFile(path, []byte(canary), 0o600); err != nil {
		t.Fatal(err)
	}
	service := &syncBillsFixture{items: []coned.Bill{{ID: id, Date: "2026-04-21"}}}
	code, stdout, stderr := executeEnvelopeForTest(t, syncTestDependencies(t, service), "", "--json-envelope", "bills", "sync", "--directory", directory)
	got := decodeEnvelopeForTest(t, stdout)
	if code != 1 || got["error"].(map[string]any)["code"] != "output_conflict" || len(service.downloads) != 0 || stderr != "" {
		t.Fatalf("invalid existing PDF was not rejected: code=%d envelope=%#v stderr=%q", code, got, stderr)
	}
	if body, err := os.ReadFile(path); err != nil || string(body) != canary {
		t.Fatalf("invalid existing file changed: %q err=%v", body, err)
	}
}

func TestBillSyncDestinationRaceIsNoReplace(t *testing.T) {
	directory := t.TempDir()
	id := publicBillID("2026-04-22")
	path := filepath.Join(directory, "coned-bill-"+id+".pdf")
	const canary = "concurrent destination"
	service := &syncBillsFixture{
		items: []coned.Bill{{ID: id, Date: "2026-04-22"}},
		onDownload: func(string) {
			if err := os.WriteFile(path, []byte(canary), 0o600); err != nil {
				t.Errorf("create concurrent destination: %v", err)
			}
		},
	}
	code, stdout, stderr := executeEnvelopeForTest(t, syncTestDependencies(t, service), "", "--json-envelope", "bills", "sync", "--directory", directory)
	got := decodeEnvelopeForTest(t, stdout)
	if code != 1 || got["error"].(map[string]any)["code"] != "output_conflict" || stderr != "" {
		t.Fatalf("destination race: code=%d envelope=%#v stderr=%q", code, got, stderr)
	}
	if body, err := os.ReadFile(path); err != nil || string(body) != canary {
		t.Fatalf("concurrent file was overwritten: %q err=%v", body, err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 1 || entries[0].Name() != filepath.Base(path) {
		t.Fatalf("destination race leaked temp file: %#v err=%v", entries, err)
	}
}

func TestBillSyncDirectorySymlinkRejectedBeforeProviderAccess(t *testing.T) {
	directory := t.TempDir()
	link := filepath.Join(t.TempDir(), "directory-link")
	if err := os.Symlink(directory, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	service := &syncBillsFixture{}
	code, stdout, stderr := executeEnvelopeForTest(t, syncTestDependencies(t, service), "", "--json-envelope", "bills", "sync", "--directory", link)
	got := decodeEnvelopeForTest(t, stdout)
	if code != 2 || got["error"].(map[string]any)["code"] != "invalid_argument" || len(service.downloads) != 0 || stderr != "" {
		t.Fatalf("directory symlink accepted: code=%d envelope=%#v stderr=%q", code, got, stderr)
	}
}

func TestBillSyncManifestUsesCanonicalPathThroughAncestorSymlink(t *testing.T) {
	parent := t.TempDir()
	realParent := filepath.Join(parent, "real-parent")
	if err := os.Mkdir(realParent, 0o700); err != nil {
		t.Fatal(err)
	}
	realDirectory := filepath.Join(realParent, "bills")
	if err := os.Mkdir(realDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	aliasedParent := filepath.Join(parent, "parent-alias")
	if err := os.Symlink(realParent, aliasedParent); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	directory := filepath.Join(aliasedParent, "bills")
	finalInfo, err := os.Lstat(directory)
	if err != nil {
		t.Fatal(err)
	}
	if finalInfo.Mode()&os.ModeSymlink != 0 || !finalInfo.IsDir() {
		t.Fatalf("final directory component is not a real directory: mode=%v", finalInfo.Mode())
	}

	id := publicBillID("2026-07-02")
	service := &syncBillsFixture{items: []coned.Bill{{ID: id, Date: "2026-07-02"}}}
	code, stdout, stderr := executeEnvelopeForTest(t, syncTestDependencies(t, service), "", "--json-envelope", "bills", "sync", "--directory", directory)
	got := decodeEnvelopeForTest(t, stdout)
	if code != 0 || got["ok"] != true || stderr != "" {
		t.Fatalf("ancestor-symlink sync: code=%d envelope=%#v stderr=%q", code, got, stderr)
	}
	expectedDirectory, err := filepath.EvalSymlinks(directory)
	if err != nil {
		t.Fatal(err)
	}
	data := syncData(t, got)
	if data["directory"] != expectedDirectory || expectedDirectory == directory {
		t.Fatalf("manifest directory=%v, want canonical path %q from %q", data["directory"], expectedDirectory, directory)
	}
	filename := data["results"].([]any)[0].(map[string]any)["filename"].(string)
	if _, err := os.Stat(filepath.Join(realDirectory, filename)); err != nil {
		t.Fatalf("bill was not published beneath the resolved directory: %v", err)
	}
}

func TestBillSyncDetectsDirectoryReplacementAndCleansRetainedRoot(t *testing.T) {
	parent := t.TempDir()
	directory := filepath.Join(parent, "bills")
	moved := filepath.Join(parent, "bills-moved")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	first := publicBillID("2026-04-23")
	second := publicBillID("2026-04-24")
	replaced := false
	service := &syncBillsFixture{
		items: []coned.Bill{{ID: second, Date: "2026-04-24"}, {ID: first, Date: "2026-04-23"}},
		onDownload: func(string) {
			if replaced {
				return
			}
			replaced = true
			if err := os.Rename(directory, moved); err != nil {
				t.Errorf("rename retained directory: %v", err)
				return
			}
			if err := os.Mkdir(directory, 0o700); err != nil {
				t.Errorf("replace logical directory: %v", err)
			}
		},
	}
	code, stdout, stderr := executeEnvelopeForTest(t, syncTestDependencies(t, service), "", "--json-envelope", "bills", "sync", "--since", "2026-04-01", "--directory", directory)
	got := decodeEnvelopeForTest(t, stdout)
	if code != 1 || got["error"].(map[string]any)["code"] != "output_failed" || stderr != "" {
		t.Fatalf("directory replacement was not detected: code=%d envelope=%#v stderr=%q", code, got, stderr)
	}
	data := syncData(t, got)
	results := data["results"].([]any)
	if data["failed"] != float64(1) || data["not_attempted"] != float64(1) || results[0].(map[string]any)["error_code"] != "output_failed" || results[1].(map[string]any)["status"] != "not_attempted" {
		t.Fatalf("directory replacement manifest = %#v", data)
	}
	for _, path := range []string{directory, moved} {
		entries, err := os.ReadDir(path)
		if err != nil || len(entries) != 0 {
			t.Fatalf("unexpected file left in %s: %#v err=%v", path, entries, err)
		}
	}
}

func TestBillSyncRejectsMissingStrictServiceAndSelectionsBeforeSession(t *testing.T) {
	directory := t.TempDir()
	legacy := &fakeBills{}
	code, stdout, stderr := executeEnvelopeForTest(t, Dependencies{Store: securestore.NewMemoryStore(), Bills: legacy}, "", "--json-envelope", "bills", "sync", "--directory", directory)
	got := decodeEnvelopeForTest(t, stdout)
	if code != 1 || got["error"].(map[string]any)["code"] != "selection_required" || legacy.downloadedID != "" || stderr != "" {
		t.Fatalf("legacy service was not rejected closed: code=%d envelope=%#v stderr=%q", code, got, stderr)
	}

	service := &syncBillsFixture{}
	deps := Dependencies{Store: securestore.NewMemoryStore(), Bills: service}
	for _, selector := range []string{"--account", "--meter"} {
		code, stdout, stderr = executeEnvelopeForTest(t, deps, "", "--json-envelope", "bills", "sync", "--directory", directory, selector, "account-canary")
		got = decodeEnvelopeForTest(t, stdout)
		if code != 1 || got["error"].(map[string]any)["code"] != "selection_required" || service.legacyCalls != 0 || len(service.downloads) != 0 || strings.Contains(stdout+stderr, "account-canary") {
			t.Fatalf("selector %s was not rejected before session/provider access: code=%d envelope=%#v stderr=%q", selector, code, got, stderr)
		}
	}
}

func TestBillSyncRejectsSavedAccountSelectionBeforeSession(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(t.TempDir(), "config.json")
	configData := `{"profile":"default","selections":{"default":{"default_account":"account-synthetic"}}}`
	if err := os.WriteFile(configPath, []byte(configData), 0o600); err != nil {
		t.Fatal(err)
	}
	service := &syncBillsFixture{}
	code, stdout, stderr := executeEnvelopeForTest(t, Dependencies{ConfigPath: configPath, Store: securestore.NewMemoryStore(), Bills: service}, "", "--json-envelope", "bills", "sync", "--directory", directory)
	got := decodeEnvelopeForTest(t, stdout)
	if code != 1 || got["error"].(map[string]any)["code"] != "selection_required" || len(service.downloads) != 0 || service.legacyCalls != 0 || stderr != "" {
		t.Fatalf("saved account selection was not rejected offline: code=%d envelope=%#v stderr=%q", code, got, stderr)
	}
}

func TestBillSyncRejectsAmbiguousOrInvalidServiceRecords(t *testing.T) {
	directory := t.TempDir()
	for name, bills := range map[string][]coned.Bill{
		"duplicate public ID": {{ID: publicBillID("2026-05-01"), Date: "2026-05-01"}, {ID: publicBillID("2026-05-01"), Date: "2026-05-01"}},
		"date mismatch":       {{ID: publicBillID("2026-05-01"), Date: "2026-05-02"}},
		"malformed ID":        {{ID: "provider-document-canary", Date: "2026-05-01"}},
	} {
		t.Run(name, func(t *testing.T) {
			service := &syncBillsFixture{items: bills}
			code, stdout, stderr := executeEnvelopeForTest(t, syncTestDependencies(t, service), "", "--json-envelope", "bills", "sync", "--directory", directory)
			got := decodeEnvelopeForTest(t, stdout)
			if code != 1 || got["error"].(map[string]any)["code"] == nil || len(service.downloads) != 0 || strings.Contains(stdout+stderr, "provider-document-canary") {
				t.Fatalf("unsafe records were not rejected before writes: code=%d envelope=%#v stderr=%q", code, got, stderr)
			}
		})
	}
}

func TestBillSyncContinuesPerBillPDFFailureAndReturnsPartialManifestOnTransportStop(t *testing.T) {
	directory := t.TempDir()
	first := publicBillID("2026-06-01")
	second := publicBillID("2026-06-02")
	third := publicBillID("2026-06-03")
	service := &syncBillsFixture{
		items:   []coned.Bill{{ID: third, Date: "2026-06-03"}, {ID: first, Date: "2026-06-01"}, {ID: second, Date: "2026-06-02"}},
		pdfs:    map[string]string{first: "<html>not a bill</html>"},
		errByID: map[string]error{second: &coned.TransportError{Kind: coned.TransportConnection}},
	}
	code, stdout, stderr := executeEnvelopeForTest(t, syncTestDependencies(t, service), "", "--json-envelope", "bills", "sync", "--since", "2026-05-01", "--directory", directory)
	got := decodeEnvelopeForTest(t, stdout)
	if code != 1 || got["ok"] != false || got["command"] != "bills.sync" || stderr != "" {
		t.Fatalf("code=%d envelope=%#v stderr=%q", code, got, stderr)
	}
	if got["error"].(map[string]any)["code"] != "transport_failed" {
		t.Fatalf("top-level error lost systemic stop cause: %#v", got["error"])
	}
	data := syncData(t, got)
	results := data["results"].([]any)
	if data["failed"] != float64(2) || data["not_attempted"] != float64(1) || len(service.downloads) != 2 || results[0].(map[string]any)["error_code"] != "provider_protocol_changed" || results[1].(map[string]any)["error_code"] != "transport_failed" || results[2].(map[string]any)["status"] != "not_attempted" {
		t.Fatalf("partial manifest = %#v downloads=%#v", data, service.downloads)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("failed/stopped sync left published or temporary files: %#v", entries)
	}
}

func TestBillSyncExistingSymlinkAndInvalidPDFAreUntouchedConflicts(t *testing.T) {
	directory := t.TempDir()
	id := publicBillID("2026-07-01")
	outside := filepath.Join(t.TempDir(), "outside.pdf")
	if err := os.WriteFile(outside, []byte("preserve me"), 0o600); err != nil {
		t.Fatal(err)
	}
	name := "coned-bill-" + id + ".pdf"
	if err := os.Symlink(outside, filepath.Join(directory, name)); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	service := &syncBillsFixture{items: []coned.Bill{{ID: id, Date: "2026-07-01"}}}
	code, stdout, stderr := executeEnvelopeForTest(t, syncTestDependencies(t, service), "", "--json-envelope", "bills", "sync", "--directory", directory)
	got := decodeEnvelopeForTest(t, stdout)
	if code != 1 || got["error"].(map[string]any)["code"] != "output_conflict" || len(service.downloads) != 0 || stderr != "" {
		t.Fatalf("symlink destination was not rejected safely: code=%d envelope=%#v stderr=%q", code, got, stderr)
	}
	if body, err := os.ReadFile(outside); err != nil || string(body) != "preserve me" {
		t.Fatalf("symlink target changed: %q, %v", body, err)
	}
}

func TestBillSyncCutoffAndDirectoryArgumentsAreValidatedBeforeSession(t *testing.T) {
	for _, args := range [][]string{
		{"--json-envelope", "bills", "sync"},
		{"--json-envelope", "bills", "sync", "--directory", "/no/such/directory"},
		{"--json-envelope", "bills", "sync", "--directory", "unused", "--since", "not-a-date"},
	} {
		code, stdout, stderr := executeEnvelopeForTest(t, Dependencies{Store: securestore.NewMemoryStore()}, "", args...)
		got := decodeEnvelopeForTest(t, stdout)
		if code != 2 || got["error"].(map[string]any)["code"] != "invalid_argument" || stderr != "" {
			t.Fatalf("invalid args %#v: code=%d envelope=%#v stderr=%q", args, code, got, stderr)
		}
	}
}

func TestBillSyncUsesStableCommandAndUnsupportedCodeIsAllowlisted(t *testing.T) {
	if !errors.Is(unsupportedPlatformError(), ErrUnsupportedPlatform) {
		t.Fatal("unsupported-platform error does not preserve its typed sentinel")
	}
	code, stdout, stderr := executeEnvelopeForTest(t, Dependencies{ConfigPath: filepath.Join(t.TempDir(), "missing.json")}, "", "capabilities", "--json-envelope")
	got := decodeEnvelopeForTest(t, stdout)
	data := got["data"].(map[string]any)
	commands := data["commands"].([]any)
	var found bool
	for _, value := range commands {
		if value == "bills.sync" {
			found = true
		}
	}
	codes := data["error_codes"].([]any)
	var unsupported bool
	for _, value := range codes {
		if value == "unsupported_platform" {
			unsupported = true
		}
	}
	if code != 0 || stderr != "" || !found || !unsupported {
		t.Fatalf("capabilities missing sync contract: code=%d data=%#v stderr=%q", code, data, stderr)
	}
}

func TestBillSyncSystemicFailureClassificationDoesNotLeakCause(t *testing.T) {
	const canary = "https://provider.invalid/bill?sig=secret-sync-canary"
	id := publicBillID("2026-08-01")
	remaining := publicBillID("2026-08-02")
	directory := t.TempDir()
	service := &syncBillsFixture{items: []coned.Bill{{ID: id, Date: "2026-08-01"}, {ID: remaining, Date: "2026-08-02"}}, errByID: map[string]error{id: errors.New(canary)}}
	code, stdout, stderr := executeEnvelopeForTest(t, syncTestDependencies(t, service), "", "--json-envelope", "bills", "sync", "--since", "2026-07-01", "--directory", directory)
	got := decodeEnvelopeForTest(t, stdout)
	if code != 1 || got["error"].(map[string]any)["code"] != "internal_error" || strings.Contains(stdout+stderr, canary) || stderr != "" {
		t.Fatalf("unknown service failure was unsafe or misclassified: code=%d envelope=%#v stderr=%q", code, got, stderr)
	}
	data := syncData(t, got)
	results := data["results"].([]any)
	if len(service.downloads) != 1 || data["not_attempted"] != float64(1) || results[0].(map[string]any)["error_code"] != "internal_error" || results[1].(map[string]any)["status"] != "not_attempted" {
		t.Fatalf("unknown systemic failure did not stop sync: manifest=%#v downloads=%#v", data, service.downloads)
	}
}

func TestBillSyncTypedSessionAndContextErrorsRemainStable(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		code string
	}{
		{name: "cancel", err: context.Canceled, code: "canceled"},
		{name: "deadline", err: context.DeadlineExceeded, code: "timeout"},
		{name: "session", err: coned.ErrSessionExpired, code: "session_expired"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id := publicBillID("2026-09-01")
			service := &syncBillsFixture{items: []coned.Bill{{ID: id, Date: "2026-09-01"}}, errByID: map[string]error{id: tc.err}}
			code, stdout, stderr := executeEnvelopeForTest(t, syncTestDependencies(t, service), "", "--json-envelope", "bills", "sync", "--directory", t.TempDir())
			got := decodeEnvelopeForTest(t, stdout)
			if code != 1 || got["error"].(map[string]any)["code"] != tc.code || stderr != "" {
				t.Fatalf("code=%d envelope=%#v stderr=%q", code, got, stderr)
			}
		})
	}
}

func TestBillSyncStrictListingSelectionErrorRemainsTyped(t *testing.T) {
	service := &syncBillsFixture{listErr: coned.ErrSelectionRequired}
	code, stdout, stderr := executeEnvelopeForTest(t, syncTestDependencies(t, service), "", "--json-envelope", "bills", "sync", "--directory", t.TempDir())
	got := decodeEnvelopeForTest(t, stdout)
	if code != 1 || got["error"].(map[string]any)["code"] != "selection_required" || stderr != "" {
		t.Fatalf("strict listing selection failure was misclassified: code=%d envelope=%#v stderr=%q", code, got, stderr)
	}
}

func TestBillSyncManifestCanBeMarshaled(t *testing.T) {
	manifest := map[string]any{"since": nil, "directory": t.TempDir(), "results": []any{}, "downloaded": 0, "existing": 0, "failed": 0, "not_attempted": 0}
	if _, err := json.Marshal(manifest); err != nil {
		t.Fatal(err)
	}
}
