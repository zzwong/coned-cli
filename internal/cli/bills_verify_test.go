//go:build darwin || linux

package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/zzwong/coned-cli/internal/auth"
	"github.com/zzwong/coned-cli/internal/coned"
	"golang.org/x/sys/unix"
)

func verifyFixture(t *testing.T, local, remote string) (string, string, *syncBillsFixture) {
	t.Helper()
	directory := t.TempDir()
	id := publicBillID("2026-02-15")
	path := filepath.Join(directory, "coned-bill-"+id+".pdf")
	if err := os.WriteFile(path, []byte(local), 0o600); err != nil {
		t.Fatal(err)
	}
	service := &syncBillsFixture{items: []coned.Bill{{ID: id, Date: "2026-02-15"}}, pdfs: map[string]string{id: remote}}
	return directory, path, service
}

// Snapshots intentionally exclude atime, which reading a retained file may change.
type verifyTreeEntry struct {
	Bytes string
	Info  billSyncSnapshot
}

func verifyTree(t *testing.T, directory string) map[string]verifyTreeEntry {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	result := make(map[string]verifyTreeEntry)
	for _, entry := range entries {
		path := filepath.Join(directory, entry.Name())
		var stat unix.Stat_t
		if err := unix.Lstat(path, &stat); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		result[entry.Name()] = verifyTreeEntry{Bytes: string(data), Info: snapshotFromUnixStat(&stat)}
	}
	return result
}

func runVerifyEnvelope(t *testing.T, directory string, service *syncBillsFixture, extra ...string) (int, map[string]any) {
	t.Helper()
	args := []string{"--json-envelope", "bills", "verify", "--directory", directory}
	args = append(args, extra...)
	code, stdout, stderr := executeEnvelopeForTest(t, syncTestDependencies(t, service), "", args...)
	if stderr != "" {
		t.Fatalf("stderr=%q", stderr)
	}
	return code, decodeEnvelopeForTest(t, stdout)
}

func TestBillVerifyChangedAndIdenticalPreserveLocalTree(t *testing.T) {
	for _, remote := range []string{"%PDF-retained\n", "%PDF-different rendering\n"} {
		t.Run(remote, func(t *testing.T) {
			const local = "%PDF-retained\n"
			directory, _, service := verifyFixture(t, local, remote)
			before := verifyTree(t, directory)
			code, envelope := runVerifyEnvelope(t, directory, service)
			data := syncData(t, envelope)
			changed := local != remote
			status := "unchanged"
			if changed {
				status = "content_changed"
			}
			results := data["results"].([]any)
			result := results[0].(map[string]any)
			localHash, remoteHash := sha256.Sum256([]byte(local)), sha256.Sum256([]byte(remote))
			if code != 0 || envelope["ok"] != true || envelope["command"] != "bills.verify" || data["report_version"] != float64(1) || data["content_changed"] != changed || result["status"] != status || result["local_sha256"] != hex.EncodeToString(localHash[:]) || result["provider_sha256"] != hex.EncodeToString(remoteHash[:]) || result["local_bytes"] != float64(len(local)) || result["provider_bytes"] != float64(len(remote)) {
				t.Fatalf("code=%d envelope=%#v", code, envelope)
			}
			if !reflect.DeepEqual(before, verifyTree(t, directory)) || len(service.downloads) != 1 || service.legacyCalls != 0 {
				t.Fatal("local content/identity/metadata changed or strict service was not used")
			}
		})
	}
}

func TestBillVerifyMissingLocalNeverDownloads(t *testing.T) {
	directory, path, service := verifyFixture(t, "%PDF-retained", "%PDF-new")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	code, envelope := runVerifyEnvelope(t, directory, service)
	data := syncData(t, envelope)
	result := data["results"].([]any)[0].(map[string]any)
	if code != 0 || data["missing_local"] != float64(1) || result["status"] != "missing_local" || len(service.downloads) != 0 || len(verifyTree(t, directory)) != 0 {
		t.Fatalf("code=%d envelope=%#v downloads=%v", code, envelope, service.downloads)
	}
	if _, ok := result["provider_sha256"]; ok {
		t.Fatal("missing file acquired a digest")
	}
}

func TestBillVerifyRejectsLocalChangesAcrossDownload(t *testing.T) {
	for _, change := range []string{"replace-identical", "in-place", "unlink", "symlink", "mode", "directory", "parent"} {
		t.Run(change, func(t *testing.T) {
			directory, path, service := verifyFixture(t, "%PDF-retained", "%PDF-retained")
			service.onDownload = func(string) {
				var err error
				switch change {
				case "replace-identical":
					err = os.Rename(path, path+".old")
					if err == nil {
						err = os.WriteFile(path, []byte("%PDF-retained"), 0o600)
					}
				case "in-place":
					err = os.WriteFile(path, []byte("%PDF-mutated!"), 0o600)
				case "unlink":
					err = os.Remove(path)
				case "symlink":
					err = os.Rename(path, path+".old")
					if err == nil {
						err = os.Symlink(path+".old", path)
					}
				case "mode":
					err = os.Chmod(path, 0o400)
				case "directory":
					err = os.Rename(directory, directory+".old")
					if err == nil {
						err = os.Mkdir(directory, 0o700)
					}
					t.Cleanup(func() { _ = os.RemoveAll(directory + ".old") })
				case "parent":
					// Replace the input component with a symlink to the retained directory.
					err = os.Rename(directory, directory+".old")
					if err == nil {
						err = os.Symlink(directory+".old", directory)
					}
					t.Cleanup(func() { _ = os.RemoveAll(directory + ".old") })
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			code, envelope := runVerifyEnvelope(t, directory, service)
			result := syncData(t, envelope)["results"].([]any)[0].(map[string]any)
			expectedCode := "output_conflict"
			if change == "directory" || change == "parent" {
				expectedCode = "output_failed"
			}
			if code != 1 || result["status"] != "failed" || result["error_code"] != expectedCode {
				t.Fatalf("code=%d envelope=%#v", code, envelope)
			}
			if _, ok := result["provider_sha256"]; ok {
				t.Fatal("race acquired a successful digest")
			}
		})
	}
}

func TestBillVerifyUnsafeLocalNeverDownloads(t *testing.T) {
	for _, kind := range []string{"invalid", "oversized", "symlink", "directory", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			directory, path, service := verifyFixture(t, "%PDF-retained", "%PDF-new")
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			var err error
			switch kind {
			case "invalid":
				err = os.WriteFile(path, []byte("<html>"), 0o600)
			case "oversized":
				var file *os.File
				file, err = os.Create(path)
				if err == nil {
					err = file.Truncate(billSyncMaxBytes + 1)
					_ = file.Close()
				}
			case "symlink":
				err = os.Symlink("missing-target", path)
			case "directory":
				err = os.Mkdir(path, 0o700)
			case "fifo":
				err = unix.Mkfifo(path, 0o600)
			}
			if err != nil {
				t.Fatal(err)
			}
			code, envelope := runVerifyEnvelope(t, directory, service)
			result := syncData(t, envelope)["results"].([]any)[0].(map[string]any)
			if code != 1 || result["error_code"] != "output_conflict" || len(service.downloads) != 0 {
				t.Fatalf("code=%d envelope=%#v downloads=%v", code, envelope, service.downloads)
			}
		})
	}
}

func TestBillVerifyPartialFailureAndSystemicStop(t *testing.T) {
	directory, _, service := verifyFixture(t, "%PDF-old", "%PDF-new")
	for _, date := range []string{"2026-03-15", "2026-04-15"} {
		id := publicBillID(date)
		service.items = append(service.items, coned.Bill{ID: id, Date: date})
		if err := os.WriteFile(filepath.Join(directory, "coned-bill-"+id+".pdf"), []byte("%PDF-local"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	service.errByID = map[string]error{publicBillID("2026-03-15"): coned.ErrSessionExpired}
	before := verifyTree(t, directory)
	code, envelope := runVerifyEnvelope(t, directory, service, "--since", "2026-01-01")
	data := syncData(t, envelope)
	if code != 1 || envelope["ok"] != false || data["content_changed"] != true || data["changed"] != float64(1) || data["failed"] != float64(1) || data["not_attempted"] != float64(1) || len(service.downloads) != 2 || !reflect.DeepEqual(before, verifyTree(t, directory)) {
		t.Fatalf("code=%d envelope=%#v", code, envelope)
	}
}

func TestBillVerifyInvalidRemoteAndPrivateErrorsDoNotWrite(t *testing.T) {
	for _, kind := range []string{"invalid", "short", "private-error"} {
		t.Run(kind, func(t *testing.T) {
			directory, _, service := verifyFixture(t, "%PDF-local", "<html>private-body</html>")
			if kind == "short" {
				service.pdfs[service.items[0].ID] = "%PDF"
			}
			if kind == "private-error" {
				service.errByID = map[string]error{service.items[0].ID: errors.New("SECRET https://private.example/bill?token=123")}
			}
			before := verifyTree(t, directory)
			code, envelope := runVerifyEnvelope(t, directory, service)
			result := syncData(t, envelope)["results"].([]any)[0].(map[string]any)
			if code != 1 || result["status"] != "failed" || !reflect.DeepEqual(before, verifyTree(t, directory)) {
				t.Fatalf("%d %#v", code, envelope)
			}
			if _, ok := result["provider_sha256"]; ok {
				t.Fatal("failed remote has digest")
			}
		})
	}
}

func TestBillVerifyCancellationAfterFinalWrite(t *testing.T) {
	directory, _, service := verifyFixture(t, "%PDF-local", "%PDF-remote")
	filesystem, err := openBillSyncFS(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = filesystem.close() }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	service.afterWrite = func(string, io.Writer) { cancel() }
	result, err := processVerifyBill(ctx, filesystem, service, auth.Session{}, service.items[0])
	if !errors.Is(err, context.Canceled) || result.Status != "failed" || result.ProviderSHA256 != "" || result.LocalSHA256 != "" {
		t.Fatalf("%#v %v", result, err)
	}
}

func TestBillVerifyAmbiguousHistoryAndInvalidFlags(t *testing.T) {
	directory, _, service := verifyFixture(t, "%PDF-local", "%PDF-remote")
	service.items = append(service.items, service.items[0])
	code, _ := runVerifyEnvelope(t, directory, service)
	if code != 1 || len(service.downloads) != 0 {
		t.Fatal("ambiguous history was downloaded")
	}
	for _, extra := range [][]string{{"--since", "bad-date"}, {"--force"}} {
		code, _ := runVerifyEnvelope(t, directory, service, extra...)
		if code != 2 {
			t.Fatalf("invalid flags exit=%d", code)
		}
	}
}

func TestBillVerifyDemoDoesNotAccessDirectoryOrService(t *testing.T) {
	service := &syncBillsFixture{listErr: errors.New("must not call provider")}
	code, stdout, stderr := executeEnvelopeForTest(t, syncTestDependencies(t, service), "", "--json-envelope", "--demo", "bills", "verify", "--directory", "/does-not-exist", "--since", "2026-01-01")
	envelope := decodeEnvelopeForTest(t, stdout)
	data := syncData(t, envelope)
	if code != 0 || stderr != "" || data["directory"] != "demo:memory" || data["unchanged"] != float64(1) || data["changed"] != float64(1) || service.legacyCalls != 0 || len(service.downloads) != 0 {
		t.Fatalf("%d %#v %s", code, envelope, stderr)
	}
	if strings.Contains(stdout, "must not call provider") {
		t.Fatal("private failure leaked")
	}
}

func TestBillVerifyDirectoryRaceStopsRemainingRows(t *testing.T) {
	directory, _, service := verifyFixture(t, "%PDF-local", "%PDF-remote")
	id := publicBillID("2026-03-15")
	service.items = append(service.items, coned.Bill{ID: id, Date: "2026-03-15"})
	service.onDownload = func(string) {
		if err := os.Rename(directory, directory+".old"); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(directory + ".old") })
	}
	code, envelope := runVerifyEnvelope(t, directory, service, "--since", "2026-01-01")
	data := syncData(t, envelope)
	if code != 1 || data["failed"] != float64(1) || data["not_attempted"] != float64(1) || len(service.downloads) != 1 {
		t.Fatalf("%d %#v", code, envelope)
	}
}

func TestBillVerifyHumanInvalidArgumentsExitTwo(t *testing.T) {
	for _, args := range [][]string{
		{"bills", "verify"},
		{"bills", "verify", "--directory", "irrelevant", "--since", "bad-date"},
		{"bills", "verify", "--force"},
		{"bills", "verify", "extra"},
	} {
		var stdout, stderr strings.Builder
		code := ExecuteCLI(args, strings.NewReader(""), &stdout, &stderr, syncTestDependencies(t, &syncBillsFixture{}))
		if code != 2 {
			t.Fatalf("args=%v exit=%d stderr=%s", args, code, stderr.String())
		}
	}
}

func TestBillVerifyLatestAndExclusiveCutoff(t *testing.T) {
	for _, cutoff := range []string{"", "2026-01-15", "2026-04-15"} {
		t.Run(cutoff, func(t *testing.T) {
			directory := t.TempDir()
			service := &syncBillsFixture{}
			for _, date := range []string{"2026-03-15", "2026-01-15", "2026-02-15"} {
				id := publicBillID(date)
				service.items = append(service.items, coned.Bill{ID: id, Date: date})
				if err := os.WriteFile(filepath.Join(directory, "coned-bill-"+id+".pdf"), []byte("%PDF-synthetic-"+id), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			var extra []string
			if cutoff != "" {
				extra = []string{"--since", cutoff}
			}
			code, envelope := runVerifyEnvelope(t, directory, service, extra...)
			results := syncData(t, envelope)["results"].([]any)
			want := []string{"2026-03-15"}
			if cutoff == "2026-01-15" {
				want = []string{"2026-02-15", "2026-03-15"}
			}
			if cutoff == "2026-04-15" {
				want = nil
			}
			if code != 0 || len(results) != len(want) || len(service.downloads) != len(want) {
				t.Fatalf("%d %#v", code, envelope)
			}
			for i, date := range want {
				if results[i].(map[string]any)["date"] != date {
					t.Fatalf("order=%#v", results)
				}
			}
		})
	}
}

func TestBillVerifyStrictDownloadScopeErrorStops(t *testing.T) {
	directory, _, service := verifyFixture(t, "%PDF-local", "%PDF-new")
	id := publicBillID("2026-03-15")
	service.items = append(service.items, coned.Bill{ID: id, Date: "2026-03-15"})
	service.errByID = map[string]error{service.items[0].ID: coned.ErrSelectionRequired}
	code, envelope := runVerifyEnvelope(t, directory, service, "--since", "2026-01-01")
	data := syncData(t, envelope)
	if code != 1 || data["failed"] != float64(1) || data["not_attempted"] != float64(1) || len(service.downloads) != 1 {
		t.Fatalf("%d %#v", code, envelope)
	}
}

func TestBillVerifyTimeoutRetainsPartialReport(t *testing.T) {
	directory, _, service := verifyFixture(t, "%PDF-local", "%PDF-new")
	service.waitForContext = true
	before := verifyTree(t, directory)
	code, envelope := runVerifyEnvelope(t, directory, service, "--timeout", "100ms")
	data := syncData(t, envelope)
	if code != 1 || data["failed"] != float64(1) || !reflect.DeepEqual(before, verifyTree(t, directory)) {
		t.Fatalf("%d %#v", code, envelope)
	}
	result := data["results"].([]any)[0].(map[string]any)
	if result["error_code"] != "timeout" {
		t.Fatalf("%#v", result)
	}
	if _, ok := result["provider_sha256"]; ok {
		t.Fatal("partial timeout digest retained")
	}
}

func TestBillVerifyRetainedDescriptorRemainsOpenUntilClosed(t *testing.T) {
	directory, _, _ := verifyFixture(t, "%PDF-local", "%PDF-new")
	filesystem, err := openBillSyncFS(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = filesystem.close() }()
	retained, exists, err := filesystem.retainForVerify("coned-bill-" + publicBillID("2026-02-15") + ".pdf")
	if err != nil || !exists {
		t.Fatalf("%v %v", exists, err)
	}
	if err := retained.recheck(filesystem); err != nil {
		t.Fatal(err)
	}
	if _, err := retained.file.Stat(); err != nil {
		t.Fatal("descriptor was prematurely closed")
	}
	if err := retained.file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := retained.file.Stat(); err == nil {
		t.Fatal("descriptor remained open")
	}
}

func TestBillVerifyRejectsForeignOwner(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("synthetic foreign-owner fixture requires root")
	}
	directory, path, service := verifyFixture(t, "%PDF-local", "%PDF-new")
	if err := os.Chown(path, 1, -1); err != nil {
		t.Fatal(err)
	}
	code, envelope := runVerifyEnvelope(t, directory, service)
	result := syncData(t, envelope)["results"].([]any)[0].(map[string]any)
	if code != 1 || result["error_code"] != "output_conflict" || len(service.downloads) != 0 {
		t.Fatalf("%d %#v", code, envelope)
	}
}

func TestBillVerifyCapabilitiesAndPrivateErrors(t *testing.T) {
	if !strings.Contains(strings.Join(availableEnvelopeCommandIDs(), ","), "bills.verify") {
		t.Fatal("missing capability")
	}
	directory, _, service := verifyFixture(t, "%PDF-local", "%PDF-new")
	const secret = "SECRET https://private.example/?token=123"
	service.errByID = map[string]error{service.items[0].ID: errors.New(secret)}
	code, stdout, stderr := executeEnvelopeForTest(t, syncTestDependencies(t, service), "", "--json-envelope", "bills", "verify", "--directory", directory)
	if code != 1 || strings.Contains(stdout+stderr, "SECRET") || strings.Contains(stdout+stderr, "private.example") || strings.Contains(stdout+stderr, "token=123") {
		t.Fatalf("private error not sanitized: %d", code)
	}
}

func TestBillVerifyEmptyAndCanceledListing(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		directory := t.TempDir()
		service := &syncBillsFixture{listWaitContext: canceled}
		code, envelope := runVerifyEnvelope(t, directory, service, "--timeout", "100ms")
		wantCode := 0
		if canceled {
			wantCode = 1
		}
		data := syncData(t, envelope)
		if code != wantCode || len(data["results"].([]any)) != 0 || len(service.downloads) != 0 || len(verifyTree(t, directory)) != 0 {
			t.Fatalf("canceled=%v code=%d %#v", canceled, code, envelope)
		}
	}
}

func TestBillVerifyAncestorSymlinkRetargetStopsRemainingRows(t *testing.T) {
	root := t.TempDir()
	for _, parent := range []string{"left", "right"} {
		if err := os.MkdirAll(filepath.Join(root, parent, "bills"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	alias := filepath.Join(root, "selected")
	if err := os.Symlink(filepath.Join(root, "left"), alias); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(alias, "bills")
	id := publicBillID("2026-02-15")
	path := filepath.Join(root, "left", "bills", "coned-bill-"+id+".pdf")
	if err := os.WriteFile(path, []byte("%PDF-local"), 0o600); err != nil {
		t.Fatal(err)
	}
	service := &syncBillsFixture{items: []coned.Bill{{ID: id, Date: "2026-02-15"}, {ID: publicBillID("2026-03-15"), Date: "2026-03-15"}}}
	service.onDownload = func(string) {
		if err := os.Remove(alias); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(root, "right"), alias); err != nil {
			t.Fatal(err)
		}
	}
	before := verifyTree(t, filepath.Join(root, "left", "bills"))
	code, envelope := runVerifyEnvelope(t, directory, service, "--since", "2026-01-01")
	data := syncData(t, envelope)
	if code != 1 || data["failed"] != float64(1) || data["not_attempted"] != float64(1) || len(service.downloads) != 1 || !reflect.DeepEqual(before, verifyTree(t, filepath.Join(root, "left", "bills"))) || len(verifyTree(t, filepath.Join(root, "right", "bills"))) != 0 {
		t.Fatalf("%d %#v", code, envelope)
	}
}
