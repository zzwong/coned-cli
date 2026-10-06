package cli

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zzwong/coned-cli/internal/auth"
	"github.com/zzwong/coned-cli/internal/coned"
)

type fakeGreenButton struct {
	*fakeOpower
	t       *testing.T
	dir     string
	options coned.GreenButtonOptions
	err     error
}

func (f *fakeGreenButton) GreenButtonInspect(context.Context, auth.Session) (coned.GreenButtonMetadata, error) {
	return coned.GreenButtonMetadata{CustomerClass: "RESIDENTIAL", TimeZone: "America/New_York", BillIntervals: []string{"2026-01"}, AMIIntervals: []string{"2026-01", "2026-02"}}, f.err
}

func (f *fakeGreenButton) GreenButtonExport(_ context.Context, _ auth.Session, options coned.GreenButtonOptions) (string, error) {
	f.options = options
	if f.err != nil {
		return "", f.err
	}
	path := filepath.Join(f.dir, "spool-"+options.Format+".zip")
	file, err := os.Create(path)
	if err != nil {
		f.t.Fatal(err)
	}
	archive := zip.NewWriter(file)
	name, body := "usage.csv", "TYPE,DATE,USAGE\nElectric usage,2026-01-01,3\n"
	if options.Format == "xml" {
		name, body = "usage.xml", "<usage>synthetic</usage>"
	}
	member, err := archive.Create(name)
	if err != nil {
		f.t.Fatal(err)
	}
	if _, err := member.Write([]byte(body)); err != nil {
		f.t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		f.t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		f.t.Fatal(err)
	}
	return path, nil
}

func greenButtonDeps(t *testing.T) (*fakeGreenButton, Dependencies) {
	fake := &fakeGreenButton{fakeOpower: &fakeOpower{}, t: t, dir: t.TempDir()}
	deps := opowerDeps(t, fake.fakeOpower)
	deps.Opower = fake
	return fake, deps
}

func TestGreenButtonInspectExportAndDownload(t *testing.T) {
	fake, deps := greenButtonDeps(t)
	output, err := runWithDependencies(t, deps, "", "green-button inspect")
	if err != nil || !strings.Contains(output, "bill intervals: 1") {
		t.Fatalf("output=%q err=%v", output, err)
	}
	output, err = runWithDependencies(t, deps, "", "--json green-button inspect")
	if err != nil || !strings.Contains(output, `"customer_class":"RESIDENTIAL"`) {
		t.Fatalf("output=%q err=%v", output, err)
	}
	output, err = runWithDependencies(t, deps, "", "green-button export --format json --from 2026-01-01 --to 2026-01-31")
	if err != nil || fake.options.Format != "csv" || !strings.Contains(output, `"USAGE":"3"`) {
		t.Fatalf("output=%q options=%#v err=%v", output, fake.options, err)
	}
	output, err = runWithDependencies(t, deps, "", "green-button export --format xml")
	if err != nil || output != "<usage>synthetic</usage>" {
		t.Fatalf("output=%q err=%v", output, err)
	}
	destination := filepath.Join(t.TempDir(), "usage.zip")
	output, err = runWithDependencies(t, deps, "", "green-button download --format csv --output "+destination)
	if err != nil || strings.TrimSpace(output) != destination {
		t.Fatalf("output=%q err=%v", output, err)
	}
	if info, err := os.Stat(destination); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("stat=%v err=%v", info, err)
	}
}

func TestGreenButtonValidationAndSafeErrors(t *testing.T) {
	_, deps := greenButtonDeps(t)
	for _, command := range []string{
		"green-button export --format zip",
		"green-button download --format json",
		"green-button export --from 2026-01-01",
		"green-button export --from bad --to 2026-01-01",
		"green-button export --from 2026-02-01 --to 2026-01-01",
	} {
		if _, err := runWithDependencies(t, deps, "", command); !errors.Is(err, coned.ErrProtocolChanged) {
			t.Fatalf("%q: %v", command, err)
		}
	}
	fake, deps := greenButtonDeps(t)
	fake.err = fmt.Errorf("private detail: %w", coned.ErrGreenButtonUnavailable)
	if _, err := runWithDependencies(t, deps, "", "green-button inspect"); !errors.Is(err, coned.ErrGreenButtonUnavailable) {
		t.Fatalf("error=%v", err)
	}
}
