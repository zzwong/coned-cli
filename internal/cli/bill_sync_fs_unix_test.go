//go:build darwin || linux

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestBillSyncExistingFIFOIsRejectedWithoutBlocking(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "coned-bill-fifo.pdf")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Skipf("FIFO creation unavailable: %v", err)
	}
	filesystem, err := openBillSyncFS(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = filesystem.close() }()
	_, exists, err := filesystem.existing(filepath.Base(path))
	if !exists || !errors.Is(err, ErrOutputConflict) {
		t.Fatalf("FIFO existing() = exists %v, err %v", exists, err)
	}
}

func TestBillSyncExistingDirectoryIsConflict(t *testing.T) {
	directory := t.TempDir()
	name := "bill.pdf"
	if err := os.Mkdir(filepath.Join(directory, name), 0o700); err != nil {
		t.Fatal(err)
	}
	filesystem, err := openBillSyncFS(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = filesystem.close() }()
	_, exists, err := filesystem.existing(name)
	if !exists || !errors.Is(err, ErrOutputConflict) {
		t.Fatalf("directory existing() = exists %v, err %v", exists, err)
	}
}

func TestBillSyncExistingWrongOwnerIsPreservedConflict(t *testing.T) {
	directory := t.TempDir()
	name := "bill.pdf"
	path := filepath.Join(directory, name)
	const canary = "%PDF-wrong-owner"
	if err := os.WriteFile(path, []byte(canary), 0o600); err != nil {
		t.Fatal(err)
	}
	otherUID := os.Getuid() + 1
	if err := os.Chown(path, otherUID, -1); err != nil {
		t.Skipf("changing synthetic fixture owner is unavailable: %v", err)
	}
	filesystem, err := openBillSyncFS(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = filesystem.close() }()
	_, exists, err := filesystem.existing(name)
	if !exists || !errors.Is(err, ErrOutputConflict) {
		t.Fatalf("wrong-owner existing() = exists %v, err %v", exists, err)
	}
	if body, err := os.ReadFile(path); err != nil || string(body) != canary {
		t.Fatalf("wrong-owner file changed: %q err=%v", body, err)
	}
}

func TestBillSyncPreLinkSnapshotRejectsMutationAfterHash(t *testing.T) {
	directory := t.TempDir()
	filesystem, err := openBillSyncFS(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = filesystem.close() }()
	file, temp, err := filesystem.createTemp()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	if _, err := file.WriteString("%PDF-original"); err != nil {
		t.Fatal(err)
	}
	verified, err := inspectBillPDF(file)
	if err != nil {
		t.Fatal(err)
	}
	filesystem.beforeLink = func() {
		if _, err := file.WriteAt([]byte("%PDF-modified"), 0); err != nil {
			t.Errorf("mutate temp after hash: %v", err)
		}
	}
	err = filesystem.publish(temp, file, "bill.pdf", &verified)
	if !errors.Is(err, ErrOutputFailed) {
		t.Fatalf("publish after same-size mutation = %v", err)
	}
	if err := filesystem.removeOwned(temp, file); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		t.Fatalf("mutation left a file behind: entries=%#v err=%v", entries, err)
	}
}

func TestBillSyncRollbackLeavesReplacementDestinationUntouched(t *testing.T) {
	directory := t.TempDir()
	filesystem, err := openBillSyncFS(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = filesystem.close() }()
	file, temp, err := filesystem.createTemp()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	if _, err := file.WriteString("%PDF-owned-content"); err != nil {
		t.Fatal(err)
	}
	verified, err := inspectBillPDF(file)
	if err != nil {
		t.Fatal(err)
	}
	destination := "bill.pdf"
	const canary = "replacement must survive rollback"
	filesystem.afterLink = func() {
		path := filepath.Join(directory, destination)
		if err := os.Remove(path); err != nil {
			t.Errorf("replace published destination: %v", err)
			return
		}
		if err := os.WriteFile(path, []byte(canary), 0o600); err != nil {
			t.Errorf("write replacement destination: %v", err)
		}
	}
	err = filesystem.publish(temp, file, destination, &verified)
	if !errors.Is(err, ErrOutputFailed) {
		t.Fatalf("publish with replaced destination = %v", err)
	}
	if err := filesystem.removeOwned(temp, file); err != nil {
		t.Fatal(err)
	}
	if body, err := os.ReadFile(filepath.Join(directory, destination)); err != nil || string(body) != canary {
		t.Fatalf("rollback removed or changed replacement: body=%q err=%v", body, err)
	}
}

func TestBillSyncTempCleanupLeavesReplacedNameUntouched(t *testing.T) {
	directory := t.TempDir()
	filesystem, err := openBillSyncFS(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = filesystem.close() }()
	file, temp, err := filesystem.createTemp()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	if _, err := file.WriteString("%PDF-owned-content"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, temp)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	const canary = "replacement temporary name"
	if err := os.WriteFile(path, []byte(canary), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := filesystem.removeOwned(temp, file); !errors.Is(err, ErrOutputFailed) {
		t.Fatalf("remove replaced temp = %v, want output_failed", err)
	}
	if body, err := os.ReadFile(path); err != nil || string(body) != canary {
		t.Fatalf("replacement temp was removed: body=%q err=%v", body, err)
	}
}
