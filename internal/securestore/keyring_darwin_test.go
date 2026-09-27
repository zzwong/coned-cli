//go:build darwin && cgo

package securestore

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

type fakeDarwinSecItemOps struct {
	copyStatus   int32
	copyResult   darwinSecItemResult
	updateStatus []int32
	addStatus    []int32
	deleteStatus int32

	copyService, copyAccount     string
	updateService, updateAccount string
	addService, addAccount       string
	deleteService, deleteAccount string
	updateValues                 [][]byte
	addValues                    [][]byte
}

func (f *fakeDarwinSecItemOps) copyMatching(service, account string) (darwinSecItemResult, int32) {
	f.copyService, f.copyAccount = service, account
	return f.copyResult, f.copyStatus
}

func (f *fakeDarwinSecItemOps) update(service, account string, value []byte) int32 {
	f.updateService, f.updateAccount = service, account
	f.updateValues = append(f.updateValues, append([]byte(nil), value...))
	return popDarwinStatus(&f.updateStatus)
}

func (f *fakeDarwinSecItemOps) add(service, account string, value []byte) int32 {
	f.addService, f.addAccount = service, account
	f.addValues = append(f.addValues, append([]byte(nil), value...))
	return popDarwinStatus(&f.addStatus)
}

func (f *fakeDarwinSecItemOps) delete(service, account string) int32 {
	f.deleteService, f.deleteAccount = service, account
	return f.deleteStatus
}

func popDarwinStatus(statuses *[]int32) int32 {
	if len(*statuses) == 0 {
		return darwinSecItemSuccess
	}
	status := (*statuses)[0]
	*statuses = (*statuses)[1:]
	return status
}

func TestDarwinKeyringDriverGetCopiesResultAndReleasesIt(t *testing.T) {
	releases := 0
	fake := &fakeDarwinSecItemOps{
		copyStatus: darwinSecItemSuccess,
		copyResult: darwinSecItemResult{
			data:    []byte{0, 1, 0xff},
			release: func() { releases++ },
		},
	}
	driver := darwinKeyringDriver{ops: fake}

	got, err := driver.Get("coned-cli", "account")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte{0, 1, 0xff}) {
		t.Fatalf("Get() = %x, want 0001ff", got)
	}
	if releases != 1 {
		t.Fatalf("returned data releases = %d, want 1", releases)
	}
	if fake.copyService != "coned-cli" || fake.copyAccount != "account" {
		t.Fatalf("copy identifiers = %q/%q, want coned-cli/account", fake.copyService, fake.copyAccount)
	}
}

func TestDarwinKeyringDriverGetDecodesCompatibilityValue(t *testing.T) {
	fake := &fakeDarwinSecItemOps{
		copyStatus: darwinSecItemSuccess,
		copyResult: darwinSecItemResult{data: []byte("go-keyring-base64:AAH/")},
	}
	driver := darwinKeyringDriver{ops: fake}

	got, err := driver.Get("service", "account")
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte{0, 1, 0xff}; !bytes.Equal(got, want) {
		t.Fatalf("Get() = %x, want %x", got, want)
	}
}

func TestDarwinKeyringDriverGetRejectsMalformedCompatibilityValue(t *testing.T) {
	const stored = "go-keyring-base64:not-valid-secret"
	fake := &fakeDarwinSecItemOps{
		copyStatus: darwinSecItemSuccess,
		copyResult: darwinSecItemResult{data: []byte(stored)},
	}
	driver := darwinKeyringDriver{ops: fake}

	_, err := driver.Get("service", "account")
	if err == nil || strings.Contains(err.Error(), stored) {
		t.Fatalf("Get() error = %v, want sanitized malformed-value error", err)
	}
}

func TestDarwinKeyringDriverGetMapsNotFound(t *testing.T) {
	fake := &fakeDarwinSecItemOps{copyStatus: darwinSecItemNotFound}
	driver := darwinKeyringDriver{ops: fake}

	if _, err := driver.Get("coned-cli", "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get() error = %v, want ErrNotFound", err)
	}
}

func TestDarwinKeyringDriverGetSanitizesOSStatusFailure(t *testing.T) {
	fake := &fakeDarwinSecItemOps{copyStatus: -34018}
	driver := darwinKeyringDriver{ops: fake}

	_, err := driver.Get("coned-cli", "synthetic-secret-account")
	if err == nil || strings.Contains(err.Error(), "synthetic-secret-account") {
		t.Fatalf("Get() error = %v, want sanitized failure", err)
	}
}

func TestDarwinKeyringDriverReleasesCopyResultOnEveryStatus(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int32
	}{
		{name: "success", status: darwinSecItemSuccess},
		{name: "not found", status: darwinSecItemNotFound},
		{name: "failure", status: -34018},
	} {
		t.Run(test.name, func(t *testing.T) {
			releases := 0
			fake := &fakeDarwinSecItemOps{
				copyStatus: test.status,
				copyResult: darwinSecItemResult{release: func() { releases++ }},
			}
			_, _ = (darwinKeyringDriver{ops: fake}).Get("service", "account")
			if releases != 1 {
				t.Fatalf("returned data releases = %d, want 1", releases)
			}
		})
	}
}

func TestDarwinKeyringDriverSetUpdatesExistingItem(t *testing.T) {
	fake := &fakeDarwinSecItemOps{updateStatus: []int32{darwinSecItemSuccess}}
	driver := darwinKeyringDriver{ops: fake}

	if err := driver.Set("coned-cli", "account", []byte("synthetic-value")); err != nil {
		t.Fatal(err)
	}
	if len(fake.updateValues) != 1 || !bytes.Equal(fake.updateValues[0], encodeKeyringValue([]byte("synthetic-value"))) {
		t.Fatalf("update values = %q, want encoded value", fake.updateValues)
	}
	if len(fake.addValues) != 0 {
		t.Fatalf("add calls = %d, want 0", len(fake.addValues))
	}
}

func TestDarwinKeyringDriverSetAddsWhenUpdateReportsNotFound(t *testing.T) {
	fake := &fakeDarwinSecItemOps{
		updateStatus: []int32{darwinSecItemNotFound},
		addStatus:    []int32{darwinSecItemSuccess},
	}
	driver := darwinKeyringDriver{ops: fake}

	if err := driver.Set("service", "account", []byte("value")); err != nil {
		t.Fatal(err)
	}
	if len(fake.updateValues) != 1 || len(fake.addValues) != 1 {
		t.Fatalf("update/add calls = %d/%d, want 1/1", len(fake.updateValues), len(fake.addValues))
	}
	if !bytes.Equal(fake.addValues[0], fake.updateValues[0]) {
		t.Fatalf("add value = %q, want same encoded value as update", fake.addValues[0])
	}
}

func TestDarwinKeyringDriverSetRetriesUpdateOnceAfterDuplicateAdd(t *testing.T) {
	fake := &fakeDarwinSecItemOps{
		updateStatus: []int32{darwinSecItemNotFound, darwinSecItemSuccess},
		addStatus:    []int32{darwinSecItemDuplicate},
	}
	driver := darwinKeyringDriver{ops: fake}

	if err := driver.Set("service", "account", []byte("value")); err != nil {
		t.Fatal(err)
	}
	if len(fake.updateValues) != 2 || len(fake.addValues) != 1 {
		t.Fatalf("update/add calls = %d/%d, want 2/1", len(fake.updateValues), len(fake.addValues))
	}
}

func TestDarwinKeyringDriverSetStopsAfterTerminalUpdateFailure(t *testing.T) {
	fake := &fakeDarwinSecItemOps{updateStatus: []int32{-34018}}
	driver := darwinKeyringDriver{ops: fake}

	if err := driver.Set("service", "account", []byte("value")); err == nil || len(fake.addValues) != 0 {
		t.Fatalf("Set() error = %v, add calls = %d; want terminal error and no add", err, len(fake.addValues))
	}
}

func TestDarwinKeyringDriverSetStopsAfterTerminalAddFailure(t *testing.T) {
	fake := &fakeDarwinSecItemOps{
		updateStatus: []int32{darwinSecItemNotFound},
		addStatus:    []int32{-34018},
	}
	driver := darwinKeyringDriver{ops: fake}

	if err := driver.Set("service", "account", []byte("value")); err == nil || len(fake.updateValues) != 1 || len(fake.addValues) != 1 {
		t.Fatalf("Set() error = %v, update/add calls = %d/%d; want terminal add error", err, len(fake.updateValues), len(fake.addValues))
	}
}

func TestDarwinKeyringDriverSetRetriesDuplicateRaceOnlyOnce(t *testing.T) {
	fake := &fakeDarwinSecItemOps{
		updateStatus: []int32{darwinSecItemNotFound, darwinSecItemNotFound},
		addStatus:    []int32{darwinSecItemDuplicate},
	}
	driver := darwinKeyringDriver{ops: fake}

	if err := driver.Set("service", "account", []byte("value")); err == nil || len(fake.updateValues) != 2 || len(fake.addValues) != 1 {
		t.Fatalf("Set() error = %v, update/add calls = %d/%d; want one bounded retry", err, len(fake.updateValues), len(fake.addValues))
	}
}

func TestDarwinKeyringDriverDeleteSuccess(t *testing.T) {
	fake := &fakeDarwinSecItemOps{deleteStatus: darwinSecItemSuccess}
	driver := darwinKeyringDriver{ops: fake}

	if err := driver.Delete("service", "account"); err != nil {
		t.Fatal(err)
	}
	if fake.deleteService != "service" || fake.deleteAccount != "account" {
		t.Fatalf("delete identifiers = %q/%q, want service/account", fake.deleteService, fake.deleteAccount)
	}
}

func TestDarwinKeyringDriverDeleteMapsNotFound(t *testing.T) {
	fake := &fakeDarwinSecItemOps{deleteStatus: darwinSecItemNotFound}
	driver := darwinKeyringDriver{ops: fake}

	if err := driver.Delete("service", "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Delete() error = %v, want ErrNotFound", err)
	}
}

func TestDarwinKeyringDriverDeleteSanitizesOSStatusFailure(t *testing.T) {
	fake := &fakeDarwinSecItemOps{deleteStatus: -34018}
	driver := darwinKeyringDriver{ops: fake}

	err := driver.Delete("service", "synthetic-secret-account")
	if err == nil || strings.Contains(err.Error(), "synthetic-secret-account") {
		t.Fatalf("Delete() error = %v, want sanitized failure", err)
	}
}

func TestDarwinKeyringDriverReportsAccessDenial(t *testing.T) {
	for _, status := range []int32{darwinSecInteractionNotAllowed, darwinSecAuthFailed, darwinSecUserCanceled} {
		driver := darwinKeyringDriver{ops: &fakeDarwinSecItemOps{copyStatus: status}}
		if _, err := driver.Get("coned-cli", "account"); !errors.Is(err, ErrAccessDenied) {
			t.Fatalf("status %d: Get() error = %v, want ErrAccessDenied", status, err)
		}
	}
	driver := darwinKeyringDriver{ops: &fakeDarwinSecItemOps{copyStatus: -25291}}
	if _, err := driver.Get("coned-cli", "account"); err == nil || errors.Is(err, ErrAccessDenied) {
		t.Fatalf("unrelated status error = %v, want a generic failure", err)
	}
}

func TestDarwinKeyringDriverReplacesItemItMayNotModify(t *testing.T) {
	fake := &fakeDarwinSecItemOps{updateStatus: []int32{darwinSecInteractionNotAllowed}}
	if err := (darwinKeyringDriver{ops: fake}).Set("coned-cli", "account", []byte("value")); err != nil {
		t.Fatal(err)
	}
	if fake.deleteAccount != "account" || len(fake.addValues) != 1 {
		t.Fatalf("delete=%q adds=%d, want the item deleted and added again", fake.deleteAccount, len(fake.addValues))
	}

	fake = &fakeDarwinSecItemOps{updateStatus: []int32{darwinSecInteractionNotAllowed}, deleteStatus: darwinSecInteractionNotAllowed}
	if err := (darwinKeyringDriver{ops: fake}).Set("coned-cli", "account", []byte("value")); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("undeletable item: Set() error = %v, want ErrAccessDenied", err)
	}
	if len(fake.addValues) != 0 {
		t.Fatal("added a value after the existing item could not be removed")
	}
}
