//go:build darwin && cgo

package securestore

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	keychainIntegrationEnv        = "CONED_KEYCHAIN_TEST"
	keychainIntegrationChildEnv   = "CONED_KEYCHAIN_TEST_CHILD"
	keychainIntegrationProfileEnv = "CONED_KEYCHAIN_TEST_PROFILE"
	keychainIntegrationKeyEnv     = "CONED_KEYCHAIN_TEST_KEY"
)

var keychainIntegrationCounter uint64

type keychainIntegrationItem struct {
	store   KeyringStore
	profile string
	key     string
	account string
}

func requireKeychainIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv(keychainIntegrationEnv) != "1" {
		t.Skip("set CONED_KEYCHAIN_TEST=1 to run live macOS Keychain integration tests")
	}
}

func newKeychainIntegrationItem(t *testing.T) keychainIntegrationItem {
	t.Helper()
	suffix := fmt.Sprintf("%d-%d-%d", os.Getpid(), time.Now().UnixNano(), atomic.AddUint64(&keychainIntegrationCounter, 1))
	return registerKeychainIntegrationItem(t,
		"coned-keychain-integration-profile-"+suffix,
		"coned-keychain-integration-key-"+suffix,
	)
}

func newKeychainIntegrationChildItem(t *testing.T) keychainIntegrationItem {
	t.Helper()
	profile := os.Getenv(keychainIntegrationProfileEnv)
	key := os.Getenv(keychainIntegrationKeyEnv)
	if profile == "" || key == "" {
		t.Fatalf("child test missing synthetic Keychain identity")
	}
	return registerKeychainIntegrationItem(t, profile, key)
}

func registerKeychainIntegrationItem(t *testing.T, profile, key string) keychainIntegrationItem {
	t.Helper()
	item := keychainIntegrationItem{
		store:   KeyringStore{},
		profile: profile,
		key:     key,
		account: account(profile, key),
	}
	t.Cleanup(func() {
		if err := item.store.Delete(item.profile, item.key); err != nil && !errors.Is(err, ErrNotFound) {
			t.Errorf("cleanup Delete() failed: %v", err)
		}
		assertExactKeychainItemMissing(t, item.account)
	})
	return item
}

func keychainIntegrationChildEnvironment(item keychainIntegrationItem) []string {
	env := append([]string(nil), os.Environ()...)
	env = withEnvironmentValue(env, keychainIntegrationEnv, "1")
	env = withEnvironmentValue(env, keychainIntegrationChildEnv, "1")
	env = withEnvironmentValue(env, keychainIntegrationProfileEnv, item.profile)
	env = withEnvironmentValue(env, keychainIntegrationKeyEnv, item.key)
	return env
}

func withEnvironmentValue(env []string, name, value string) []string {
	prefix := name + "="
	for i, entry := range env {
		if strings.HasPrefix(entry, prefix) {
			env[i] = prefix + value
			return env
		}
	}
	return append(env, prefix+value)
}

func assertExactKeychainItemMissing(t *testing.T, accountName string) {
	t.Helper()
	result, status := (darwinSecItemCgoOps{}).copyMatching(serviceName, accountName)
	if result.release != nil {
		result.release()
	}
	if status != darwinSecItemNotFound {
		t.Fatalf("exact Keychain lookup for service %q/account %q status = %d, want item-not-found", serviceName, accountName, status)
	}
	t.Logf("exact Keychain cleanup verified for service %q/account %q", serviceName, accountName)
}

func TestDarwinKeyringIntegrationMissingItem(t *testing.T) {
	requireKeychainIntegration(t)
	item := newKeychainIntegrationItem(t)

	if _, err := item.store.Get(item.profile, item.key); err != ErrNotFound {
		t.Fatalf("Get() error = %v, want ErrNotFound", err)
	}
}

func TestDarwinKeyringIntegrationSmallRoundTrip(t *testing.T) {
	requireKeychainIntegration(t)
	item := newKeychainIntegrationItem(t)
	want := []byte("synthetic-small-keychain-value")

	if err := item.store.Set(item.profile, item.key, want); err != nil {
		t.Fatalf("Set() failed: %v", err)
	}
	got, err := item.store.Get(item.profile, item.key)
	if err != nil {
		t.Fatalf("Get() failed: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("Get() = %q, want %q", got, want)
	}
}

func TestDarwinKeyringIntegrationLargeBinaryRoundTrip(t *testing.T) {
	requireKeychainIntegration(t)
	item := newKeychainIntegrationItem(t)
	want := make([]byte, 16*1024)
	for i := range want {
		want[i] = byte((i*29 + 7) % 256)
	}

	if err := item.store.Set(item.profile, item.key, want); err != nil {
		t.Fatalf("Set() failed: %v", err)
	}
	got, err := item.store.Get(item.profile, item.key)
	if err != nil {
		t.Fatalf("Get() failed: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("large binary round trip changed payload: got %d bytes, want %d", len(got), len(want))
	}
}

func TestDarwinKeyringIntegrationOverwrite(t *testing.T) {
	requireKeychainIntegration(t)
	item := newKeychainIntegrationItem(t)
	first := []byte("synthetic-first-value")
	second := []byte("synthetic-overwritten-value")

	if err := item.store.Set(item.profile, item.key, first); err != nil {
		t.Fatalf("first Set() failed: %v", err)
	}
	if err := item.store.Set(item.profile, item.key, second); err != nil {
		t.Fatalf("second Set() failed: %v", err)
	}
	got, err := item.store.Get(item.profile, item.key)
	if err != nil {
		t.Fatalf("Get() failed: %v", err)
	}
	if !bytes.Equal(got, second) {
		t.Fatalf("Get() after overwrite = %q, want %q", got, second)
	}
}

func TestDarwinKeyringIntegrationDeleteAndRepeatedDelete(t *testing.T) {
	requireKeychainIntegration(t)
	item := newKeychainIntegrationItem(t)

	if err := item.store.Set(item.profile, item.key, []byte("synthetic-delete-value")); err != nil {
		t.Fatalf("Set() failed: %v", err)
	}
	if err := item.store.Delete(item.profile, item.key); err != nil {
		t.Fatalf("Delete() failed: %v", err)
	}
	if _, err := item.store.Get(item.profile, item.key); err != ErrNotFound {
		t.Fatalf("Get() after Delete() error = %v, want ErrNotFound", err)
	}
	if err := item.store.Delete(item.profile, item.key); err != ErrNotFound {
		t.Fatalf("repeated Delete() error = %v, want ErrNotFound", err)
	}
}

func TestDarwinKeyringIntegrationCleanupAfterForcedFailure(t *testing.T) {
	requireKeychainIntegration(t)
	if os.Getenv(keychainIntegrationChildEnv) == "1" {
		item := newKeychainIntegrationChildItem(t)
		if err := item.store.Set(item.profile, item.key, []byte("synthetic-forced-failure-value")); err != nil {
			t.Fatalf("child Set() failed: %v", err)
		}
		t.Fatal("synthetic keychain assertion failure")
	}

	item := newKeychainIntegrationItem(t)
	cmd := exec.Command(os.Args[0], "-test.run", "^TestDarwinKeyringIntegrationCleanupAfterForcedFailure$")
	cmd.Env = keychainIntegrationChildEnvironment(item)
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("child unexpectedly passed instead of exercising forced failure cleanup")
	}
	if !bytes.Contains(output, []byte("synthetic keychain assertion failure")) {
		t.Fatalf("child output did not prove forced assertion ran: %q", output)
	}
	assertExactKeychainItemMissing(t, item.account)
}
