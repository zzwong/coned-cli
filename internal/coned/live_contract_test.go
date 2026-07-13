package coned

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/zzwong/coned-cli/internal/auth"
	"github.com/zzwong/coned-cli/internal/securestore"
)

func TestLiveReadOnlyContracts(t *testing.T) {
	if os.Getenv("CONED_LIVE_TEST") != "1" {
		t.Skip("set CONED_LIVE_TEST=1 for explicit read-only provider checks")
	}
	session, err := auth.LoadSession(securestore.KeyringStore{}, "default")
	if err != nil {
		t.Fatal("stored session unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	client := NewDefaultClient()
	entities, err := client.Discover(ctx, session)
	if err != nil {
		t.Fatal("entity discovery contract failed")
	}
	if len(entities) == 0 {
		t.Fatal("entity discovery returned no structural records")
	}
	fingerprints, err := client.SchemaDiagnostics(ctx, session)
	if err != nil {
		t.Fatal("schema diagnostic contract failed")
	}
	if len(fingerprints) == 0 || len(fingerprints[0].Paths) == 0 {
		t.Fatal("schema diagnostic returned no paths")
	}
	t.Logf("read-only contracts passed: entities=%d schema_paths=%d", len(entities), len(fingerprints[0].Paths))
}
