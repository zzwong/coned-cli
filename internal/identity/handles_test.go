package identity

import (
	"github.com/zzwong/coned-cli/internal/securestore"
	"strings"
	"testing"
)

func TestHandlesStableIsolatedAndOpaque(t *testing.T) {
	s := securestore.NewMemoryStore()
	a, _ := Load(s, "a", true)
	again, _ := Load(s, "a", false)
	b, _ := Load(s, "b", true)
	e := Entity{"account", "opower", "raw-provider-secret"}
	ha, _ := a.Handle(e)
	ha2, _ := again.Handle(e)
	hb, _ := b.Handle(e)
	if ha != ha2 || ha == hb || strings.Contains(ha, "secret") || !strings.HasPrefix(ha, "account-") {
		t.Fatalf("handles %q %q %q", ha, ha2, hb)
	}
	meter, _ := a.Handle(Entity{"meter", "opower", e.ProviderID})
	if meter == ha {
		t.Fatal("type isolation failed")
	}
}
func TestAliasValidation(t *testing.T) {
	for _, v := range []string{"home", "gas-2"} {
		if !ValidAlias(v) {
			t.Fatal(v)
		}
	}
	for _, v := range []string{"", "Home", "account-abc", "spaces here"} {
		if ValidAlias(v) {
			t.Fatal(v)
		}
	}
}
func TestMissingKey(t *testing.T) {
	if _, err := Load(securestore.NewMemoryStore(), "x", false); err != ErrHandleKeyMissing {
		t.Fatalf("%v", err)
	}
}
