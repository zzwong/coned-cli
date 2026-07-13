package diagnostics

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestCollectNeverRetainsValues(t *testing.T) {
	raw := []byte(`{"email":"person@example.test","account":"123456789012345","token":"bearer-secret","customers":[{"uuid":"secret-uuid","meterType":"ELEC","usage":42.5}],"empty":[]}`)
	f, err := Collect("test", "synthetic-adversarial", raw, time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(f)
	text := string(data)
	for _, secret := range []string{"person@example.test", "123456789012345", "bearer-secret", "secret-uuid", "42.5"} {
		if strings.Contains(text, secret) {
			t.Fatalf("leaked %q in %s", secret, text)
		}
	}
	if !strings.Contains(text, "ELEC") || f.Paths["$.customers"].Cardinality != "1" || f.Paths["$.empty"].Cardinality != "0" {
		t.Fatalf("%s", text)
	}
}
