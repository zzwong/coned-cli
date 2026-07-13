// Package diagnostics creates value-free structural fingerprints.
package diagnostics

import (
	"encoding/json"
	"sort"
	"strconv"
	"time"
)

const SchemaVersion = 1

type Node struct {
	Types       []string `json:"types"`
	Nullable    bool     `json:"nullable,omitempty"`
	Cardinality string   `json:"cardinality,omitempty"`
	Enums       []string `json:"enums,omitempty"`
}
type Fingerprint struct {
	SchemaVersion int             `json:"schema_version"`
	Operation     string          `json:"operation"`
	Provenance    string          `json:"provenance"`
	LastChecked   string          `json:"last_checked"`
	Paths         map[string]Node `json:"paths"`
}

var enumKeys = map[string]bool{"meterType": true, "readResolution": true, "serviceType": true, "unit": true, "unitOfMeasure": true}

func Collect(operation, provenance string, raw []byte, now time.Time) (Fingerprint, error) {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return Fingerprint{}, err
	}
	f := Fingerprint{SchemaVersion: SchemaVersion, Operation: operation, Provenance: provenance, LastChecked: now.UTC().Format(time.RFC3339), Paths: map[string]Node{}}
	walk(&f, "$", "", value)
	return f, nil
}
func walk(f *Fingerprint, path, key string, value any) {
	n := f.Paths[path]
	t := jsonType(value)
	if !contains(n.Types, t) {
		n.Types = append(n.Types, t)
		sort.Strings(n.Types)
	}
	if value == nil {
		n.Nullable = true
	}
	switch x := value.(type) {
	case []any:
		if len(x) == 0 {
			n.Cardinality = "0"
		} else if len(x) == 1 {
			n.Cardinality = "1"
		} else {
			n.Cardinality = "many"
		}
		f.Paths[path] = n
		for _, child := range x {
			walk(f, path+"[]", key, child)
		}
	case map[string]any:
		f.Paths[path] = n
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			walk(f, path+"."+k, k, x[k])
		}
	case string:
		if enumKeys[key] && len(x) <= 32 && safeEnum(x) && !contains(n.Enums, x) {
			n.Enums = append(n.Enums, x)
			sort.Strings(n.Enums)
		}
		f.Paths[path] = n
	default:
		f.Paths[path] = n
	}
}
func jsonType(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case string:
		return "string"
	case float64:
		return "number"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	}
	return "unknown"
}
func contains(values []string, target string) bool {
	for _, v := range values {
		if v == target {
			return true
		}
	}
	return false
}
func safeEnum(v string) bool {
	for _, r := range v {
		if (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' && r != '-' {
			return false
		}
	}
	return v != "" && v != strconv.Itoa(0)
}
