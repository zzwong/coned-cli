// Package identity creates stable, privacy-preserving entity handles.
package identity

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/zzwong/coned-cli/internal/securestore"
)

const handleKey = "entity-handle-key-v1"

var ErrHandleKeyMissing = errors.New("entity handle key is missing")
var aliasPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

type Manager struct{ key []byte }
type Entity struct{ Type, Namespace, ProviderID string }

func Deterministic(seed string) *Manager {
	sum := sha256.Sum256([]byte("coned-demo-v1\x00" + seed))
	return &Manager{key: sum[:]}
}

func Load(store securestore.Store, profile string, create bool) (*Manager, error) {
	key, err := store.Get(profile, handleKey)
	if errors.Is(err, securestore.ErrNotFound) && create {
		key = make([]byte, 32)
		if _, err = rand.Read(key); err != nil {
			return nil, fmt.Errorf("create handle key: %w", err)
		}
		if err = store.Set(profile, handleKey, key); err != nil {
			return nil, err
		}
	} else if errors.Is(err, securestore.ErrNotFound) {
		return nil, ErrHandleKeyMissing
	} else if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, errors.New("invalid entity handle key")
	}
	return &Manager{key: append([]byte(nil), key...)}, nil
}
func (m *Manager) Handle(entity Entity) (string, error) {
	prefix := map[string]string{"account": "account", "premise": "premise", "meter": "meter", "register": "register"}[entity.Type]
	if prefix == "" || entity.Namespace == "" || entity.ProviderID == "" {
		return "", errors.New("invalid entity identity")
	}
	mac := hmac.New(sha256.New, m.key)
	mac.Write([]byte("v1\x00" + entity.Type + "\x00" + entity.Namespace + "\x00" + entity.ProviderID))
	encoded := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(mac.Sum(nil)))
	return prefix + "-" + encoded[:12], nil
}
func (m *Manager) Handles(entities []Entity) ([]string, error) {
	out := make([]string, len(entities))
	seen := map[string]bool{}
	for i, e := range entities {
		h, err := m.Handle(e)
		if err != nil {
			return nil, err
		}
		if seen[h] {
			return nil, errors.New("entity handle collision")
		}
		seen[h] = true
		out[i] = h
	}
	return out, nil
}
func ValidAlias(alias string) bool {
	return aliasPattern.MatchString(alias) && !strings.HasPrefix(alias, "account-") && !strings.HasPrefix(alias, "meter-") && !strings.HasPrefix(alias, "premise-") && !strings.HasPrefix(alias, "register-")
}
