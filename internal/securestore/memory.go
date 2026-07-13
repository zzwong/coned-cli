package securestore

import "sync"

// MemoryStore is an in-memory Store intended for deterministic tests.
type MemoryStore struct {
	mu     sync.RWMutex
	values map[string][]byte
}

// NewMemoryStore creates an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{values: make(map[string][]byte)}
}

func memoryKey(profile, key string) string { return profile + "\x00" + key }

func (s *MemoryStore) Get(profile, key string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	value, ok := s.values[memoryKey(profile, key)]
	if !ok {
		return nil, ErrNotFound
	}
	return append([]byte(nil), value...), nil
}

func (s *MemoryStore) Set(profile, key string, value []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.values == nil {
		s.values = make(map[string][]byte)
	}
	s.values[memoryKey(profile, key)] = append([]byte(nil), value...)
	return nil
}

func (s *MemoryStore) Delete(profile, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	name := memoryKey(profile, key)
	if _, ok := s.values[name]; !ok {
		return ErrNotFound
	}
	delete(s.values, name)
	return nil
}
