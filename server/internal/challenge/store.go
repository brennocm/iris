// Package challenge issues single-use attestation challenges.
package challenge

import (
	"crypto/rand"
	"errors"
	"sync"
	"time"
)

// Size of each challenge in bytes.
const Size = 32

// ErrFull is returned when too many challenges are outstanding.
var ErrFull = errors.New("too many outstanding challenges")

// Store keeps challenges in memory. It is correct for a single instance; several instances
// behind a load balancer need a shared store (for example Redis with SET NX and a TTL).
type Store struct {
	mu    sync.Mutex
	ttl   time.Duration
	max   int
	now   func() time.Time
	items map[string]time.Time
}

func NewStore(ttl time.Duration, max int) *Store {
	return &Store{ttl: ttl, max: max, now: time.Now, items: map[string]time.Time{}}
}

// Issue returns a new random challenge.
func (s *Store) Issue() ([]byte, error) {
	c := make([]byte, Size)
	if _, err := rand.Read(c); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for k, exp := range s.items {
		if now.After(exp) {
			delete(s.items, k)
		}
	}
	if len(s.items) >= s.max {
		return nil, ErrFull
	}
	s.items[string(c)] = now.Add(s.ttl)
	return c, nil
}

// Consume reports whether c was issued, has not expired and has not been used, and marks it
// used.
func (s *Store) Consume(c []byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.items[string(c)]
	if !ok {
		return false
	}
	delete(s.items, string(c))
	return !s.now().After(exp)
}

// TTL is how long an issued challenge stays valid.
func (s *Store) TTL() time.Duration { return s.ttl }
