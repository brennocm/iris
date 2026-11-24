// Package challenge issues single-use attestation challenges.
package challenge

import (
	"context"
	"crypto/rand"
	"errors"
	"sync"
	"time"
)

// Size of each challenge in bytes.
const Size = 32

// ErrFull is returned when too many challenges are outstanding.
var ErrFull = errors.New("too many outstanding challenges")

// Store issues single-use challenges and consumes them exactly once.
type Store interface {
	// Issue returns a new random challenge valid for TTL.
	Issue(ctx context.Context) ([]byte, error)
	// Consume reports whether c was issued, has not expired and has not been used, and marks
	// it used. An error means the store could not answer, not that the challenge is invalid.
	Consume(ctx context.Context, c []byte) (bool, error)
	TTL() time.Duration
}

func newChallenge() ([]byte, error) {
	c := make([]byte, Size)
	if _, err := rand.Read(c); err != nil {
		return nil, err
	}
	return c, nil
}

// Memory keeps challenges in this process. It is correct for a single instance; several
// instances behind a load balancer need [Redis].
type Memory struct {
	mu    sync.Mutex
	ttl   time.Duration
	max   int
	now   func() time.Time
	items map[string]time.Time
}

func NewMemory(ttl time.Duration, max int) *Memory {
	return &Memory{ttl: ttl, max: max, now: time.Now, items: map[string]time.Time{}}
}

func (s *Memory) Issue(context.Context) ([]byte, error) {
	c, err := newChallenge()
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if len(s.items) >= s.max {
		// Sweep expired entries only when full, so a burst of requests does not scan the
		// whole map on every call.
		for k, exp := range s.items {
			if now.After(exp) {
				delete(s.items, k)
			}
		}
		if len(s.items) >= s.max {
			return nil, ErrFull
		}
	}
	s.items[string(c)] = now.Add(s.ttl)
	return c, nil
}

func (s *Memory) Consume(_ context.Context, c []byte) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.items[string(c)]
	if !ok {
		return false, nil
	}
	delete(s.items, string(c))
	return !s.now().After(exp), nil
}

func (s *Memory) TTL() time.Duration { return s.ttl }
