package challenge

import (
	"testing"
	"time"
)

func TestChallengesAreSingleUseAndExpire(t *testing.T) {
	now := time.Unix(1000, 0)
	s := NewStore(time.Minute, 10)
	s.now = func() time.Time { return now }

	c, err := s.Issue()
	if err != nil || len(c) != Size {
		t.Fatalf("issue: %v %d", err, len(c))
	}
	if !s.Consume(c) {
		t.Fatal("fresh challenge rejected")
	}
	if s.Consume(c) {
		t.Fatal("challenge accepted twice")
	}

	old, _ := s.Issue()
	now = now.Add(2 * time.Minute)
	if s.Consume(old) {
		t.Fatal("expired challenge accepted")
	}
	if s.Consume([]byte("never issued")) {
		t.Fatal("unknown challenge accepted")
	}
}

func TestIssueIsBoundedAndReclaimsExpired(t *testing.T) {
	now := time.Unix(1000, 0)
	s := NewStore(time.Minute, 2)
	s.now = func() time.Time { return now }
	s.Issue()
	s.Issue()
	if _, err := s.Issue(); err != ErrFull {
		t.Fatalf("expected ErrFull, got %v", err)
	}
	now = now.Add(2 * time.Minute)
	if _, err := s.Issue(); err != nil {
		t.Fatalf("expired challenges were not reclaimed: %v", err)
	}
}
