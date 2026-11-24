package challenge

import (
	"context"
	"testing"
	"time"
)

func TestChallengesAreSingleUseAndExpire(t *testing.T) {
	now := time.Unix(1000, 0)
	s := NewMemory(time.Minute, 10)
	s.now = func() time.Time { return now }

	c, err := s.Issue(context.Background())
	if err != nil || len(c) != Size {
		t.Fatalf("issue: %v %d", err, len(c))
	}
	if ok, _ := s.Consume(context.Background(), c); !ok {
		t.Fatal("fresh challenge rejected")
	}
	if ok, _ := s.Consume(context.Background(), c); ok {
		t.Fatal("challenge accepted twice")
	}

	old, _ := s.Issue(context.Background())
	now = now.Add(2 * time.Minute)
	if ok, _ := s.Consume(context.Background(), old); ok {
		t.Fatal("expired challenge accepted")
	}
	if ok, _ := s.Consume(context.Background(), []byte("never issued")); ok {
		t.Fatal("unknown challenge accepted")
	}
}

func TestIssueIsBoundedAndReclaimsExpired(t *testing.T) {
	now := time.Unix(1000, 0)
	s := NewMemory(time.Minute, 2)
	s.now = func() time.Time { return now }
	s.Issue(context.Background())
	s.Issue(context.Background())
	if _, err := s.Issue(context.Background()); err != ErrFull {
		t.Fatalf("expected ErrFull, got %v", err)
	}
	now = now.Add(2 * time.Minute)
	if _, err := s.Issue(context.Background()); err != nil {
		t.Fatalf("expired challenges were not reclaimed: %v", err)
	}
}

func TestMemorySatisfiesTheContract(t *testing.T) {
	exerciseStore(t, NewMemory(time.Minute, 10))
}
