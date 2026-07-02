package main

import (
	"testing"
	"time"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

func TestVelocityWindow_Aggregate(t *testing.T) {
	w := &velocityWindow{}
	base := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)

	// Two events 90 and 30 minutes ago, one 2 minutes ago.
	w.record(base.Add(-90*time.Minute), 500)
	w.record(base.Add(-30*time.Minute), 700)
	w.record(base.Add(-2*time.Minute), 300)

	s1, c1, s24, c24 := w.aggregate(base)
	if c1 != 2 || s1 != 1000 {
		t.Errorf("1h window: got sum=%v count=%d, want sum=1000 count=2", s1, c1)
	}
	if c24 != 3 || s24 != 1500 {
		t.Errorf("24h window: got sum=%v count=%d, want sum=1500 count=3", s24, c24)
	}
}

func TestVelocityWindow_Prune24h(t *testing.T) {
	w := &velocityWindow{}
	base := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	w.record(base.Add(-26*time.Hour), 999) // outside 24h — should be pruned
	w.record(base.Add(-1*time.Hour), 100)

	_, _, s24, c24 := w.aggregate(base)
	if c24 != 1 || s24 != 100 {
		t.Errorf("expected the 26h-old event pruned: got sum=%v count=%d", s24, c24)
	}
	if len(w.events) != 1 {
		t.Errorf("expected pruned slice len 1, got %d", len(w.events))
	}
}

func TestVelocityWindow_HardCap(t *testing.T) {
	w := &velocityWindow{}
	now := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	for i := 0; i < velocityMaxEventsPerKey+500; i++ {
		w.record(now, 1)
	}
	if len(w.events) > velocityMaxEventsPerKey {
		t.Errorf("hard cap breached: %d > %d", len(w.events), velocityMaxEventsPerKey)
	}
}

func TestVelocityTracker_KeyingAndBound(t *testing.T) {
	v := newVelocityTracker()
	v.maxKeys = 3
	v.idleEvict = time.Nanosecond // everything is immediately evictable

	// Distinct keys beyond the cap trigger a sweep; because idleEvict is
	// ~0 the old windows are reaped and the map stays bounded.
	for _, k := range []string{"a", "b", "c", "d", "e"} {
		w := v.windowFor(k)
		if w == nil {
			t.Fatalf("nil window for %q", k)
		}
		time.Sleep(time.Millisecond)
	}
	if got := v.stats(); got > 3 {
		t.Errorf("tracker exceeded maxKeys after sweep: %d", got)
	}

	// Empty key collapses to the shared _unknown bucket.
	if v.windowFor("") != v.windowFor("") {
		t.Error("empty key should map to a stable shared window")
	}
}

func TestVelocityKey(t *testing.T) {
	env := &domain.ActionEnvelope{AgentID: "ag1", SessionID: "s1", OrgID: "o1"}
	if velocityKey(env, "agent_id") != "ag1" {
		t.Error("agent_id keying")
	}
	if velocityKey(env, "session_id") != "s1" {
		t.Error("session_id keying")
	}
	if velocityKey(env, "org_id") != "o1" {
		t.Error("org_id keying")
	}
	if velocityKey(env, "bogus") != "ag1" {
		t.Error("unknown key-by should default to agent_id")
	}
}
