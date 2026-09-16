package procs

import (
	"testing"
	"time"
)

func TestDescendantSet(t *testing.T) {
	// Tree:
	//   1 (root, our wrapped command)
	//   ├─ 2
	//   │  └─ 4
	//   └─ 3
	//   9 (unrelated process elsewhere on the system)
	byPID := map[int]rawProc{
		1: {PID: 1, PPID: 0},
		2: {PID: 2, PPID: 1},
		3: {PID: 3, PPID: 1},
		4: {PID: 4, PPID: 2},
		9: {PID: 9, PPID: 0},
	}

	got := descendantSet(byPID, 1)

	want := map[int]bool{2: true, 3: true, 4: true}
	if len(got) != len(want) {
		t.Fatalf("descendantSet = %v, want %v", got, want)
	}
	for pid := range want {
		if !got[pid] {
			t.Errorf("descendantSet missing expected descendant pid %d", pid)
		}
	}
	if got[1] {
		t.Errorf("descendantSet must not include the root itself")
	}
	if got[9] {
		t.Errorf("descendantSet must not include an unrelated process")
	}
}

func TestSampler_TracksDescendantsAcrossTicks(t *testing.T) {
	orig := listAll
	defer func() { listAll = orig }()

	// Tick 1: only the root and one child exist.
	tick1 := []rawProc{
		{PID: 1, PPID: 0, Comm: "root", Cmdline: []string{"root"}},
		{PID: 2, PPID: 1, Comm: "child", Cmdline: []string{"child", "--flag"}},
	}
	// Tick 2: the child has exited, a grandchild (already gone by now too)
	// spawned and died between ticks — this simulates a short-lived process
	// we never observe, which is expected and documented behaviour.
	tick2 := []rawProc{
		{PID: 1, PPID: 0, Comm: "root", Cmdline: []string{"root"}},
	}

	calls := 0
	listAll = func() ([]rawProc, error) {
		calls++
		if calls == 1 {
			return tick1, nil
		}
		return tick2, nil
	}

	s := NewSampler(1, time.Millisecond) // interval unused; we call sampleOnce directly
	s.sampleOnce()
	s.sampleOnce()

	res := s.Result()
	if !res.Available {
		t.Fatalf("Available = false, want true")
	}
	if res.SampleCount != 2 {
		t.Fatalf("SampleCount = %d, want 2", res.SampleCount)
	}
	if len(res.Procs) != 1 {
		t.Fatalf("Procs = %+v, want exactly pid 2 retained across ticks", res.Procs)
	}
	p := res.Procs[0]
	if p.PID != 2 || p.Comm != "child" {
		t.Fatalf("Procs[0] = %+v, want pid=2 comm=child", p)
	}
	if !p.LastSeen.After(p.FirstSeen) && !p.LastSeen.Equal(p.FirstSeen) {
		t.Fatalf("LastSeen (%v) should be >= FirstSeen (%v)", p.LastSeen, p.FirstSeen)
	}
	// Root itself must never appear in the descendant list.
	for _, p := range res.Procs {
		if p.PID == 1 {
			t.Fatalf("root pid 1 must not appear in Procs")
		}
	}
}

func TestSampler_UnavailablePlatform(t *testing.T) {
	orig := listAll
	defer func() { listAll = orig }()

	listAll = func() ([]rawProc, error) {
		return nil, errUnsupportedPlatform
	}

	s := NewSampler(1, time.Millisecond)
	s.sampleOnce()
	s.sampleOnce() // availability is latched from the first sample only

	res := s.Result()
	if res.Available {
		t.Fatalf("Available = true, want false")
	}
	if len(res.Procs) != 0 {
		t.Fatalf("Procs = %+v, want none when collection is unavailable", res.Procs)
	}
}

func TestSampler_RunAndStop(t *testing.T) {
	orig := listAll
	defer func() { listAll = orig }()

	listAll = func() ([]rawProc, error) {
		return []rawProc{{PID: 1, PPID: 0}}, nil
	}

	s := NewSampler(1, 5*time.Millisecond)
	go s.Run()
	time.Sleep(20 * time.Millisecond)
	s.SampleNow()
	s.Stop()

	res := s.Result()
	if res.SampleCount < 2 {
		t.Fatalf("SampleCount = %d, want at least 2 across a running sampler", res.SampleCount)
	}
}
