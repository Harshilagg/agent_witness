package netw

import (
	"testing"
	"time"
)

func TestSample_FiltersToDescendantPIDs(t *testing.T) {
	orig := listConnections
	defer func() { listConnections = orig }()

	listConnections = func() ([]Connection, string, error) {
		return []Connection{
			{RemoteHost: "descendant.example.com", RemotePort: 443, PID: 100},
			{RemoteHost: "unrelated.example.com", RemotePort: 443, PID: 200},
		}, "ss", nil
	}

	res := Sample(map[int]bool{100: true})
	if !res.Available {
		t.Fatalf("Available = false, want true")
	}
	if len(res.Connections) != 1 || res.Connections[0].RemoteHost != "descendant.example.com" {
		t.Fatalf("Connections = %+v, want exactly the pid-100 connection", res.Connections)
	}
	if res.Connections[0].Observed.IsZero() {
		t.Errorf("Observed timestamp was not set")
	}
}

func TestSample_UnavailableWhenCollectorFails(t *testing.T) {
	orig := listConnections
	defer func() { listConnections = orig }()

	listConnections = func() ([]Connection, string, error) {
		return nil, "", errUnsupportedPlatform
	}

	res := Sample(map[int]bool{1: true})
	if res.Available {
		t.Fatalf("Available = true, want false")
	}
	if len(res.Notes) == 0 {
		t.Fatalf("Notes is empty, want an explanation")
	}
}

func TestSample_NoConnectionsIsNotUnavailable(t *testing.T) {
	orig := listConnections
	defer func() { listConnections = orig }()

	listConnections = func() ([]Connection, string, error) {
		return nil, "ss", nil
	}

	res := Sample(map[int]bool{1: true})
	if !res.Available {
		t.Fatalf("Available = false, want true: the collector ran fine, it just saw nothing")
	}
	if len(res.Connections) != 0 {
		t.Fatalf("Connections = %+v, want none", res.Connections)
	}
}

func TestSampler_AccumulatesAcrossTicks(t *testing.T) {
	orig := listConnections
	defer func() { listConnections = orig }()

	// Tick 1: descendant pid 100 has a connection.
	// Tick 2: that connection has already closed (would be invisible to a
	// single post-exit sample), but the sampler must still remember it.
	tick := 0
	listConnections = func() ([]Connection, string, error) {
		tick++
		if tick == 1 {
			return []Connection{{RemoteHost: "example.com", RemotePort: 443, PID: 100}}, "ss", nil
		}
		return nil, "ss", nil
	}

	s := NewSampler(time.Millisecond, func() map[int]bool { return map[int]bool{100: true} })
	s.sampleOnce()
	s.sampleOnce()

	res := s.Result()
	if !res.Available {
		t.Fatalf("Available = false, want true")
	}
	if len(res.Connections) != 1 || res.Connections[0].RemoteHost != "example.com" {
		t.Fatalf("Connections = %+v, want the tick-1 connection retained despite tick-2 seeing nothing", res.Connections)
	}
}

func TestSampler_GrowingDescendantSet(t *testing.T) {
	orig := listConnections
	defer func() { listConnections = orig }()

	listConnections = func() ([]Connection, string, error) {
		return []Connection{
			{RemoteHost: "a.example.com", RemotePort: 443, PID: 100},
			{RemoteHost: "b.example.com", RemotePort: 443, PID: 200},
		}, "ss", nil
	}

	// Simulates procs.Sampler discovering pid 200 only after the first tick.
	knownPIDs := map[int]bool{100: true}
	s := NewSampler(time.Millisecond, func() map[int]bool { return knownPIDs })
	s.sampleOnce() // pid 200 not yet known
	knownPIDs = map[int]bool{100: true, 200: true}
	s.sampleOnce() // pid 200 now known

	res := s.Result()
	if len(res.Connections) != 2 {
		t.Fatalf("Connections = %+v, want both pid 100 and pid 200 connections", res.Connections)
	}
}

func TestSampler_RunAndStop(t *testing.T) {
	orig := listConnections
	defer func() { listConnections = orig }()

	listConnections = func() ([]Connection, string, error) {
		return []Connection{{RemoteHost: "example.com", RemotePort: 443, PID: 1}}, "ss", nil
	}

	s := NewSampler(5*time.Millisecond, func() map[int]bool { return map[int]bool{1: true} })
	go s.Run()
	time.Sleep(20 * time.Millisecond)
	s.SampleNow()
	s.Stop()

	res := s.Result()
	if !res.Available || len(res.Connections) != 1 {
		t.Fatalf("Result = %+v, want one available connection after a running sampler", res)
	}
}
