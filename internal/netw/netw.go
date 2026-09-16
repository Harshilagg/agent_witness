// Package netw samples established TCP connections made by a wrapped
// command's descendant processes.
//
// This is opt-in (the `run --net` flag) and strictly best-effort: it shells
// out to whatever platform tool is available (`ss` on Linux, `lsof` on
// macOS), and if neither exists, or the platform has no collector at all, it
// degrades to Result.Available == false rather than failing the run. No
// /proc/net inode→fd mapping and no eBPF in v0.1.0 — see the README roadmap.
//
// Connections are sampled periodically while the wrapped command runs (see
// Sampler), not just once at exit — a one-shot sample taken after cmd.Wait()
// returns would almost always see nothing, since by then the process (and
// its sockets) has already gone. Even so, a connection opened and fully
// closed between two ticks is still invisible; that gap is real and is
// surfaced honestly rather than hidden.
package netw

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

var errUnsupportedPlatform = errors.New("network sampling is not implemented on this platform")

// DefaultInterval is how often the connection table is sampled. It is
// coarser than process sampling's 500ms: shelling out to `ss`/`lsof`
// enumerates every socket on the system, which is real work worth not
// repeating too often during a long-running, --net-enabled agent session.
const DefaultInterval = 2 * time.Second

// Connection is one observed established TCP connection.
type Connection struct {
	RemoteHost string    `json:"remote_host"`
	RemotePort int       `json:"remote_port"`
	PID        int       `json:"pid"`
	Observed   time.Time `json:"observed"`
}

// Result is everything sampled (or not) for one run.
type Result struct {
	// Available is false when no collector tool could be run at all — not
	// to be confused with Available == true and zero Connections, which
	// just means nothing was observed.
	Available bool `json:"available"`
	// Tool names which platform tool produced this result ("ss" or
	// "lsof"), for evidence.
	Tool        string       `json:"tool,omitempty"`
	Connections []Connection `json:"connections,omitempty"`
	Notes       []string     `json:"notes,omitempty"`
}

// listConnections is implemented per-platform (netw_linux.go, netw_darwin.go,
// netw_other.go) and returns every established TCP connection currently
// visible on the system, unfiltered by owner.
var listConnections func() (conns []Connection, tool string, err error)

// Sample lists established TCP connections owned by any PID in
// descendantPIDs, which should include the wrapped command's own PID as
// well as every descendant procs.Sampler observed (a connection made
// directly by the wrapped process itself still counts).
func Sample(descendantPIDs map[int]bool) Result {
	all, tool, err := listConnections()
	if err != nil {
		return Result{
			Available: false,
			Notes:     []string{"network sampling unavailable: " + err.Error()},
		}
	}

	now := time.Now()
	var filtered []Connection
	for _, c := range all {
		if !descendantPIDs[c.PID] {
			continue
		}
		c.Observed = now
		filtered = append(filtered, c)
	}

	return Result{Available: true, Tool: tool, Connections: filtered}
}

// Sampler periodically samples established connections while a wrapped
// command runs, accumulating every connection ever seen for a descendant
// PID — including ones already closed by the time the caller reads Result —
// the same "retain everything ever observed" approach procs.Sampler uses.
type Sampler struct {
	interval time.Duration
	// descendantPIDs is called fresh on every tick, since the set of known
	// descendants grows over the life of the run (see procs.Sampler).
	descendantPIDs func() map[int]bool

	mu          sync.Mutex
	seen        map[string]Connection
	available   bool
	checked     bool
	tool        string
	sampleCount int

	stop chan struct{}
	done chan struct{}
}

// NewSampler prepares a sampler. descendantPIDs is called on every tick to
// get the current known descendant PID set (including the wrapped command's
// own root PID); callers typically close over a procs.Sampler's Result.
func NewSampler(interval time.Duration, descendantPIDs func() map[int]bool) *Sampler {
	if interval <= 0 {
		interval = DefaultInterval
	}
	return &Sampler{
		interval:       interval,
		descendantPIDs: descendantPIDs,
		seen:           map[string]Connection{},
		stop:           make(chan struct{}),
		done:           make(chan struct{}),
	}
}

// Run samples on a fixed interval until Stop is called. It samples once
// immediately so even a very short run gets at least one data point.
func (s *Sampler) Run() {
	s.sampleOnce()
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-s.stop:
			close(s.done)
			return
		case <-ticker.C:
			s.sampleOnce()
		}
	}
}

// Stop ends the sampling loop and blocks until it has stopped. Call
// SampleNow first to catch the connection table right as the child exits,
// since the loop may otherwise be mid-sleep when Stop is called.
func (s *Sampler) Stop() {
	close(s.stop)
	<-s.done
}

// SampleNow takes one sample immediately, outside the regular interval.
func (s *Sampler) SampleNow() {
	s.sampleOnce()
}

func (s *Sampler) sampleOnce() {
	res := Sample(s.descendantPIDs())

	s.mu.Lock()
	defer s.mu.Unlock()
	s.sampleCount++

	if !s.checked {
		s.checked = true
		s.available = res.Available
		s.tool = res.Tool
	}
	if !res.Available {
		return
	}
	for _, c := range res.Connections {
		key := fmt.Sprintf("%d|%s|%d", c.PID, c.RemoteHost, c.RemotePort)
		if _, exists := s.seen[key]; !exists {
			s.seen[key] = c
		}
	}
}

// Result returns everything observed so far. Safe to call after Stop, or at
// any point while Run is still active.
func (s *Sampler) Result() Result {
	s.mu.Lock()
	defer s.mu.Unlock()

	res := Result{Available: s.available, Tool: s.tool}
	for _, c := range s.seen {
		res.Connections = append(res.Connections, c)
	}
	sort.Slice(res.Connections, func(i, j int) bool {
		a, b := res.Connections[i], res.Connections[j]
		if a.PID != b.PID {
			return a.PID < b.PID
		}
		if a.RemoteHost != b.RemoteHost {
			return a.RemoteHost < b.RemoteHost
		}
		return a.RemotePort < b.RemotePort
	})
	return res
}
