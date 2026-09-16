// Package procs samples the descendant process tree of a wrapped command
// while it runs.
//
// We only ever observe. Every process ever seen as a descendant is retained,
// including ones that have since exited, so ancestry can still be resolved
// after the fact. Sampling is periodic (500ms by default), which means very
// short-lived processes can be missed entirely — that limitation is reported
// honestly rather than silently.
package procs

import (
	"errors"
	"sort"
	"sync"
	"time"
)

// DefaultInterval is how often the descendant tree is sampled. 500ms is a
// deliberate tradeoff: frequent enough to catch most activity in a typical
// agent session, cheap enough not to be noticeable, but it can still miss a
// process that starts and exits between two ticks.
const DefaultInterval = 500 * time.Millisecond

// errUnsupportedPlatform is returned by listAll on platforms with no
// collector (v0.1.0: anything that isn't linux or darwin).
var errUnsupportedPlatform = errors.New("process tree sampling is not implemented on this platform")

// rawProc is one process as reported by a single sample tick.
type rawProc struct {
	PID     int
	PPID    int
	Comm    string
	Cmdline []string
}

// listAll returns every process currently visible on the system. It is
// implemented per-platform (procs_linux.go, procs_darwin.go, procs_other.go).
var listAll func() ([]rawProc, error)

// Proc is one descendant process as observed across the whole sampling
// period: the union of every tick it appeared in.
type Proc struct {
	PID       int       `json:"pid"`
	PPID      int       `json:"ppid"`
	Comm      string    `json:"comm"`
	Cmdline   []string  `json:"cmdline,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// Result is the full record of one sampling run.
type Result struct {
	RootPID     int           `json:"root_pid"`
	Interval    time.Duration `json:"interval"`
	SampleCount int           `json:"sample_count"`
	// Available is false when no collector exists for this platform, or the
	// first sample attempt failed outright (e.g. /proc unreadable).
	Available bool `json:"available"`
	// Procs is every descendant of RootPID observed in any sample, sorted by
	// PID. Processes outside the descendant tree are never recorded.
	Procs []Proc `json:"procs,omitempty"`
}

// Sampler periodically snapshots the descendant tree of RootPID. Zero value
// is not usable; construct with NewSampler.
type Sampler struct {
	rootPID  int
	interval time.Duration

	mu          sync.Mutex
	procs       map[int]*Proc
	available   bool
	checked     bool
	sampleCount int

	stop chan struct{}
	done chan struct{}
}

// NewSampler prepares a sampler for the descendant tree of rootPID. Call Run
// in its own goroutine to start sampling, and Stop to end it.
func NewSampler(rootPID int, interval time.Duration) *Sampler {
	if interval <= 0 {
		interval = DefaultInterval
	}
	return &Sampler{
		rootPID:  rootPID,
		interval: interval,
		procs:    map[int]*Proc{},
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
}

// Run samples on a fixed interval until Stop is called. It takes one sample
// immediately so very short sessions still get at least one data point.
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

// Stop ends the sampling loop and blocks until it has stopped. Call SampleNow
// first if you want one last sample of the tree right as the child exits,
// since the loop may otherwise be mid-sleep when Stop is called.
func (s *Sampler) Stop() {
	close(s.stop)
	<-s.done
}

// SampleNow takes one sample immediately, outside the regular interval. Used
// to catch the tree's state right when the child process exits.
func (s *Sampler) SampleNow() {
	s.sampleOnce()
}

func (s *Sampler) sampleOnce() {
	all, err := listAll()

	s.mu.Lock()
	defer s.mu.Unlock()
	s.sampleCount++

	if !s.checked {
		s.checked = true
		s.available = err == nil
	}
	if err != nil {
		return
	}

	byPID := make(map[int]rawProc, len(all))
	for _, p := range all {
		byPID[p.PID] = p
	}

	now := time.Now()
	for pid := range descendantSet(byPID, s.rootPID) {
		rp := byPID[pid]
		p, ok := s.procs[pid]
		if !ok {
			p = &Proc{PID: pid, FirstSeen: now}
			s.procs[pid] = p
		}
		p.PPID = rp.PPID
		p.Comm = rp.Comm
		p.Cmdline = rp.Cmdline
		p.LastSeen = now
	}
}

// Result returns everything observed so far. Safe to call after Stop.
func (s *Sampler) Result() Result {
	s.mu.Lock()
	defer s.mu.Unlock()

	res := Result{
		RootPID:     s.rootPID,
		Interval:    s.interval,
		SampleCount: s.sampleCount,
		Available:   s.available,
	}
	for _, p := range s.procs {
		res.Procs = append(res.Procs, *p)
	}
	sort.Slice(res.Procs, func(i, j int) bool { return res.Procs[i].PID < res.Procs[j].PID })
	return res
}

// descendantSet returns the PIDs reachable from root by following child
// links in one tick's process table (root itself excluded). Only that tick's
// table is used for the walk — an unrelated process elsewhere on the system
// is never pulled in and never retained, even transiently.
func descendantSet(byPID map[int]rawProc, root int) map[int]bool {
	children := make(map[int][]int, len(byPID))
	for pid, p := range byPID {
		children[p.PPID] = append(children[p.PPID], pid)
	}

	set := map[int]bool{}
	queue := []int{root}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, c := range children[cur] {
			if !set[c] {
				set[c] = true
				queue = append(queue, c)
			}
		}
	}
	return set
}
