// Package session defines the persisted record of one `agentwitness run`
// invocation: an ID, the command that was wrapped, timing, exit code, and
// (as later steps add them) the observed/claimed data and findings.
package session

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/harshilaggarwal/agentwitness/internal/claim"
	"github.com/harshilaggarwal/agentwitness/internal/correlate"
	"github.com/harshilaggarwal/agentwitness/internal/netw"
	"github.com/harshilaggarwal/agentwitness/internal/procs"
	"github.com/harshilaggarwal/agentwitness/internal/snapshot"
)

// Dir is the directory, relative to the project root, where session state
// lives. Nothing agentwitness writes ever goes outside it.
const Dir = ".agentwitness"

// SessionsSubdir holds one JSON file per recorded session.
const SessionsSubdir = "sessions"

// Session is the full persisted record of one run.
type Session struct {
	ID        string    `json:"id"`
	Command   []string  `json:"command"`
	Dir       string    `json:"dir"`
	StartedAt time.Time `json:"started_at"`
	EndedAt   time.Time `json:"ended_at"`
	ExitCode  int       `json:"exit_code"`

	Before snapshot.Result     `json:"before"`
	After  snapshot.Result     `json:"after"`
	Diff   snapshot.DiffResult `json:"diff"`

	SensitiveBefore snapshot.Result     `json:"sensitive_before,omitempty"`
	SensitiveAfter  snapshot.Result     `json:"sensitive_after,omitempty"`
	SensitiveDiff   snapshot.DiffResult `json:"sensitive_diff,omitempty"`

	Processes procs.Result `json:"processes"`
	Claim     claim.Result `json:"claim"`
	Network   netw.Result  `json:"network"`

	Findings []correlate.Finding `json:"findings"`

	// Confidence notes what did and didn't run, filled in by later steps and
	// always rendered honestly in the report footer.
	Confidence Confidence `json:"confidence"`
}

// Confidence records collection gaps so the report never overstates what was
// actually observed.
type Confidence struct {
	Notes []string `json:"notes,omitempty"`
}

// NewID returns a short random hex session ID. It's not a UUID: we don't need
// global uniqueness, just something unique enough per project and easy to
// type on a command line.
func NewID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failing is effectively unheard of; fall back to time so
		// we still produce a usable, if weaker, identifier rather than crash.
		return fmt.Sprintf("t%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// NewSensitiveKey returns a random per-session key for hashing the sensitive
// watchlist. It must never be persisted; see snapshot.WalkSensitive.
func NewSensitiveKey() []byte {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// Extremely unlikely, but fall back to a time-derived key rather than
		// an all-zero one so before/after comparisons still work.
		copy(b, fmt.Sprintf("%d", time.Now().UnixNano()))
	}
	return b
}

// Root returns the .agentwitness directory for the given project dir.
func Root(projectDir string) string {
	return filepath.Join(projectDir, Dir)
}

func sessionsDir(projectDir string) string {
	return filepath.Join(Root(projectDir), SessionsSubdir)
}

// Path returns the JSON file path for a given session ID under projectDir.
func Path(projectDir, id string) string {
	return filepath.Join(sessionsDir(projectDir), id+".json")
}

// Save writes s to .agentwitness/sessions/<id>.json, creating directories as
// needed. This is the only place agentwitness writes to disk on its own.
func Save(projectDir string, s *Session) error {
	if err := os.MkdirAll(sessionsDir(projectDir), 0o755); err != nil {
		return fmt.Errorf("create session dir: %w", err)
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal session: %w", err)
	}
	tmp := Path(projectDir, s.ID) + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("write session: %w", err)
	}
	return os.Rename(tmp, Path(projectDir, s.ID))
}

// Load reads a previously saved session by ID.
func Load(projectDir, id string) (*Session, error) {
	data, err := os.ReadFile(Path(projectDir, id))
	if err != nil {
		return nil, err
	}
	var s Session
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse session %s: %w", id, err)
	}
	return &s, nil
}

// List returns session IDs under projectDir, most recently started first.
func List(projectDir string) ([]*Session, error) {
	entries, err := os.ReadDir(sessionsDir(projectDir))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []*Session
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		id := e.Name()[:len(e.Name())-len(".json")]
		s, err := Load(projectDir, id)
		if err != nil {
			// A corrupt or partially-written session file is skipped, not fatal
			// to `list`.
			continue
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StartedAt.After(out[j].StartedAt) })
	return out, nil
}

// Last returns the most recently started session, if any.
func Last(projectDir string) (*Session, error) {
	all, err := List(projectDir)
	if err != nil || len(all) == 0 {
		return nil, err
	}
	return all[0], nil
}
