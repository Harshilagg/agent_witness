// Package claim extracts what an AI coding agent's own session log says it
// did — the "claim" side of the observed-vs-claimed comparison. It never
// treats the log as authoritative; it is the thing being checked.
//
// The log format is not ours and it drifts. Every parser in this package
// must be tolerant of unknown shapes: an unrecognized record is skipped, a
// malformed line is skipped, and a total parse failure degrades to
// Result.Available == false, never a crash.
package claim

import "time"

// Kind identifies what an agent claimed to do in one tool call.
type Kind string

const (
	// KindEdit is a claimed write to a file (Edit, Write, MultiEdit,
	// NotebookEdit all reduce to this — we don't yet distinguish them for
	// correlation purposes; the tool name is preserved in Tool).
	KindEdit Kind = "edit"
	// KindRead is a claimed read of a file.
	KindRead Kind = "read"
	// KindCommand is a claimed shell command.
	KindCommand Kind = "command"
)

// Claim is one thing the agent's session log says it did.
type Claim struct {
	Kind Kind `json:"kind"`
	// Tool is the original tool name as it appears in the log (e.g. "Edit",
	// "MultiEdit", "Bash"), kept for evidence even though Kind normalizes it.
	Tool string `json:"tool"`
	// Path is set for KindEdit and KindRead.
	Path string `json:"path,omitempty"`
	// Command is set for KindCommand.
	Command   string    `json:"command,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// Result is everything extracted from an agent's claim log for one session,
// plus an honest account of how much of it could actually be read.
type Result struct {
	// Source names which agent's log format this came from, e.g.
	// "claude-code". Empty if nothing could be identified.
	Source string `json:"source,omitempty"`
	// Available is false when no claim log could be found, matched or
	// parsed at all. Callers must treat this as "claim unavailable", not as
	// "the agent claimed nothing".
	Available bool `json:"available"`
	// Files lists the session log file(s) actually used, for evidence.
	Files  []string `json:"files,omitempty"`
	Claims []Claim  `json:"claims,omitempty"`
	// SkippedLines counts log lines that could not be parsed as JSON or had
	// an unrecognized shape. A high count is a sign the log format has
	// drifted, not a fatal error.
	SkippedLines int      `json:"skipped_lines,omitempty"`
	Notes        []string `json:"notes,omitempty"`
}

// Source is the extensibility point named in the project's design as the
// "Claim interface": one implementation per coding agent whose session log
// we know how to read. v0.1.0 ships only ClaudeCode; OpenCode, Cursor, etc.
// can implement this later without touching correlate or report.
type Source interface {
	// Name identifies the agent this Source understands, e.g. "claude-code".
	Name() string
	// Parse extracts claims made while running in projectDir at any point
	// between start and end (inclusive). It never returns an error: total
	// failure is expressed as Result.Available == false.
	Parse(projectDir string, start, end time.Time) Result
}
