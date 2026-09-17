// Package correlate is the core of agentwitness: comparing what was
// observed out-of-band against what the agent's own session log claimed,
// and turning any discrepancy into a Finding.
//
// Analyze is a pure function over two plain data structs. It does no I/O, no
// filesystem access, no clock reads — every input it needs is passed in, so
// every finding type is fully exercisable from a table-driven test without
// touching disk, a process tree, or a real session log.
package correlate

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Harshilagg/agent_witness/internal/claim"
	"github.com/Harshilagg/agent_witness/internal/procs"
	"github.com/Harshilagg/agent_witness/internal/snapshot"
)

// FindingType identifies the kind of discrepancy a Finding reports.
type FindingType string

const (
	// UnclaimedWrite: a file changed on disk with no claimed Edit/Write/
	// MultiEdit/NotebookEdit call for that path. This is the tool's
	// headline case — a subprocess wrote something the session log never
	// mentions an edit to.
	UnclaimedWrite FindingType = "UNCLAIMED_WRITE"
	// ClaimWithoutEffect: the agent claimed an edit to a path we fingerprint
	// (inside the project directory), but the file is unchanged on disk.
	ClaimWithoutEffect FindingType = "CLAIM_WITHOUT_EFFECT"
	// OutOfBounds: a claimed edit targets a path outside the project
	// directory. This can only be detected from claims, not observation —
	// we only fingerprint the project tree and the sensitive watchlist, so
	// a silent (unclaimed) write to some other arbitrary path on the
	// filesystem is invisible to us and cannot produce this finding.
	OutOfBounds FindingType = "OUT_OF_BOUNDS"
	// SensitiveTouch: an observed change to a path on the sensitive
	// watchlist (~/.ssh, ~/.aws, shell rc files, ...).
	SensitiveTouch FindingType = "SENSITIVE_TOUCH"
	// UnclaimedProcess: a descendant process whose binary name is never
	// mentioned in any claimed Bash command.
	UnclaimedProcess FindingType = "UNCLAIMED_PROCESS"
	// UnexpectedEgress: a descendant process connected to a host outside
	// the configured allowlist. Only meaningful once network sampling is
	// enabled; with no observed connections this simply never fires.
	UnexpectedEgress FindingType = "UNEXPECTED_EGRESS"
)

// Severity is a coarse priority signal for report ordering and highlighting.
// It is not part of the spec's required finding metadata beyond the two
// types it explicitly calls out (SENSITIVE_TOUCH: HIGH, UNCLAIMED_PROCESS:
// MEDIUM); the rest are judgment calls documented alongside each rule below.
type Severity string

const (
	SeverityHigh   Severity = "HIGH"
	SeverityMedium Severity = "MEDIUM"
	SeverityLow    Severity = "LOW"
	// SeverityInfo is for findings a reader should be able to audit but
	// should not be alarmed by — things that are expected in a normal
	// session and are reported for completeness, not concern.
	SeverityInfo Severity = "INFO"
)

// Finding is one discrepancy between what was observed and what was
// claimed.
type Finding struct {
	Type     FindingType `json:"type"`
	Severity Severity    `json:"severity"`
	Title    string      `json:"title"`
	Detail   string      `json:"detail"`
	// Evidence is plain facts only: paths, binary names, counts, ports.
	// Never file contents, never environment variable values.
	Evidence []string `json:"evidence,omitempty"`
	// Timestamp is when the underlying claim or observation occurred, when
	// known. Zero when there is no single meaningful instant (e.g. a
	// filesystem diff has no timestamp of its own).
	Timestamp time.Time `json:"timestamp,omitempty"`
}

// Connection is one observed network connection made by a descendant
// process. Defined here, the package that consumes it, rather than in
// internal/netw (added in a later step) which will produce values of this
// shape.
type Connection struct {
	RemoteHost string    `json:"remote_host"`
	RemotePort int       `json:"remote_port"`
	PID        int       `json:"pid"`
	Observed   time.Time `json:"observed,omitempty"`
}

// Observed is everything agentwitness collected out-of-band, independent of
// what the agent's own session log says.
type Observed struct {
	// ProjectDir is the absolute project root. Diff paths are resolved
	// against it to test OUT_OF_BOUNDS and CLAIM_WITHOUT_EFFECT scope.
	ProjectDir string
	Diff       snapshot.DiffResult
	// SensitiveDiff is the before/after diff of the sensitive path
	// watchlist (~/.ssh, ~/.aws, shell rc files, ...), one level deep.
	SensitiveDiff snapshot.DiffResult
	Processes     []procs.Proc
	Connections   []Connection
}

// Claimed is what the agent's own session log says it did.
type Claimed struct {
	Claims []claim.Claim
}

// Config tunes correlation without changing its logic.
type Config struct {
	// AllowedHosts is the network egress allowlist for UNEXPECTED_EGRESS. A
	// nil/empty map means no host is pre-approved, so every observed
	// connection is unexpected — this only has any effect once network
	// sampling is enabled (opt-in, a later step).
	AllowedHosts map[string]bool
	// AgentBinary, if set, is excluded from UNCLAIMED_PROCESS alongside
	// ShellWrappers (e.g. "claude" should not be flagged as an unclaimed
	// process descendant of itself).
	AgentBinary string
}

// ShellWrappers are never themselves reported as an unclaimed process: a
// shell is how a claimed Bash command actually executes, not a separate
// program the agent silently invoked. This is a documented, easily extended
// constant because false positives here are the main quality risk in
// UNCLAIMED_PROCESS — if another shell shows up in practice, add it here.
var ShellWrappers = map[string]bool{
	"sh":   true,
	"bash": true,
	"zsh":  true,
	"dash": true,
	"env":  true,
}

// Unattributable are process records that name a state rather than a
// program, so no binary can be attributed to them. macOS `ps` reports a
// zombie's command as "<defunct>"; a real session produced eight of these,
// each becoming its own finding, telling the reader nothing they could act
// on. They are still counted in the observed process list — only excluded
// from findings.
var Unattributable = map[string]bool{
	"<defunct>": true,
	"(unknown)": true,
}

// AgentInfrastructure are binaries coding agents routinely spawn as their
// own machinery rather than on the user's behalf. Observed in a real Claude
// Code session: `caffeinate` (prevents sleep for the session), `security`
// (macOS keychain), `gh` (GitHub integration), and `uname`/`tr`/`printf`/
// `tail`/`head`/`sed`/`grep` (shell-environment snapshotting at startup).
//
// These are grouped into one informational finding, never silently
// dropped. Several of them — `security` and `gh` especially — touch real
// credentials, and quietly whitelisting a credential-reading binary in a
// security tool would build precisely the blind spot an attacker would
// choose to hide in. Grouping keeps them auditable while stopping them
// from drowning genuine findings.
//
// Documented and exported so it is easy to extend as other agents' plumbing
// shows up in practice.
var AgentInfrastructure = map[string]bool{
	"caffeinate": true,
	"security":   true,
	"gh":         true,
	"uname":      true,
	"tr":         true,
	"printf":     true,
	"tail":       true,
	"head":       true,
	"sed":        true,
	"grep":       true,
	"dirname":    true,
	"basename":   true,
	"which":      true,
	"locale":     true,
}

// normalizeBinary reduces a binary name to a comparable form: lower-cased,
// with any trailing version suffix removed.
//
// This exists because macOS reports the Python framework executable as
// "Python" while the command that launched it says "python3" — a real
// session flagged a genuinely claimed python3 invocation as unclaimed
// purely on that mismatch. "Python", "python3" and "python3.14" all
// normalize to "python".
//
// Deliberately biased toward over-matching: a collision here costs a missed
// finding, while under-matching costs a false positive, and false positives
// are what make this finding type untrustworthy.
func normalizeBinary(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	// Strip a trailing version suffix: digits, optionally dot-separated.
	end := len(n)
	for end > 0 {
		c := n[end-1]
		if (c >= '0' && c <= '9') || c == '.' {
			end--
			continue
		}
		break
	}
	// Only strip if something recognizable is left, so "7" or "3.14" alone
	// aren't reduced to nothing.
	if end > 0 {
		return n[:end]
	}
	return n
}

// Analyze compares Observed against Claimed and returns every discrepancy
// found, most severe first. An empty slice means no discrepancy was found —
// it never means correlation didn't run.
func Analyze(o Observed, c Claimed, cfg Config) []Finding {
	var findings []Finding
	findings = append(findings, unclaimedWrites(o, c)...)
	findings = append(findings, claimsWithoutEffect(o, c)...)
	findings = append(findings, outOfBoundsClaims(o, c)...)
	findings = append(findings, sensitiveTouches(o)...)
	findings = append(findings, unclaimedProcesses(o, c, cfg)...)
	findings = append(findings, unexpectedEgress(o, cfg)...)
	sortFindings(findings)
	return findings
}

// unclaimedWrites: a file changed on disk (added, modified, or deleted)
// with no claimed Edit/Write/MultiEdit/NotebookEdit call for that path.
//
// A deletion via a claimed Bash command (e.g. `rm old.txt`) will also
// appear here, since we don't parse Bash argument strings for file targets
// (only for binary names, in unclaimedProcesses). The wording below says
// exactly that — "no claimed edit call" — rather than "never mentioned",
// since the path may well appear inside a claimed command string.
func unclaimedWrites(o Observed, c Claimed) []Finding {
	claimedEdits := claimedEditPaths(c.Claims)

	var entries []snapshot.DiffEntry
	entries = append(entries, o.Diff.Added...)
	entries = append(entries, o.Diff.Modified...)
	entries = append(entries, o.Diff.Deleted...)

	seen := map[string]bool{}
	var out []Finding
	for _, e := range entries {
		abs := resolveDiffPath(o.ProjectDir, e.Path)
		if claimedEdits[abs] || seen[abs] {
			continue
		}
		seen[abs] = true
		out = append(out, Finding{
			Type:     UnclaimedWrite,
			Severity: SeverityMedium,
			Title:    "File changed with no claimed edit",
			Detail: fmt.Sprintf(
				"%s changed on disk, but no claimed Edit, Write, MultiEdit or NotebookEdit call references this path.",
				e.Path,
			),
			Evidence: []string{"path: " + e.Path},
		})
	}
	return out
}

// claimsWithoutEffect: the agent claimed an edit to a path inside the
// project directory, but the file is unchanged on disk.
//
// Scoped strictly to paths under ProjectDir, the only tree we actually
// fingerprint before and after. A claimed edit to a path we never observed
// is not evidence of "no effect" — we simply don't know — so it is left to
// OUT_OF_BOUNDS instead of being asserted here.
func claimsWithoutEffect(o Observed, c Claimed) []Finding {
	changed := changedPaths(o.ProjectDir, o.Diff)

	seen := map[string]bool{}
	var out []Finding
	for _, cl := range c.Claims {
		if cl.Kind != claim.KindEdit {
			continue
		}
		abs := filepath.Clean(cl.Path)
		if !isUnder(abs, o.ProjectDir) {
			continue // out of our observed scope; see OUT_OF_BOUNDS
		}
		if changed[abs] || seen[abs] {
			continue
		}
		seen[abs] = true
		out = append(out, Finding{
			Type:     ClaimWithoutEffect,
			Severity: SeverityLow,
			Title:    "Claimed edit had no observed effect",
			Detail: fmt.Sprintf(
				"The session log claims a %s to %s, but the file is unchanged on disk.",
				cl.Tool, cl.Path,
			),
			Evidence:  []string{"path: " + cl.Path, "tool: " + cl.Tool},
			Timestamp: cl.Timestamp,
		})
	}
	return out
}

// outOfBoundsClaims: a claimed edit targets a path outside the project
// directory.
func outOfBoundsClaims(o Observed, c Claimed) []Finding {
	seen := map[string]bool{}
	var out []Finding
	for _, cl := range c.Claims {
		if cl.Kind != claim.KindEdit {
			continue
		}
		abs := filepath.Clean(cl.Path)
		if isUnder(abs, o.ProjectDir) || seen[abs] {
			continue
		}
		seen[abs] = true
		out = append(out, Finding{
			Type:     OutOfBounds,
			Severity: SeverityHigh,
			Title:    "Claimed edit outside the project directory",
			Detail: fmt.Sprintf(
				"The session log claims a %s to %s, which is outside the project directory (%s).",
				cl.Tool, cl.Path, o.ProjectDir,
			),
			Evidence:  []string{"path: " + cl.Path, "tool: " + cl.Tool},
			Timestamp: cl.Timestamp,
		})
	}
	return out
}

// sensitiveTouches: an observed change to a path on the sensitive
// watchlist. Severity is always HIGH.
func sensitiveTouches(o Observed) []Finding {
	var entries []snapshot.DiffEntry
	entries = append(entries, o.SensitiveDiff.Added...)
	entries = append(entries, o.SensitiveDiff.Modified...)
	entries = append(entries, o.SensitiveDiff.Deleted...)

	var out []Finding
	for _, e := range entries {
		out = append(out, Finding{
			Type:     SensitiveTouch,
			Severity: SeverityHigh,
			Title:    "Change on sensitive path watchlist",
			Detail: fmt.Sprintf(
				"%s changed during this session. This path is on the sensitive watchlist (credentials/config).",
				e.Path,
			),
			Evidence: []string{"path: " + e.Path},
		})
	}
	return out
}

// unclaimedProcesses: a descendant process whose binary name never appears
// in any claimed Bash command.
//
// The claimed-binary set is deliberately generous: every whitespace/pipe/
// &&/;-separated token in every claimed command string counts as
// "mentioned", not just the leading command of each pipeline segment. A
// binary name appearing as an argument (e.g. "xargs rm" mentions rm) still
// counts. This trades a few false negatives for far fewer false positives,
// which is the right tradeoff here: this finding's severity stays MEDIUM
// specifically because false positives are the main quality risk.
//
// Two further filters exist because a real Claude Code session produced 9
// false positives against 1 true finding without them:
//
//   - Unattributable process records (macOS zombies reported as "<defunct>")
//     are dropped: they say a process existed, but not which program it was,
//     so there is nothing to attribute or for a reader to act on.
//   - Agent infrastructure (see AgentInfrastructure) is demoted into a single
//     informational finding rather than one MEDIUM per binary. It is grouped,
//     never hidden: `security` reads the keychain and `gh` holds a GitHub
//     token, so silently whitelisting them would build exactly the blind spot
//     an attacker would want.
func unclaimedProcesses(o Observed, c Claimed, cfg Config) []Finding {
	claimedBinaries := map[string]bool{}
	for _, cl := range c.Claims {
		if cl.Kind != claim.KindCommand {
			continue
		}
		for _, bin := range extractBinaries(cl.Command) {
			claimedBinaries[normalizeBinary(bin)] = true
		}
	}

	agentBinary := normalizeBinary(cfg.AgentBinary)

	counts := map[string]int{}
	infraCounts := map[string]int{}
	for _, p := range o.Processes {
		name := p.Comm
		if name == "" || Unattributable[name] {
			continue
		}
		norm := normalizeBinary(name)
		if ShellWrappers[norm] || claimedBinaries[norm] {
			continue
		}
		if agentBinary != "" && norm == agentBinary {
			continue
		}
		if AgentInfrastructure[norm] {
			infraCounts[name]++
			continue
		}
		counts[name]++
	}

	var out []Finding
	for _, n := range sortedKeys(counts) {
		out = append(out, Finding{
			Type:     UnclaimedProcess,
			Severity: SeverityMedium,
			Title:    fmt.Sprintf("Unclaimed process: %s", n),
			Detail: fmt.Sprintf(
				"%s ran as a descendant process %d time(s), but is not mentioned in any claimed Bash command.",
				n, counts[n],
			),
			Evidence: []string{"binary: " + n, fmt.Sprintf("count: %d", counts[n])},
		})
	}

	if len(infraCounts) > 0 {
		names := sortedKeys(infraCounts)
		total := 0
		evidence := make([]string, 0, len(names))
		for _, n := range names {
			total += infraCounts[n]
			evidence = append(evidence, fmt.Sprintf("%s x%d", n, infraCounts[n]))
		}
		out = append(out, Finding{
			Type:     UnclaimedProcess,
			Severity: SeverityInfo,
			Title:    fmt.Sprintf("Agent infrastructure: %d process(es)", total),
			Detail: "These are processes coding agents routinely spawn for their own " +
				"machinery (keychain access, sleep prevention, shell environment " +
				"snapshots), not attributable to any claimed command. Grouped rather " +
				"than hidden, since some of them hold real credentials.",
			Evidence: evidence,
		})
	}
	return out
}

func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// unexpectedEgress: a descendant process connected to a host outside the
// configured allowlist. With no observed connections (network sampling
// disabled, or unavailable) this simply produces nothing.
func unexpectedEgress(o Observed, cfg Config) []Finding {
	seen := map[string]bool{}
	var out []Finding
	for _, conn := range o.Connections {
		if cfg.AllowedHosts[conn.RemoteHost] || seen[conn.RemoteHost] {
			continue
		}
		seen[conn.RemoteHost] = true
		out = append(out, Finding{
			Type:     UnexpectedEgress,
			Severity: SeverityHigh,
			Title:    fmt.Sprintf("Unexpected network egress to %s", conn.RemoteHost),
			Detail: fmt.Sprintf(
				"A descendant process connected to %s:%d, which is not on the configured allowlist.",
				conn.RemoteHost, conn.RemotePort,
			),
			Evidence:  []string{"host: " + conn.RemoteHost, fmt.Sprintf("port: %d", conn.RemotePort), fmt.Sprintf("pid: %d", conn.PID)},
			Timestamp: conn.Observed,
		})
	}
	return out
}

// --- shared helpers ---

// claimedEditPaths returns the set of absolute, cleaned paths claimed via
// Edit, Write, MultiEdit or NotebookEdit.
func claimedEditPaths(claims []claim.Claim) map[string]bool {
	set := map[string]bool{}
	for _, cl := range claims {
		if cl.Kind == claim.KindEdit {
			set[filepath.Clean(cl.Path)] = true
		}
	}
	return set
}

// changedPaths returns the set of absolute paths that changed in any way
// (added, modified or deleted) according to diff.
func changedPaths(projectDir string, diff snapshot.DiffResult) map[string]bool {
	set := map[string]bool{}
	for _, e := range diff.Added {
		set[resolveDiffPath(projectDir, e.Path)] = true
	}
	for _, e := range diff.Modified {
		set[resolveDiffPath(projectDir, e.Path)] = true
	}
	for _, e := range diff.Deleted {
		set[resolveDiffPath(projectDir, e.Path)] = true
	}
	return set
}

// resolveDiffPath turns a snapshot.DiffEntry's project-relative, slash-style
// path back into an absolute, OS-native, cleaned path comparable against a
// claim's (already absolute) file_path.
func resolveDiffPath(projectDir, relPath string) string {
	return filepath.Clean(filepath.Join(projectDir, filepath.FromSlash(relPath)))
}

// isUnder reports whether path is root itself or nested under it.
func isUnder(path, root string) bool {
	cleanRoot := filepath.Clean(root)
	cleanPath := filepath.Clean(path)
	if cleanPath == cleanRoot {
		return true
	}
	rel, err := filepath.Rel(cleanRoot, cleanPath)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// extractBinaries tokenizes a claimed Bash command string into candidate
// binary names: split on pipes, &&, ;, and whitespace, then take each
// token's base name (so "/usr/bin/python3" and "python3" match the same
// process Comm).
func extractBinaries(command string) []string {
	normalized := shellSeparators.Replace(command)
	fields := strings.Fields(normalized)

	seen := map[string]bool{}
	var out []string
	for _, f := range fields {
		base := filepath.Base(f)
		if base == "" || base == "." || base == string(filepath.Separator) || seen[base] {
			continue
		}
		seen[base] = true
		out = append(out, base)
	}
	return out
}

var shellSeparators = strings.NewReplacer("|", " ", "&&", " ", ";", " ")

// sortFindings orders results deterministically: most severe first, then by
// type, then by title. Presentation grouping is internal/report's concern.
func sortFindings(f []Finding) {
	rank := map[Severity]int{SeverityHigh: 0, SeverityMedium: 1, SeverityLow: 2, SeverityInfo: 3}
	sort.SliceStable(f, func(i, j int) bool {
		if rank[f[i].Severity] != rank[f[j].Severity] {
			return rank[f[i].Severity] < rank[f[j].Severity]
		}
		if f[i].Type != f[j].Type {
			return f[i].Type < f[j].Type
		}
		return f[i].Title < f[j].Title
	})
}
