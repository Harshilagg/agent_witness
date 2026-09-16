package claim

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// mtimeSlack accounts for clock differences between our own StartedAt and
// the moment Claude Code last flushed its session log to disk. It only
// widens the coarse file-selection pass; the actual claims are still bounded
// precisely by each record's own timestamp.
const mtimeSlack = 2 * time.Minute

// ClaudeCode reads session logs written by the Claude Code CLI.
//
// Logs live at ~/.claude/projects/<mangled-cwd>/*.jsonl. Rather than trust
// the path mangling scheme (which is undocumented and has changed before),
// we scan every project directory's *.jsonl files modified around the
// session window and confirm the match by reading the `cwd` field recorded
// inside the log itself.
type ClaudeCode struct {
	// HomeDir overrides os.UserHomeDir, for tests. Empty means use the real
	// home directory.
	HomeDir string
}

func (ClaudeCode) Name() string { return "claude-code" }

func (c ClaudeCode) Parse(projectDir string, start, end time.Time) Result {
	res := Result{Source: "claude-code"}

	home := c.HomeDir
	if home == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			res.Notes = append(res.Notes, "claim unavailable: could not determine home directory: "+err.Error())
			return res
		}
		home = h
	}

	absProjectDir, err := filepath.Abs(projectDir)
	if err != nil {
		absProjectDir = projectDir
	}

	projectsDir := filepath.Join(home, ".claude", "projects")
	projectEntries, err := os.ReadDir(projectsDir)
	if err != nil {
		res.Notes = append(res.Notes, "claim unavailable: no Claude Code session directory found at "+projectsDir)
		return res
	}

	candidates := candidateFiles(projectsDir, projectEntries, start)
	if len(candidates) == 0 {
		res.Notes = append(res.Notes, "claim unavailable: no Claude Code session log was modified during this run")
		return res
	}

	var (
		usedFiles     []string
		allClaims     []Claim
		skippedLines  int
		untimestamped int
	)
	for _, f := range candidates {
		lr := parseSessionFile(f)
		skippedLines += lr.skipped
		if !lr.matchedCWD(absProjectDir) {
			continue
		}
		usedFiles = append(usedFiles, f)
		for _, cl := range lr.claims {
			if cl.Timestamp.IsZero() {
				untimestamped++
				continue
			}
			// This is the core correctness guard: a Claude Code session log
			// can span many days of unrelated work in the same project. Only
			// claims whose own timestamp falls inside this run's window
			// belong to it.
			if cl.Timestamp.Before(start) || cl.Timestamp.After(end) {
				continue
			}
			allClaims = append(allClaims, cl)
		}
	}

	if len(usedFiles) == 0 {
		res.Notes = append(res.Notes, "claim unavailable: no session log's cwd matched this project directory")
		return res
	}

	sort.Slice(allClaims, func(i, j int) bool { return allClaims[i].Timestamp.Before(allClaims[j].Timestamp) })
	sort.Strings(usedFiles)

	res.Available = true
	res.Files = usedFiles
	res.Claims = allClaims
	res.SkippedLines = skippedLines
	if skippedLines > 0 {
		res.Notes = append(res.Notes, fmt.Sprintf("%d malformed or unrecognized session log line(s) were skipped", skippedLines))
	}
	if untimestamped > 0 {
		res.Notes = append(res.Notes, fmt.Sprintf("%d claim(s) without a parseable timestamp were excluded", untimestamped))
	}
	return res
}

// candidateFiles returns every *.jsonl file, across every project directory,
// whose mtime suggests it could have been written during this session. This
// is a coarse, cheap first pass only; the real filter is matchedCWD plus
// each claim's own timestamp.
func candidateFiles(projectsDir string, entries []os.DirEntry, start time.Time) []string {
	cutoff := start.Add(-mtimeSlack)
	var out []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		matches, err := filepath.Glob(filepath.Join(projectsDir, e.Name(), "*.jsonl"))
		if err != nil {
			continue
		}
		for _, f := range matches {
			info, err := os.Stat(f)
			if err != nil {
				continue // file disappeared or is unreadable; skip, don't fail
			}
			if info.ModTime().Before(cutoff) {
				continue
			}
			out = append(out, f)
		}
	}
	sort.Strings(out)
	return out
}

// lineResult is what one session log file yields: every claim found in it
// (regardless of window — that filtering happens by the caller), whether any
// record's cwd matched the project we're looking for, and how many lines
// couldn't be parsed at all.
type lineResult struct {
	claims  []Claim
	cwds    map[string]bool
	skipped int
}

func (lr lineResult) matchedCWD(absProjectDir string) bool {
	for cwd := range lr.cwds {
		if cwdUnder(cwd, absProjectDir) {
			return true
		}
	}
	return false
}

// parseSessionFile reads one *.jsonl file line by line. Every line is parsed
// independently: a malformed line increments skipped and the scan continues,
// it never aborts the file or panics.
func parseSessionFile(path string) lineResult {
	lr := lineResult{cwds: map[string]bool{}}

	f, err := os.Open(path)
	if err != nil {
		return lr
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	// Session log lines can be large (tool inputs can embed sizeable text);
	// the default 64KiB scanner limit is not enough.
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)

	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}

		var rec map[string]any
		if err := json.Unmarshal(line, &rec); err != nil {
			lr.skipped++
			continue
		}
		if cwd, ok := rec["cwd"].(string); ok && cwd != "" {
			lr.cwds[cwd] = true
		}

		claims, ok := claimsFromRecord(rec)
		if !ok {
			// Not an error: most lines (attachments, headers, user turns,
			// bridge/session bookkeeping) simply carry no claim.
			continue
		}
		lr.claims = append(lr.claims, claims...)
	}
	// A scanner failure (e.g. a line longer than our buffer) degrades to
	// "some lines were unreadable", not a failed parse of the whole file.
	if err := scanner.Err(); err != nil {
		lr.skipped++
	}
	return lr
}

// claimsFromRecord extracts every tool_use claim from one assistant message
// record. The second return value is false when rec isn't a well-formed
// assistant message at all, as opposed to one that legitimately made no
// tool calls.
func claimsFromRecord(rec map[string]any) ([]Claim, bool) {
	if t, _ := rec["type"].(string); t != "assistant" {
		return nil, false
	}
	msg, ok := rec["message"].(map[string]any)
	if !ok {
		return nil, false
	}
	content, ok := msg["content"].([]any)
	if !ok {
		return nil, false
	}
	ts, _ := parseTimestamp(rec["timestamp"])

	var claims []Claim
	for _, blockAny := range content {
		block, ok := blockAny.(map[string]any)
		if !ok {
			continue
		}
		if bt, _ := block["type"].(string); bt != "tool_use" {
			continue
		}
		name, _ := block["name"].(string)
		input, _ := block["input"].(map[string]any)
		cl, ok := claimFromToolUse(name, input)
		if !ok {
			continue
		}
		cl.Timestamp = ts
		claims = append(claims, cl)
	}
	return claims, true
}

// claimFromToolUse maps one tool_use block's name/input to a Claim. Unknown
// tool names (AskUserQuestion, WebFetch, Agent, ToolSearch, ...) are not
// claims we correlate against observed state and are skipped deliberately,
// not as a parsing failure.
func claimFromToolUse(name string, input map[string]any) (Claim, bool) {
	switch name {
	case "Edit", "Write", "MultiEdit", "NotebookEdit":
		path, ok := stringField(input, "file_path")
		if !ok {
			return Claim{}, false
		}
		return Claim{Kind: KindEdit, Tool: name, Path: path}, true
	case "Read":
		path, ok := stringField(input, "file_path")
		if !ok {
			return Claim{}, false
		}
		return Claim{Kind: KindRead, Tool: name, Path: path}, true
	case "Bash":
		cmd, ok := stringField(input, "command")
		if !ok {
			return Claim{}, false
		}
		return Claim{Kind: KindCommand, Tool: name, Command: cmd}, true
	default:
		return Claim{}, false
	}
}

func stringField(m map[string]any, key string) (string, bool) {
	v, ok := m[key].(string)
	if !ok || v == "" {
		return "", false
	}
	return v, true
}

// parseTimestamp parses the RFC3339-with-milliseconds timestamps Claude Code
// writes (e.g. "2026-08-29T13:22:59.112Z"). RFC3339Nano's fractional digits
// are optional, so it also accepts a bare RFC3339 value if the format ever
// drops the milliseconds.
func parseTimestamp(v any) (time.Time, bool) {
	s, ok := v.(string)
	if !ok || s == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// cwdUnder reports whether cwd is the project root itself or a subdirectory
// of it. Claude Code's `cwd` field can be a subdirectory (e.g. the agent cd's
// into a package within a monorepo), so exact equality alone is too strict.
func cwdUnder(cwd, absProjectDir string) bool {
	absCwd, err := filepath.Abs(cwd)
	if err != nil {
		absCwd = cwd
	}
	absCwd = filepath.Clean(absCwd)
	root := filepath.Clean(absProjectDir)

	if absCwd == root {
		return true
	}
	rel, err := filepath.Rel(root, absCwd)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
