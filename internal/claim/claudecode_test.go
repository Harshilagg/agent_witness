package claim

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeSessionFile writes one .jsonl file with the given raw lines (already
// JSON-encoded strings, or literal garbage for malformed-line tests) and
// sets its mtime so candidateFiles' coarse mtime filter finds it.
func writeSessionFile(t *testing.T, path string, lines []string, mtime time.Time) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	content := ""
	for _, l := range lines {
		content += l + "\n"
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatal(err)
	}
}

func assistantLine(t *testing.T, cwd string, ts time.Time, blocks ...map[string]any) string {
	t.Helper()
	content := make([]any, len(blocks))
	for i, b := range blocks {
		content[i] = b
	}
	rec := map[string]any{
		"type": "assistant",
		"cwd":  cwd,
		"message": map[string]any{
			"content": content,
		},
	}
	if !ts.IsZero() {
		rec["timestamp"] = ts.UTC().Format("2006-01-02T15:04:05.000Z")
	}
	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func toolUse(name string, input map[string]any) map[string]any {
	return map[string]any{"type": "tool_use", "name": name, "input": input}
}

func TestParse_MalformedLineIsSkippedNotFatal(t *testing.T) {
	home := t.TempDir()
	base := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	sessDir := filepath.Join(home, ".claude", "projects", "-proj")
	valid := assistantLine(t, "/proj", base.Add(time.Minute),
		toolUse("Bash", map[string]any{"command": "echo hi"}))

	writeSessionFile(t, filepath.Join(sessDir, "s.jsonl"), []string{
		`{not valid json at all`,
		valid,
		`{"type": "assistant", "message": "not-an-object"}`, // wrong shape, not garbage
	}, base.Add(2*time.Minute))

	res := ClaudeCode{HomeDir: home}.Parse("/proj", base, base.Add(time.Hour))

	if !res.Available {
		t.Fatalf("Available = false, want true; notes=%v", res.Notes)
	}
	if res.SkippedLines != 1 {
		t.Fatalf("SkippedLines = %d, want 1 (only the truly malformed JSON line)", res.SkippedLines)
	}
	if len(res.Claims) != 1 || res.Claims[0].Kind != KindCommand || res.Claims[0].Command != "echo hi" {
		t.Fatalf("Claims = %+v, want one Bash command claim despite the malformed line", res.Claims)
	}
}

func TestParse_ToolUseKindMapping(t *testing.T) {
	home := t.TempDir()
	base := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	sessDir := filepath.Join(home, ".claude", "projects", "-proj")

	line := assistantLine(t, "/proj", base.Add(time.Minute),
		toolUse("Edit", map[string]any{"file_path": "/proj/a.go", "old_string": "x", "new_string": "y"}),
		toolUse("Write", map[string]any{"file_path": "/proj/b.go", "content": "package b"}),
		toolUse("MultiEdit", map[string]any{"file_path": "/proj/c.go"}),
		toolUse("NotebookEdit", map[string]any{"file_path": "/proj/d.ipynb"}),
		toolUse("Read", map[string]any{"file_path": "/proj/e.go"}),
		toolUse("Bash", map[string]any{"command": "go test ./..."}),
		toolUse("AskUserQuestion", map[string]any{"questions": []any{}}), // unknown tool, must be ignored
	)
	writeSessionFile(t, filepath.Join(sessDir, "s.jsonl"), []string{line}, base.Add(2*time.Minute))

	res := ClaudeCode{HomeDir: home}.Parse("/proj", base, base.Add(time.Hour))
	if !res.Available {
		t.Fatalf("Available = false, want true; notes=%v", res.Notes)
	}
	if len(res.Claims) != 6 {
		t.Fatalf("got %d claims, want 6 (AskUserQuestion must be excluded): %+v", len(res.Claims), res.Claims)
	}

	want := map[string]Kind{
		"/proj/a.go":    KindEdit,
		"/proj/b.go":    KindEdit,
		"/proj/c.go":    KindEdit,
		"/proj/d.ipynb": KindEdit,
		"/proj/e.go":    KindRead,
	}
	for _, c := range res.Claims {
		if c.Kind == KindCommand {
			if c.Command != "go test ./..." {
				t.Errorf("command claim = %q, want %q", c.Command, "go test ./...")
			}
			continue
		}
		wantKind, ok := want[c.Path]
		if !ok {
			t.Errorf("unexpected claim path %q", c.Path)
			continue
		}
		if c.Kind != wantKind {
			t.Errorf("claim for %q: Kind = %v, want %v", c.Path, c.Kind, wantKind)
		}
	}
}

func TestParse_FiltersToSessionWindow(t *testing.T) {
	home := t.TempDir()
	base := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	start := base
	end := base.Add(10 * time.Minute)
	sessDir := filepath.Join(home, ".claude", "projects", "-proj")

	before := assistantLine(t, "/proj", base.Add(-time.Hour),
		toolUse("Bash", map[string]any{"command": "echo before"}))
	inside := assistantLine(t, "/proj", base.Add(5*time.Minute),
		toolUse("Bash", map[string]any{"command": "echo inside"}))
	after := assistantLine(t, "/proj", base.Add(2*time.Hour),
		toolUse("Bash", map[string]any{"command": "echo after"}))

	writeSessionFile(t, filepath.Join(sessDir, "s.jsonl"), []string{before, inside, after}, base.Add(3*time.Hour))

	res := ClaudeCode{HomeDir: home}.Parse("/proj", start, end)
	if !res.Available {
		t.Fatalf("Available = false, want true; notes=%v", res.Notes)
	}
	if len(res.Claims) != 1 || res.Claims[0].Command != "echo inside" {
		t.Fatalf("Claims = %+v, want exactly the one claim inside [start,end]", res.Claims)
	}
}

func TestParse_CWDMatchingAcceptsSubdirectory(t *testing.T) {
	home := t.TempDir()
	base := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	sessDir := filepath.Join(home, ".claude", "projects", "-proj")

	// The recorded cwd is a subdirectory of the project, as Claude Code
	// produces when the agent cd's into a package within a monorepo.
	line := assistantLine(t, "/proj/pkg/sub", base.Add(time.Minute),
		toolUse("Bash", map[string]any{"command": "go build ./..."}))
	writeSessionFile(t, filepath.Join(sessDir, "s.jsonl"), []string{line}, base.Add(2*time.Minute))

	res := ClaudeCode{HomeDir: home}.Parse("/proj", base, base.Add(time.Hour))
	if !res.Available || len(res.Claims) != 1 {
		t.Fatalf("res = %+v, want one claim matched via subdirectory cwd", res)
	}
}

func TestParse_UnrelatedProjectCWDIsExcluded(t *testing.T) {
	home := t.TempDir()
	base := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	sessDir := filepath.Join(home, ".claude", "projects", "-other")

	line := assistantLine(t, "/some/other/project", base.Add(time.Minute),
		toolUse("Bash", map[string]any{"command": "echo unrelated"}))
	writeSessionFile(t, filepath.Join(sessDir, "s.jsonl"), []string{line}, base.Add(2*time.Minute))

	res := ClaudeCode{HomeDir: home}.Parse("/proj", base, base.Add(time.Hour))
	if res.Available {
		t.Fatalf("Available = true, want false: a log for an unrelated project must not be used; claims=%+v", res.Claims)
	}
}

func TestParse_MultipleFilesMergedAndSorted(t *testing.T) {
	home := t.TempDir()
	base := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	sessDir := filepath.Join(home, ".claude", "projects", "-proj")

	line1 := assistantLine(t, "/proj", base.Add(5*time.Minute),
		toolUse("Bash", map[string]any{"command": "second"}))
	line2 := assistantLine(t, "/proj", base.Add(1*time.Minute),
		toolUse("Bash", map[string]any{"command": "first"}))

	writeSessionFile(t, filepath.Join(sessDir, "a.jsonl"), []string{line1}, base.Add(6*time.Minute))
	writeSessionFile(t, filepath.Join(sessDir, "b.jsonl"), []string{line2}, base.Add(2*time.Minute))

	res := ClaudeCode{HomeDir: home}.Parse("/proj", base, base.Add(time.Hour))
	if len(res.Files) != 2 {
		t.Fatalf("Files = %v, want both session files used", res.Files)
	}
	if len(res.Claims) != 2 || res.Claims[0].Command != "first" || res.Claims[1].Command != "second" {
		t.Fatalf("Claims = %+v, want [first, second] sorted by timestamp across files", res.Claims)
	}
}

func TestParse_NoSessionDirectory(t *testing.T) {
	home := t.TempDir() // no .claude/projects at all
	base := time.Now()

	res := ClaudeCode{HomeDir: home}.Parse("/proj", base, base.Add(time.Hour))
	if res.Available {
		t.Fatalf("Available = true, want false when there is no Claude Code session directory")
	}
	if len(res.Notes) == 0 {
		t.Fatalf("Notes is empty, want an explanation of why claims are unavailable")
	}
}

func TestCwdUnder(t *testing.T) {
	tests := []struct {
		name string
		cwd  string
		root string
		want bool
	}{
		{"exact match", "/proj", "/proj", true},
		{"subdirectory", "/proj/pkg/sub", "/proj", true},
		{"unrelated sibling", "/projects-archive", "/proj", false},
		{"parent of root, not under it", "/", "/proj", false},
		{"completely different tree", "/var/tmp", "/proj", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := cwdUnder(tt.cwd, tt.root); got != tt.want {
				t.Errorf("cwdUnder(%q, %q) = %v, want %v", tt.cwd, tt.root, got, tt.want)
			}
		})
	}
}
