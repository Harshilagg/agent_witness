package correlate

import (
	"testing"
	"time"

	"github.com/harshilaggarwal/agentwitness/internal/claim"
	"github.com/harshilaggarwal/agentwitness/internal/procs"
	"github.com/harshilaggarwal/agentwitness/internal/snapshot"
)

const projectDir = "/home/user/project"

func diffEntry(path string) snapshot.DiffEntry {
	return snapshot.DiffEntry{Path: path}
}

func findingsOfType(findings []Finding, t FindingType) []Finding {
	var out []Finding
	for _, f := range findings {
		if f.Type == t {
			out = append(out, f)
		}
	}
	return out
}

// TestHeadlineCase is the scenario the whole project exists for: a
// subprocess writes a file that the agent's session log never mentions.
func TestHeadlineCase_SubprocessWriteNeverClaimed(t *testing.T) {
	o := Observed{
		ProjectDir: projectDir,
		Diff: snapshot.DiffResult{
			Added: []snapshot.DiffEntry{diffEntry("evidence.txt")},
		},
		Processes: []procs.Proc{
			{PID: 42, Comm: "python3"},
		},
	}
	c := Claimed{
		Claims: []claim.Claim{
			// The agent's log only shows a Bash call that (as far as the log
			// is concerned) did nothing to evidence.txt — e.g. it ran a
			// script that, unbeknownst to the log, itself spawned python3
			// which did the actual writing.
			{Kind: claim.KindCommand, Tool: "Bash", Command: "./run.sh"},
		},
	}

	findings := Analyze(o, c, Config{})

	writes := findingsOfType(findings, UnclaimedWrite)
	if len(writes) != 1 || writes[0].Evidence[0] != "path: evidence.txt" {
		t.Fatalf("UNCLAIMED_WRITE findings = %+v, want exactly one for evidence.txt", writes)
	}

	procsFindings := findingsOfType(findings, UnclaimedProcess)
	if len(procsFindings) != 1 {
		t.Fatalf("UNCLAIMED_PROCESS findings = %+v, want exactly one for python3", procsFindings)
	}
	if procsFindings[0].Severity != SeverityMedium {
		t.Errorf("UNCLAIMED_PROCESS severity = %v, want MEDIUM", procsFindings[0].Severity)
	}
}

func TestUnclaimedWrite_MatchedClaimSuppressesFinding(t *testing.T) {
	o := Observed{
		ProjectDir: projectDir,
		Diff: snapshot.DiffResult{
			Modified: []snapshot.DiffEntry{diffEntry("main.go")},
		},
	}
	c := Claimed{
		Claims: []claim.Claim{
			{Kind: claim.KindEdit, Tool: "Edit", Path: "/home/user/project/main.go"},
		},
	}

	findings := Analyze(o, c, Config{})
	if got := findingsOfType(findings, UnclaimedWrite); len(got) != 0 {
		t.Fatalf("UNCLAIMED_WRITE = %+v, want none: the edit was claimed", got)
	}
}

func TestClaimWithoutEffect(t *testing.T) {
	o := Observed{
		ProjectDir: projectDir,
		Diff:       snapshot.DiffResult{}, // nothing actually changed
	}
	c := Claimed{
		Claims: []claim.Claim{
			{Kind: claim.KindEdit, Tool: "Write", Path: "/home/user/project/unchanged.go", Timestamp: time.Unix(100, 0)},
		},
	}

	findings := Analyze(o, c, Config{})
	got := findingsOfType(findings, ClaimWithoutEffect)
	if len(got) != 1 {
		t.Fatalf("CLAIM_WITHOUT_EFFECT = %+v, want exactly one", got)
	}
	if got[0].Severity != SeverityLow {
		t.Errorf("severity = %v, want LOW", got[0].Severity)
	}
	if got[0].Timestamp.Unix() != 100 {
		t.Errorf("Timestamp not propagated from the claim")
	}
}

func TestClaimWithoutEffect_OutOfScopePathNotAsserted(t *testing.T) {
	// A claimed edit to a path outside the project directory must NOT be
	// asserted to have "no effect" — we never fingerprinted it, so we
	// genuinely don't know. Overstating this would violate the "never
	// overstate what we observed" constraint.
	o := Observed{ProjectDir: projectDir}
	c := Claimed{
		Claims: []claim.Claim{
			{Kind: claim.KindEdit, Tool: "Write", Path: "/etc/hosts"},
		},
	}

	findings := Analyze(o, c, Config{})
	if got := findingsOfType(findings, ClaimWithoutEffect); len(got) != 0 {
		t.Fatalf("CLAIM_WITHOUT_EFFECT = %+v, want none for an out-of-scope path", got)
	}
	if got := findingsOfType(findings, OutOfBounds); len(got) != 1 {
		t.Fatalf("OUT_OF_BOUNDS = %+v, want exactly one for /etc/hosts", got)
	}
}

func TestOutOfBounds(t *testing.T) {
	o := Observed{ProjectDir: projectDir}
	c := Claimed{
		Claims: []claim.Claim{
			{Kind: claim.KindEdit, Tool: "Write", Path: "/home/user/.ssh/authorized_keys"},
			{Kind: claim.KindEdit, Tool: "Edit", Path: "/home/user/project/main.go"}, // in bounds
		},
	}

	findings := Analyze(o, c, Config{})
	got := findingsOfType(findings, OutOfBounds)
	if len(got) != 1 {
		t.Fatalf("OUT_OF_BOUNDS = %+v, want exactly one (the in-project edit must not appear)", got)
	}
	if got[0].Severity != SeverityHigh {
		t.Errorf("severity = %v, want HIGH", got[0].Severity)
	}
}

func TestSensitiveTouch(t *testing.T) {
	o := Observed{
		ProjectDir: projectDir,
		SensitiveDiff: snapshot.DiffResult{
			Modified: []snapshot.DiffEntry{diffEntry("/home/user/.ssh/authorized_keys")},
		},
	}

	findings := Analyze(o, Claimed{}, Config{})
	got := findingsOfType(findings, SensitiveTouch)
	if len(got) != 1 {
		t.Fatalf("SENSITIVE_TOUCH = %+v, want exactly one", got)
	}
	if got[0].Severity != SeverityHigh {
		t.Errorf("severity = %v, want HIGH", got[0].Severity)
	}
	// SENSITIVE_TOUCH must be the highest-ranked finding in the output.
	if findings[0].Type != SensitiveTouch && findings[0].Severity != SeverityHigh {
		t.Errorf("expected a HIGH severity finding first, got %+v", findings[0])
	}
}

func TestUnclaimedProcess(t *testing.T) {
	o := Observed{
		ProjectDir: projectDir,
		Processes: []procs.Proc{
			{PID: 1, Comm: "curl"},
			{PID: 2, Comm: "curl"}, // same binary twice -> one grouped finding with count 2
			{PID: 3, Comm: "sh"},   // shell wrapper, excluded
			{PID: 4, Comm: "go"},   // claimed via "go test ./..."
		},
	}
	c := Claimed{
		Claims: []claim.Claim{
			{Kind: claim.KindCommand, Tool: "Bash", Command: "go test ./..."},
		},
	}

	findings := Analyze(o, c, Config{})
	got := findingsOfType(findings, UnclaimedProcess)
	if len(got) != 1 {
		t.Fatalf("UNCLAIMED_PROCESS = %+v, want exactly one grouped finding for curl", got)
	}
	if got[0].Title != "Unclaimed process: curl" {
		t.Errorf("Title = %q, want to name curl", got[0].Title)
	}
	if got[0].Evidence[1] != "count: 2" {
		t.Errorf("Evidence = %v, want count: 2", got[0].Evidence)
	}
	if got[0].Severity != SeverityMedium {
		t.Errorf("severity = %v, want MEDIUM", got[0].Severity)
	}
}

func TestUnclaimedProcess_TokenMentionedAnywhereCounts(t *testing.T) {
	// "rm" appears only as an argument to xargs, not as a pipeline's own
	// leading command, but the spec's "mentioned anywhere" wording means it
	// still counts as claimed — this favors false negatives over false
	// positives, which is the documented tradeoff.
	o := Observed{
		Processes: []procs.Proc{{PID: 1, Comm: "rm"}},
	}
	c := Claimed{
		Claims: []claim.Claim{
			{Kind: claim.KindCommand, Tool: "Bash", Command: "find . -name '*.tmp' | xargs rm"},
		},
	}

	findings := Analyze(o, c, Config{})
	if got := findingsOfType(findings, UnclaimedProcess); len(got) != 0 {
		t.Fatalf("UNCLAIMED_PROCESS = %+v, want none: rm is mentioned in the claimed command", got)
	}
}

func TestUnclaimedProcess_AgentBinaryExcluded(t *testing.T) {
	o := Observed{
		Processes: []procs.Proc{{PID: 1, Comm: "claude"}},
	}
	findings := Analyze(o, Claimed{}, Config{AgentBinary: "claude"})
	if got := findingsOfType(findings, UnclaimedProcess); len(got) != 0 {
		t.Fatalf("UNCLAIMED_PROCESS = %+v, want none: claude is the configured agent binary", got)
	}
}

func TestUnexpectedEgress(t *testing.T) {
	o := Observed{
		Connections: []Connection{
			{RemoteHost: "allowed.example.com", RemotePort: 443, PID: 10},
			{RemoteHost: "evil.example.com", RemotePort: 443, PID: 11},
		},
	}
	cfg := Config{AllowedHosts: map[string]bool{"allowed.example.com": true}}

	findings := Analyze(o, Claimed{}, cfg)
	got := findingsOfType(findings, UnexpectedEgress)
	if len(got) != 1 {
		t.Fatalf("UNEXPECTED_EGRESS = %+v, want exactly one (evil.example.com only)", got)
	}
	if got[0].Evidence[0] != "host: evil.example.com" {
		t.Errorf("Evidence = %v, want to name evil.example.com", got[0].Evidence)
	}
	if got[0].Severity != SeverityHigh {
		t.Errorf("severity = %v, want HIGH", got[0].Severity)
	}
}

func TestUnexpectedEgress_NoConnectionsProducesNothing(t *testing.T) {
	// Network sampling disabled/unavailable: Observed.Connections is empty,
	// and this must never be misread as "every host was unexpected".
	findings := Analyze(Observed{}, Claimed{}, Config{})
	if got := findingsOfType(findings, UnexpectedEgress); len(got) != 0 {
		t.Fatalf("UNEXPECTED_EGRESS = %+v, want none with no observed connections", got)
	}
}

func TestAnalyze_NoDiscrepanciesProducesEmptySlice(t *testing.T) {
	o := Observed{
		ProjectDir: projectDir,
		Diff: snapshot.DiffResult{
			Modified: []snapshot.DiffEntry{diffEntry("main.go")},
		},
		Processes: []procs.Proc{{PID: 1, Comm: "go"}},
	}
	c := Claimed{
		Claims: []claim.Claim{
			{Kind: claim.KindEdit, Tool: "Edit", Path: "/home/user/project/main.go"},
			{Kind: claim.KindCommand, Tool: "Bash", Command: "go build ./..."},
		},
	}

	findings := Analyze(o, c, Config{})
	if len(findings) != 0 {
		t.Fatalf("findings = %+v, want none: everything observed was claimed", findings)
	}
}

func TestSortFindings_MostSevereFirst(t *testing.T) {
	o := Observed{
		ProjectDir: projectDir,
		Diff: snapshot.DiffResult{
			Added: []snapshot.DiffEntry{diffEntry("unclaimed.txt")}, // MEDIUM
		},
		SensitiveDiff: snapshot.DiffResult{
			Modified: []snapshot.DiffEntry{diffEntry("/home/user/.ssh/config")}, // HIGH
		},
	}
	c := Claimed{
		Claims: []claim.Claim{
			{Kind: claim.KindEdit, Tool: "Write", Path: "/home/user/project/noeffect.txt"}, // LOW
		},
	}

	findings := Analyze(o, c, Config{})
	if len(findings) < 3 {
		t.Fatalf("expected at least 3 findings, got %+v", findings)
	}
	for i := 1; i < len(findings); i++ {
		rank := map[Severity]int{SeverityHigh: 0, SeverityMedium: 1, SeverityLow: 2}
		if rank[findings[i-1].Severity] > rank[findings[i].Severity] {
			t.Fatalf("findings not sorted by severity: %+v", findings)
		}
	}
	if findings[0].Severity != SeverityHigh {
		t.Errorf("first finding severity = %v, want HIGH", findings[0].Severity)
	}
}

func TestExtractBinaries(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    []string
	}{
		{
			name:    "pipe separated",
			command: "cat file.txt | grep foo",
			want:    []string{"cat", "file.txt", "grep", "foo"},
		},
		{
			name:    "and-and separated",
			command: "go build ./... && go test ./...",
			want:    []string{"go", "build", "...", "test"},
		},
		{
			name:    "semicolon separated",
			command: "echo hi; echo bye",
			want:    []string{"echo", "hi", "bye"},
		},
		{
			name:    "absolute path reduces to basename",
			command: "/usr/bin/python3 script.py",
			want:    []string{"python3", "script.py"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractBinaries(tt.command)
			gotSet := map[string]bool{}
			for _, g := range got {
				gotSet[g] = true
			}
			for _, w := range tt.want {
				if !gotSet[w] {
					t.Errorf("extractBinaries(%q) = %v, missing %q", tt.command, got, w)
				}
			}
		})
	}
}

func TestIsUnder(t *testing.T) {
	tests := []struct {
		name string
		path string
		root string
		want bool
	}{
		{"exact", "/proj", "/proj", true},
		{"nested", "/proj/pkg/file.go", "/proj", true},
		{"sibling", "/proj-other/file.go", "/proj", false},
		{"parent", "/", "/proj", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isUnder(tt.path, tt.root); got != tt.want {
				t.Errorf("isUnder(%q, %q) = %v, want %v", tt.path, tt.root, got, tt.want)
			}
		})
	}
}
