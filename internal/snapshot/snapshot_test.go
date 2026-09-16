package snapshot

import (
	"testing"
	"time"
)

func fp(digest string, size int64, mod time.Time, metaOnly bool) Fingerprint {
	return Fingerprint{Digest: digest, Size: size, ModTime: mod, MetaOnly: metaOnly}
}

func TestDiff(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Hour)

	before := Result{Files: map[string]Fingerprint{
		"unchanged.txt": fp("aaa", 10, t0, false),
		"modified.txt":  fp("bbb", 20, t0, false),
		"deleted.txt":   fp("ccc", 30, t0, false),
	}}
	after := Result{Files: map[string]Fingerprint{
		"unchanged.txt": fp("aaa", 10, t0, false),
		"modified.txt":  fp("bbb2", 25, t1, false),
		"added.txt":     fp("ddd", 40, t1, false),
	}}

	d := Diff(before, after)

	if len(d.Added) != 1 || d.Added[0].Path != "added.txt" {
		t.Fatalf("Added = %+v, want [added.txt]", d.Added)
	}
	if len(d.Modified) != 1 || d.Modified[0].Path != "modified.txt" {
		t.Fatalf("Modified = %+v, want [modified.txt]", d.Modified)
	}
	if len(d.Deleted) != 1 || d.Deleted[0].Path != "deleted.txt" {
		t.Fatalf("Deleted = %+v, want [deleted.txt]", d.Deleted)
	}
	// unchanged.txt must not appear anywhere.
	for _, list := range [][]DiffEntry{d.Added, d.Modified, d.Deleted} {
		for _, e := range list {
			if e.Path == "unchanged.txt" {
				t.Fatalf("unchanged.txt unexpectedly appeared in diff: %+v", e)
			}
		}
	}
}

func TestDiff_MetaOnlyPropagation(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Minute)

	tests := []struct {
		name         string
		before       Fingerprint
		after        Fingerprint
		wantChanged  bool
		wantMetaOnly bool
	}{
		{
			name:         "meta-only file with changed size is modified and flagged",
			before:       fp("", 100, t0, true),
			after:        fp("", 200, t1, true),
			wantChanged:  true,
			wantMetaOnly: true,
		},
		{
			name:         "meta-only file with same size+mtime is unchanged",
			before:       fp("", 100, t0, true),
			after:        fp("", 100, t0, true),
			wantChanged:  false,
			wantMetaOnly: false,
		},
		{
			name:         "one side meta-only still compares and flags",
			before:       fp("digest", 100, t0, false),
			after:        fp("", 100, t1, true),
			wantChanged:  true,
			wantMetaOnly: true,
		},
		{
			name:         "fully hashed sides compare by digest only",
			before:       fp("digest-a", 100, t0, false),
			after:        fp("digest-b", 100, t0, false), // same size/mtime, different digest
			wantChanged:  true,
			wantMetaOnly: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := Result{Files: map[string]Fingerprint{"f": tt.before}}
			after := Result{Files: map[string]Fingerprint{"f": tt.after}}
			d := Diff(before, after)

			gotChanged := len(d.Modified) == 1
			if gotChanged != tt.wantChanged {
				t.Fatalf("changed = %v, want %v (modified=%+v)", gotChanged, tt.wantChanged, d.Modified)
			}
			if gotChanged && d.Modified[0].MetaOnly != tt.wantMetaOnly {
				t.Fatalf("MetaOnly = %v, want %v", d.Modified[0].MetaOnly, tt.wantMetaOnly)
			}
		})
	}
}

func TestSkipDirsFromGitignore(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    []string
	}{
		{
			name:    "bare names",
			content: "node_modules\nbuild\n",
			want:    []string{"build", "node_modules"},
		},
		{
			name:    "trailing slash entries",
			content: "dist/\ncoverage/\n",
			want:    []string{"coverage", "dist"},
		},
		{
			name:    "comments and blank lines ignored",
			content: "# a comment\n\nbuild\n\n# another\n",
			want:    []string{"build"},
		},
		{
			name:    "globs are ignored, not half-implemented",
			content: "*.log\nbuild/*.tmp\n**/cache\n",
			want:    nil,
		},
		{
			name:    "negations are ignored entirely, not applied as un-skips",
			content: "build\n!build/keep\n",
			want:    []string{"build"},
		},
		{
			name:    "nested/anchored paths are ignored",
			content: "a/b\n/rooted\n",
			want:    nil,
		},
		{
			name:    "duplicates collapse",
			content: "build\nbuild\n",
			want:    []string{"build"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SkipDirsFromGitignore(tt.content)
			if !equalStrings(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
