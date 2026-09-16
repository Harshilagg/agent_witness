// Package snapshot fingerprints a directory tree before and after an agent
// run so the difference can be compared against what the agent claimed it did.
//
// Nothing here ever records file contents. A fingerprint is a hash, a size and
// a modification time; that is all that is ever persisted or printed.
package snapshot

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// MaxHashBytes is the size above which a file is fingerprinted by size+mtime
// only. Hashing multi-gigabyte files would dominate the runtime of a wrap and
// buy very little: we only need to know whether a file changed.
const MaxHashBytes = 8 << 20 // 8 MiB

// MaxFiles caps the walk so a wrap in an enormous tree cannot hang the user's
// session. Hitting it sets Result.Truncated, which the report states plainly.
const MaxFiles = 200000

// DefaultSkipDirs are directory names never descended into. These are build
// and dependency caches: they churn constantly and would drown real findings.
var DefaultSkipDirs = []string{
	".git",
	"node_modules",
	"vendor",
	"__pycache__",
	".venv",
	"target",
	"dist",
	"build",
	".next",
	".agentwitness",
}

// Skip reasons.
const (
	ReasonUnreadable = "unreadable"
	ReasonSymlink    = "symlink"
	ReasonNotRegular = "not-regular"
)

// Fingerprint identifies a file's state without revealing its contents.
type Fingerprint struct {
	Digest  string    `json:"digest,omitempty"`
	Size    int64     `json:"size"`
	ModTime time.Time `json:"mod_time"`
	// MetaOnly means Digest is absent and the fingerprint rests on size+mtime
	// alone, so a change is detected less reliably. Reports must not imply
	// content certainty for these.
	MetaOnly bool `json:"meta_only,omitempty"`
}

// Skipped records a path we deliberately did not fingerprint. Skips are never
// errors; an unreadable file is a fact about the environment, not a failure.
type Skipped struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// Result is one point-in-time fingerprint of a tree.
type Result struct {
	Root string `json:"root"`
	// Files is keyed by path relative to Root, using forward slashes.
	Files   map[string]Fingerprint `json:"files"`
	Skipped []Skipped              `json:"skipped,omitempty"`
	// Truncated reports that MaxFiles was hit and the walk is incomplete.
	Truncated bool `json:"truncated,omitempty"`
}

// Walk fingerprints root, skipping DefaultSkipDirs plus any bare directory
// names extracted from root/.gitignore.
func Walk(root string) Result {
	skip := make(map[string]bool, len(DefaultSkipDirs))
	for _, d := range DefaultSkipDirs {
		skip[d] = true
	}
	if data, err := os.ReadFile(filepath.Join(root, ".gitignore")); err == nil {
		for _, d := range SkipDirsFromGitignore(string(data)) {
			skip[d] = true
		}
	}
	return walkWith(root, skip, sha256.New)
}

// WalkSensitive fingerprints an explicit watchlist of sensitive paths, one
// level deep only.
//
// Digests are HMAC-SHA256 under a per-session key that is never persisted.
// Change detection within a run is exact, because both the before and after
// fingerprints use the same key, but the stored digests are useless to anyone
// who later reads the session file: they cannot be checked against a guess at
// the contents of, say, an SSH private key.
func WalkSensitive(paths []string, key []byte) Result {
	newHash := func() hash.Hash { return hmac.New(sha256.New, key) }
	res := Result{Root: "", Files: map[string]Fingerprint{}}

	for _, p := range paths {
		info, err := os.Lstat(p)
		if err != nil {
			if !os.IsNotExist(err) {
				res.Skipped = append(res.Skipped, Skipped{p, ReasonUnreadable})
			}
			continue // a watchlist entry the user simply does not have
		}
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			res.Skipped = append(res.Skipped, Skipped{p, ReasonSymlink})
		case info.IsDir():
			entries, err := os.ReadDir(p)
			if err != nil {
				res.Skipped = append(res.Skipped, Skipped{p, ReasonUnreadable})
				continue
			}
			for _, e := range entries {
				child := filepath.Join(p, e.Name())
				if e.Type() != 0 { // not a regular file
					reason := ReasonNotRegular
					if e.Type()&os.ModeSymlink != 0 {
						reason = ReasonSymlink
					}
					res.Skipped = append(res.Skipped, Skipped{child, reason})
					continue
				}
				addFile(&res, child, child, newHash)
			}
		case info.Mode().IsRegular():
			addFile(&res, p, p, newHash)
		default:
			res.Skipped = append(res.Skipped, Skipped{p, ReasonNotRegular})
		}
	}
	sortSkipped(&res)
	return res
}

// DefaultSensitivePaths is the watchlist: credential stores and shell startup
// files, the places where a change is worth a HIGH severity finding.
func DefaultSensitivePaths(home string) []string {
	if home == "" {
		return nil
	}
	names := []string{
		".ssh", ".aws", ".config",
		".npmrc", ".gitconfig",
		".bashrc", ".bash_profile", ".zshrc", ".zprofile", ".profile",
	}
	paths := make([]string, 0, len(names))
	for _, n := range names {
		paths = append(paths, filepath.Join(home, n))
	}
	return paths
}

func walkWith(root string, skip map[string]bool, newHash func() hash.Hash) Result {
	res := Result{Root: root, Files: map[string]Fingerprint{}}

	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// An unreadable directory is recorded and stepped over, never fatal.
			res.Skipped = append(res.Skipped, Skipped{path, ReasonUnreadable})
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if len(res.Files) >= MaxFiles {
			res.Truncated = true
			return fs.SkipAll
		}

		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)

		if d.IsDir() {
			if path != root && skip[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		// WalkDir does not follow symlinks; we additionally refuse to resolve
		// them, so a link pointing outside the project can never pull us there.
		if d.Type()&os.ModeSymlink != 0 {
			res.Skipped = append(res.Skipped, Skipped{rel, ReasonSymlink})
			return nil
		}
		if !d.Type().IsRegular() {
			res.Skipped = append(res.Skipped, Skipped{rel, ReasonNotRegular})
			return nil
		}
		addFile(&res, path, rel, newHash)
		return nil
	})

	sortSkipped(&res)
	return res
}

// addFile fingerprints one regular file, recording it under key.
func addFile(res *Result, path, key string, newHash func() hash.Hash) {
	info, err := os.Stat(path)
	if err != nil {
		res.Skipped = append(res.Skipped, Skipped{key, ReasonUnreadable})
		return
	}
	fp := Fingerprint{Size: info.Size(), ModTime: info.ModTime()}

	if info.Size() > MaxHashBytes {
		fp.MetaOnly = true
		res.Files[key] = fp
		return
	}
	digest, err := hashFile(path, newHash())
	if err != nil {
		// Readable enough to stat but not to read: keep what we have and say so.
		fp.MetaOnly = true
		res.Files[key] = fp
		res.Skipped = append(res.Skipped, Skipped{key, ReasonUnreadable})
		return
	}
	fp.Digest = digest
	res.Files[key] = fp
}

func hashFile(path string, h hash.Hash) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func sortSkipped(res *Result) {
	sort.Slice(res.Skipped, func(i, j int) bool { return res.Skipped[i].Path < res.Skipped[j].Path })
}

// SkipDirsFromGitignore extracts bare directory names from gitignore content.
//
// Support is deliberately approximate, and the README says so. We honour only
// bare names ("node_modules") and trailing-slash entries ("build/"). Globs,
// negations, anchored paths and nested patterns are ignored outright rather
// than half-implemented: a wrong skip silently hides evidence, which is worse
// for this tool than walking a few extra directories.
func SkipDirsFromGitignore(content string) []string {
	var out []string
	seen := map[string]bool{}

	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "!") { // negation
			continue
		}
		if strings.ContainsAny(line, "*?[]\\") { // glob or escape
			continue
		}
		name := strings.TrimSuffix(line, "/")
		// Anything with a path separator left is anchored or nested, not a
		// bare name.
		if name == "" || strings.Contains(name, "/") {
			continue
		}
		if name == "." || name == ".." || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// DiffEntry describes one path's change between two snapshots.
type DiffEntry struct {
	Path     string      `json:"path"`
	Before   Fingerprint `json:"before,omitempty"`
	After    Fingerprint `json:"after,omitempty"`
	MetaOnly bool        `json:"meta_only,omitempty"`
}

// DiffResult buckets changes between two Results, each list sorted by path.
type DiffResult struct {
	Added    []DiffEntry `json:"added,omitempty"`
	Modified []DiffEntry `json:"modified,omitempty"`
	Deleted  []DiffEntry `json:"deleted,omitempty"`
}

// Diff compares two snapshots of the same tree. A file counts as modified
// only when its fingerprint actually differs; if either side is MetaOnly the
// entry is flagged MetaOnly so a report never implies content certainty it
// doesn't have.
func Diff(before, after Result) DiffResult {
	var res DiffResult
	paths := make(map[string]bool, len(before.Files)+len(after.Files))
	for p := range before.Files {
		paths[p] = true
	}
	for p := range after.Files {
		paths[p] = true
	}

	for p := range paths {
		b, inBefore := before.Files[p]
		a, inAfter := after.Files[p]
		switch {
		case !inBefore && inAfter:
			res.Added = append(res.Added, DiffEntry{Path: p, After: a, MetaOnly: a.MetaOnly})
		case inBefore && !inAfter:
			res.Deleted = append(res.Deleted, DiffEntry{Path: p, Before: b, MetaOnly: b.MetaOnly})
		case inBefore && inAfter:
			if changed(b, a) {
				res.Modified = append(res.Modified, DiffEntry{
					Path: p, Before: b, After: a, MetaOnly: b.MetaOnly || a.MetaOnly,
				})
			}
		}
	}

	sortEntries(res.Added)
	sortEntries(res.Modified)
	sortEntries(res.Deleted)
	return res
}

func changed(b, a Fingerprint) bool {
	if !b.MetaOnly && !a.MetaOnly {
		return b.Digest != a.Digest
	}
	// At least one side is metadata-only: fall back to size+mtime, the best
	// evidence available for a file we chose not to hash in full.
	return b.Size != a.Size || !b.ModTime.Equal(a.ModTime)
}

func sortEntries(e []DiffEntry) {
	sort.Slice(e, func(i, j int) bool { return e[i].Path < e[j].Path })
}
