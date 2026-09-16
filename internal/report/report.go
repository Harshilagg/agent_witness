// Package report renders a Session to the terminal.
//
// Order is deliberate and fixed: discrepancies first (added by later steps),
// then the plain summary, then the diff stat, then a confidence footer. A
// reader should see what went wrong before they see what happened normally.
package report

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/harshilaggarwal/agentwitness/internal/claim"
	"github.com/harshilaggarwal/agentwitness/internal/correlate"
	"github.com/harshilaggarwal/agentwitness/internal/session"
	"github.com/harshilaggarwal/agentwitness/internal/snapshot"
)

// useColor reports whether ANSI color codes should be written to w, honoring
// NO_COLOR (https://no-color.org) and refusing color on a non-TTY stream.
func useColor(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

const (
	bold   = "\x1b[1m"
	dim    = "\x1b[2m"
	red    = "\x1b[31m"
	yellow = "\x1b[33m"
	reset  = "\x1b[0m"
)

func style(w io.Writer, code, s string) string {
	if !useColor(w) {
		return s
	}
	return code + s + reset
}

// Write renders s to w. Discrepancies come first, then the plain summary,
// then the diff stat, then an honest confidence footer — a reader should see
// what went wrong before they see what happened normally.
func Write(w io.Writer, s *session.Session) {
	writeFindings(w, s)
	writeSummary(w, s)
	writeProcesses(w, s)
	writeDiffStat(w, s)
	writeFooter(w, s)
}

func writeFindings(w io.Writer, s *session.Session) {
	if len(s.Findings) == 0 {
		fmt.Fprintln(w, style(w, bold, "Discrepancies"))
		fmt.Fprintln(w, "  none found")
		fmt.Fprintln(w)
		return
	}
	fmt.Fprintln(w, style(w, bold, fmt.Sprintf("Discrepancies (%d)", len(s.Findings))))
	for _, f := range s.Findings {
		fmt.Fprintf(w, "  %s %s\n", severityTag(w, f.Severity), f.Title)
		fmt.Fprintf(w, "    %s\n", f.Detail)
		for _, e := range f.Evidence {
			fmt.Fprintf(w, "    - %s\n", e)
		}
	}
	fmt.Fprintln(w)
}

func severityTag(w io.Writer, sev correlate.Severity) string {
	switch sev {
	case correlate.SeverityHigh:
		return style(w, red+bold, "[HIGH]")
	case correlate.SeverityMedium:
		return style(w, yellow, "[MEDIUM]")
	default:
		return style(w, dim, "[LOW]")
	}
}

func writeSummary(w io.Writer, s *session.Session) {
	fmt.Fprintln(w, style(w, bold, "Summary"))
	fmt.Fprintf(w, "  command:    %s\n", strings.Join(s.Command, " "))
	fmt.Fprintf(w, "  dir:        %s\n", s.Dir)
	fmt.Fprintf(w, "  duration:   %s\n", s.EndedAt.Sub(s.StartedAt).Round(1e6))
	fmt.Fprintf(w, "  exit code:  %d\n", s.ExitCode)
	fmt.Fprintf(w, "  files changed: %d added, %d modified, %d deleted\n",
		len(s.Diff.Added), len(s.Diff.Modified), len(s.Diff.Deleted))
	if s.Processes.Available {
		fmt.Fprintf(w, "  processes:  %d descendant process(es) observed\n", len(s.Processes.Procs))
	} else {
		fmt.Fprintf(w, "  processes:  unavailable\n")
	}
	if s.Claim.Available {
		edits, reads, cmds := countClaimKinds(s.Claim.Claims)
		fmt.Fprintf(w, "  claimed:    %d edit(s), %d read(s), %d command(s) (source: %s)\n", edits, reads, cmds, s.Claim.Source)
	} else {
		fmt.Fprintf(w, "  claimed:    unavailable\n")
	}
	fmt.Fprintln(w)
}

func countClaimKinds(claims []claim.Claim) (edits, reads, commands int) {
	for _, c := range claims {
		switch c.Kind {
		case claim.KindEdit:
			edits++
		case claim.KindRead:
			reads++
		case claim.KindCommand:
			commands++
		}
	}
	return
}

func writeProcesses(w io.Writer, s *session.Session) {
	if !s.Processes.Available || len(s.Processes.Procs) == 0 {
		return
	}
	fmt.Fprintln(w, style(w, bold, "Processes"))
	counts := map[string]int{}
	for _, p := range s.Processes.Procs {
		name := p.Comm
		if name == "" {
			name = "(unknown)"
		}
		counts[name]++
	}
	names := make([]string, 0, len(counts))
	for n := range counts {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(w, "  %-20s x%d\n", n, counts[n])
	}
	fmt.Fprintln(w)
}

func writeDiffStat(w io.Writer, s *session.Session) {
	fmt.Fprintln(w, style(w, bold, "Diff"))
	if len(s.Diff.Added) == 0 && len(s.Diff.Modified) == 0 && len(s.Diff.Deleted) == 0 {
		fmt.Fprintln(w, "  (no file changes observed)")
		fmt.Fprintln(w)
		return
	}
	printEntries(w, "+", s.Diff.Added)
	printEntries(w, "~", s.Diff.Modified)
	printEntries(w, "-", s.Diff.Deleted)
	fmt.Fprintln(w)
}

func printEntries(w io.Writer, marker string, entries []snapshot.DiffEntry) {
	paths := make([]string, len(entries))
	for i, e := range entries {
		paths[i] = e.Path
	}
	sort.Strings(paths)
	for _, p := range paths {
		suffix := ""
		if isMetaOnly(entries, p) {
			suffix = "  (size/mtime only)"
		}
		fmt.Fprintf(w, "  %s %s%s\n", marker, p, suffix)
	}
}

func isMetaOnly(entries []snapshot.DiffEntry, path string) bool {
	for _, e := range entries {
		if e.Path == path {
			return e.MetaOnly
		}
	}
	return false
}

func writeFooter(w io.Writer, s *session.Session) {
	fmt.Fprintln(w, style(w, dim, "Confidence"))
	if len(s.Confidence.Notes) == 0 {
		fmt.Fprintln(w, style(w, dim, "  full collection ran; no gaps reported"))
		return
	}
	for _, n := range s.Confidence.Notes {
		fmt.Fprintln(w, style(w, dim, "  - "+n))
	}
}
