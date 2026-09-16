// Command agentwitness wraps an AI coding agent invocation and observes what
// it actually did to the filesystem, process tree and network, independent
// of what the agent's own session log claims.
//
// It never blocks, kills, sandboxes or modifies the wrapped process, makes no
// network calls of its own, and never prints file contents or environment
// variable values.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/harshilaggarwal/agentwitness/internal/claim"
	"github.com/harshilaggarwal/agentwitness/internal/procs"
	"github.com/harshilaggarwal/agentwitness/internal/report"
	"github.com/harshilaggarwal/agentwitness/internal/session"
	"github.com/harshilaggarwal/agentwitness/internal/snapshot"
)

// version is set via -ldflags "-X main.version=..." at release build time.
var version = "dev"

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		usage(os.Stderr)
		return 2
	}

	switch args[0] {
	case "run":
		return cmdRun(args[1:])
	case "report":
		return cmdReport(args[1:])
	case "list":
		return cmdList(args[1:])
	case "version":
		fmt.Println("agentwitness " + version)
		return 0
	case "-h", "--help", "help":
		usage(os.Stdout)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "agentwitness: unknown command %q\n\n", args[0])
		usage(os.Stderr)
		return 2
	}
}

func usage(w *os.File) {
	fmt.Fprint(w, `agentwitness observes what an AI coding agent actually did, independent of
what its own session log claims.

Usage:
  agentwitness run -- <command...>    wrap and observe an agent invocation
  agentwitness report [session-id]    re-render a past session (default: last)
  agentwitness list                   list recorded sessions
  agentwitness version                print the version

agentwitness makes no network calls of its own and sends no telemetry. See
the README for what it observes and what it can miss.
`)
}

// cmdRun is Step 1: spawn the child with direct stdio passthrough (no pty,
// no wrapping) so the interactive experience is identical to running the
// command directly, snapshot the project directory before and after, and
// report the diff. The child's exit code is always ours.
func cmdRun(args []string) int {
	// Manual split at "--" rather than flag.FlagSet: everything after -- is
	// the wrapped command's own argv and must never be interpreted by us,
	// including things that look like our flags.
	dashIdx := -1
	for i, a := range args {
		if a == "--" {
			dashIdx = i
			break
		}
	}
	if dashIdx == -1 || dashIdx == len(args)-1 {
		fmt.Fprintln(os.Stderr, "agentwitness run: usage: agentwitness run -- <command...>")
		return 2
	}
	// Flags before "--" are reserved for future use (e.g. --net in Step 5);
	// none are defined yet, so any present is an error rather than silently
	// ignored.
	if dashIdx != 0 {
		fmt.Fprintf(os.Stderr, "agentwitness run: unrecognized flags before --: %v\n", args[:dashIdx])
		return 2
	}
	command := args[dashIdx+1:]

	projectDir, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentwitness: %v\n", err)
		return 1
	}
	absProjectDir, err := filepath.Abs(projectDir)
	if err == nil {
		projectDir = absProjectDir
	}

	sess := &session.Session{
		ID:      session.NewID(),
		Command: command,
		Dir:     projectDir,
	}

	fmt.Fprintf(os.Stderr, "%s\n", style("agentwitness: observing "+shellJoin(command)))

	sess.StartedAt = time.Now()
	before := snapshot.Walk(projectDir)

	exitCode, spawnErr, procResult := spawnAndSample(command)

	sess.EndedAt = time.Now()
	sess.ExitCode = exitCode
	sess.Processes = procResult

	if spawnErr != nil {
		// The child never started (e.g. binary not found). We still want a
		// record of the attempt, but there is nothing to diff meaningfully
		// beyond "nothing happened", so note it and move on.
		sess.Confidence.Notes = append(sess.Confidence.Notes,
			fmt.Sprintf("failed to start command: %v", spawnErr))
	}

	after := snapshot.Walk(projectDir)
	sess.Before = before
	sess.After = after
	sess.Diff = snapshot.Diff(before, after)

	if before.Truncated || after.Truncated {
		sess.Confidence.Notes = append(sess.Confidence.Notes,
			fmt.Sprintf("filesystem walk truncated at %d files; some changes may be missed", snapshot.MaxFiles))
	}
	if !procResult.Available {
		sess.Confidence.Notes = append(sess.Confidence.Notes,
			"process tree sampling is unavailable on this platform (windows v0.1.0 collects filesystem only)")
	} else {
		sess.Confidence.Notes = append(sess.Confidence.Notes,
			fmt.Sprintf("process tree sampled every %s: very short-lived processes between samples may be missed", procResult.Interval))
	}

	claimResult := claim.ClaudeCode{}.Parse(projectDir, sess.StartedAt, sess.EndedAt)
	sess.Claim = claimResult
	if !claimResult.Available {
		for _, n := range claimResult.Notes {
			sess.Confidence.Notes = append(sess.Confidence.Notes, n)
		}
	} else {
		sess.Confidence.Notes = append(sess.Confidence.Notes,
			fmt.Sprintf("claim log: %d claim(s) from %d Claude Code session file(s)", len(claimResult.Claims), len(claimResult.Files)))
		for _, n := range claimResult.Notes {
			sess.Confidence.Notes = append(sess.Confidence.Notes, n)
		}
	}
	sess.Confidence.Notes = append(sess.Confidence.Notes,
		"network collection is not yet implemented (coming in a later step); correlation between observed and claimed is not yet implemented (coming in the next step)")

	if err := session.Save(projectDir, sess); err != nil {
		fmt.Fprintf(os.Stderr, "agentwitness: failed to save session: %v\n", err)
	}

	fmt.Fprintln(os.Stderr)
	report.Write(os.Stderr, sess)

	return exitCode
}

// spawnAndSample runs command with stdio passed through directly to the real
// terminal, sampling its descendant process tree while it runs.
//
// Stdio passthrough is the single most important correctness requirement: no
// pty, no buffering, no interception of any stream, so an interactive
// program behaves exactly as it would unwrapped.
//
// The child is left in our own process group (no Setpgid) so the terminal
// continues to treat it as the foreground process and delivers Ctrl+C /
// Ctrl+Z to it directly, the same as running it unwrapped. We still trap
// SIGINT/SIGTERM ourselves, not to forward them (the tty already did that)
// but so we are not torn down before we've written the report — we only
// ever observe, never kill.
func spawnAndSample(command []string) (exitCode int, err error, procResult procs.Result) {
	cmd := exec.Command(command[0], command[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	sigCh := make(chan os.Signal, 4)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	go func() {
		// Drain and discard: the terminal already delivers these signals to
		// the child directly since it shares our process group. We just need
		// to not die from them ourselves.
		for range sigCh {
		}
	}()

	if startErr := cmd.Start(); startErr != nil {
		return 127, startErr, procs.Result{}
	}

	sampler := procs.NewSampler(cmd.Process.Pid, procs.DefaultInterval)
	go sampler.Run()

	waitErr := cmd.Wait()

	// One last sample right at exit, before descendants that are about to be
	// reaped disappear from the process table, then stop the ticking loop.
	sampler.SampleNow()
	sampler.Stop()
	procResult = sampler.Result()

	if waitErr == nil {
		return 0, nil, procResult
	}
	if exitErr, ok := waitErr.(*exec.ExitError); ok {
		if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
			if status.Signaled() {
				return 128 + int(status.Signal()), nil, procResult
			}
			return status.ExitStatus(), nil, procResult
		}
		return exitErr.ExitCode(), nil, procResult
	}
	// The process couldn't even be waited on (rare). Report it as a failure
	// to start rather than guessing an exit code.
	return 127, waitErr, procResult
}

func cmdReport(args []string) int {
	projectDir, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentwitness: %v\n", err)
		return 1
	}

	var sess *session.Session
	if len(args) > 0 {
		sess, err = session.Load(projectDir, args[0])
	} else {
		sess, err = session.Last(projectDir)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentwitness: %v\n", err)
		return 1
	}
	if sess == nil {
		fmt.Fprintln(os.Stderr, "agentwitness: no recorded sessions found")
		return 1
	}
	report.Write(os.Stdout, sess)
	return 0
}

func cmdList(args []string) int {
	projectDir, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentwitness: %v\n", err)
		return 1
	}
	sessions, err := session.List(projectDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentwitness: %v\n", err)
		return 1
	}
	if len(sessions) == 0 {
		fmt.Println("no recorded sessions")
		return 0
	}
	for _, s := range sessions {
		fmt.Printf("%-16s  %-20s  exit=%-4d  %s\n",
			s.ID, s.StartedAt.Format(time.RFC3339), s.ExitCode, shellJoin(s.Command))
	}
	return 0
}

func shellJoin(args []string) string {
	out := ""
	for i, a := range args {
		if i > 0 {
			out += " "
		}
		out += a
	}
	return out
}

func style(s string) string {
	if os.Getenv("NO_COLOR") != "" {
		return s
	}
	info, err := os.Stderr.Stat()
	if err != nil || info.Mode()&os.ModeCharDevice == 0 {
		return s
	}
	return "\x1b[2m" + s + "\x1b[0m"
}
