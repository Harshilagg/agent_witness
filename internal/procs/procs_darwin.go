//go:build darwin

package procs

import (
	"bufio"
	"bytes"
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

func init() {
	listAll = listAllDarwin
}

// listAllDarwin shells out to `ps`, since macOS has no /proc. `-axo
// pid=,ppid=,command=` suppresses headers and gives a stable, whitespace
// padded column layout with the full command (including args) last.
func listAllDarwin() ([]rawProc, error) {
	out, err := exec.Command("ps", "-axo", "pid=,ppid=,command=").Output()
	if err != nil {
		return nil, fmt.Errorf("run ps: %w", err)
	}

	var procs []rawProc
	scanner := bufio.NewScanner(bytes.NewReader(out))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		p, ok := parsePSLine(scanner.Text())
		if ok {
			procs = append(procs, p)
		}
	}
	return procs, scanner.Err()
}

// parsePSLine parses one "  PID  PPID  full command with spaces" line. pid
// and ppid are taken as the first two whitespace-separated tokens; everything
// after that, verbatim (spacing included), is the command — command can
// itself have embedded spaces, so it must not be tokenized further beyond
// splitting off argv[0] for Comm.
func parsePSLine(line string) (rawProc, bool) {
	line = strings.TrimLeft(line, " \t")
	pidEnd := strings.IndexAny(line, " \t")
	if pidEnd < 0 {
		return rawProc{}, false
	}
	pid, err := strconv.Atoi(line[:pidEnd])
	if err != nil {
		return rawProc{}, false
	}

	rest := strings.TrimLeft(line[pidEnd:], " \t")
	ppidEnd := strings.IndexAny(rest, " \t")
	if ppidEnd < 0 {
		return rawProc{}, false
	}
	ppid, err := strconv.Atoi(rest[:ppidEnd])
	if err != nil {
		return rawProc{}, false
	}

	command := strings.TrimLeft(rest[ppidEnd:], " \t")
	if command == "" {
		return rawProc{}, false
	}

	// ps gives one flat command string, not a real argv array. We do a naive
	// whitespace split for Cmdline; unlike /proc/[pid]/cmdline this cannot
	// distinguish an argument containing a literal space from an argument
	// boundary, so it is best-effort.
	fields := strings.Fields(command)
	comm := filepath.Base(fields[0])
	// When ps cannot read a process's argument vector (commonly a process
	// that has just exec'd, or one about to exit) it falls back to printing
	// the command name alone in parentheses, e.g. "(sleep)" instead of
	// "sleep 3". That is a real gap, not a formatting choice: we only know
	// the name, not the arguments, for that sample. Strip the parens for a
	// readable Comm; Cmdline still reflects exactly what ps gave us.
	if len(comm) >= 2 && strings.HasPrefix(comm, "(") && strings.HasSuffix(comm, ")") {
		comm = comm[1 : len(comm)-1]
	}

	return rawProc{PID: pid, PPID: ppid, Comm: comm, Cmdline: fields}, true
}
