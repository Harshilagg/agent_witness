//go:build linux

package procs

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

func init() {
	listAll = listAllLinux
}

func listAllLinux() ([]rawProc, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("read /proc: %w", err)
	}

	out := make([]rawProc, 0, len(entries))
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue // not a PID directory (self, cpuinfo, etc.)
		}

		statData, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil {
			continue // process exited between the readdir and this read
		}
		gotPID, ppid, comm, err := parseStat(statData)
		if err != nil {
			continue
		}

		cmdline, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		out = append(out, rawProc{
			PID:     gotPID,
			PPID:    ppid,
			Comm:    comm,
			Cmdline: parseCmdline(cmdline),
		})
	}
	return out, nil
}

// parseStat extracts pid, ppid and comm from the contents of /proc/[pid]/stat.
//
// The format is "pid (comm) state ppid ...". comm is the process name in
// parentheses, and it can itself contain spaces and parentheses (a process
// can name itself anything via prctl/argv[0]), so the only safe way to find
// its end is the LAST ')' in the line, not the first.
func parseStat(data []byte) (pid, ppid int, comm string, err error) {
	s := string(data)

	openIdx := strings.IndexByte(s, '(')
	closeIdx := strings.LastIndexByte(s, ')')
	if openIdx < 0 || closeIdx < openIdx {
		return 0, 0, "", fmt.Errorf("malformed stat line: no comm parens found")
	}

	pid, err = strconv.Atoi(strings.TrimSpace(s[:openIdx]))
	if err != nil {
		return 0, 0, "", fmt.Errorf("parse pid: %w", err)
	}
	comm = s[openIdx+1 : closeIdx]

	// Everything after ") " is: state ppid pgrp session tty_nr tpgid flags ...
	rest := strings.Fields(s[closeIdx+1:])
	if len(rest) < 2 {
		return 0, 0, "", fmt.Errorf("malformed stat line: too few fields after comm")
	}
	ppid, err = strconv.Atoi(rest[1])
	if err != nil {
		return 0, 0, "", fmt.Errorf("parse ppid: %w", err)
	}
	return pid, ppid, comm, nil
}

// parseCmdline splits the NUL-separated contents of /proc/[pid]/cmdline.
func parseCmdline(data []byte) []string {
	trimmed := strings.TrimRight(string(data), "\x00")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "\x00")
}
