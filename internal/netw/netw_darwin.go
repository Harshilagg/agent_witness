//go:build darwin

package netw

import (
	"bufio"
	"bytes"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

func init() {
	listConnections = listConnectionsDarwin
}

// listConnectionsDarwin shells out to lsof. -F requests machine-readable
// field output instead of the human-oriented table, which is far more
// robust to parse than fixed-width columns; the underlying query is exactly
// the one named in the design (-nP -iTCP -sTCP:ESTABLISHED), just with -F pn
// added so the result is trivial to parse reliably: p<pid> then n<name> per
// matching socket.
func listConnectionsDarwin() ([]Connection, string, error) {
	out, err := exec.Command("lsof", "-nP", "-iTCP", "-sTCP:ESTABLISHED", "-F", "pn").Output()
	if err != nil {
		// lsof exits non-zero when it simply finds no matching sockets;
		// treat that as "zero connections", not a failure.
		if exitErr, ok := err.(*exec.ExitError); ok && len(exitErr.Stderr) == 0 {
			return nil, "lsof", nil
		}
		return nil, "", fmt.Errorf("run lsof: %w", err)
	}

	var conns []Connection
	curPID := 0
	scanner := bufio.NewScanner(bytes.NewReader(out))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		tag, val := line[0], line[1:]
		switch tag {
		case 'p':
			if pid, err := strconv.Atoi(val); err == nil {
				curPID = pid
			}
		case 'n':
			c, ok := parseLsofName(val, curPID)
			if ok {
				conns = append(conns, c)
			}
		}
	}
	return conns, "lsof", scanner.Err()
}

// parseLsofName parses lsof's -F "n" field for a TCP socket, which looks
// like "192.168.1.5:52134->93.184.216.34:443".
func parseLsofName(name string, pid int) (Connection, bool) {
	parts := strings.SplitN(name, "->", 2)
	if len(parts) != 2 {
		return Connection{}, false // not a connected socket (e.g. a listener)
	}
	host, portStr, ok := splitHostPort(parts[1])
	if !ok {
		return Connection{}, false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return Connection{}, false
	}
	return Connection{RemoteHost: host, RemotePort: port, PID: pid}, true
}

// splitHostPort splits a "host:port" or "[ipv6host]:port" address, the same
// shape both ss and lsof produce.
func splitHostPort(s string) (host, port string, ok bool) {
	if strings.HasPrefix(s, "[") {
		idx := strings.LastIndex(s, "]:")
		if idx < 0 {
			return "", "", false
		}
		return s[1:idx], s[idx+2:], true
	}
	idx := strings.LastIndex(s, ":")
	if idx < 0 {
		return "", "", false
	}
	return s[:idx], s[idx+1:], true
}
