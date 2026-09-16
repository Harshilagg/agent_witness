//go:build linux

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
	listConnections = listConnectionsLinux
}

// listConnectionsLinux shells out to `ss`. `state established` narrows to
// live connections (skipping LISTEN, TIME_WAIT, ...), matching the
// established-only scope `lsof -sTCP:ESTABLISHED` gives on macOS.
func listConnectionsLinux() ([]Connection, string, error) {
	out, err := exec.Command("ss", "-tnpH", "state", "established").Output()
	if err != nil {
		return nil, "", fmt.Errorf("run ss: %w", err)
	}

	var conns []Connection
	scanner := bufio.NewScanner(bytes.NewReader(out))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		c, ok := parseSSLine(scanner.Text())
		if ok {
			conns = append(conns, c)
		}
	}
	return conns, "ss", scanner.Err()
}

// parseSSLine parses one line of `ss -tnpH state established` output:
//
//	ESTAB 0 0 192.168.1.5:52134 93.184.216.34:443 users:(("curl",pid=12345,fd=5))
//
// Columns are State, Recv-Q, Send-Q, Local address:port, Peer address:port,
// then process info. We need the peer address:port (5th field) and the pid
// pulled out of the users:(...) field.
func parseSSLine(line string) (Connection, bool) {
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return Connection{}, false
	}

	host, portStr, ok := splitHostPort(fields[4])
	if !ok {
		return Connection{}, false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return Connection{}, false
	}

	pid, ok := extractPID(line)
	if !ok {
		// No pid info (e.g. we lack permission to see another user's
		// socket): we can't attribute this connection to a descendant, so
		// it can never match the filter in Sample. Drop it rather than
		// keep an unattributable record.
		return Connection{}, false
	}

	return Connection{RemoteHost: host, RemotePort: port, PID: pid}, true
}

// splitHostPort splits a "host:port" or "[ipv6host]:port" address. Unlike
// net.SplitHostPort, it does not validate that host/port are well-formed —
// ss's output is trusted enough for our purposes, and being lenient here
// means a slightly unexpected format degrades to "skip this line", not a
// crash.
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

// extractPID pulls the first "pid=NNN" occurrence out of an ss line.
func extractPID(line string) (int, bool) {
	idx := strings.Index(line, "pid=")
	if idx < 0 {
		return 0, false
	}
	rest := line[idx+len("pid="):]
	end := 0
	for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
		end++
	}
	if end == 0 {
		return 0, false
	}
	n, err := strconv.Atoi(rest[:end])
	if err != nil {
		return 0, false
	}
	return n, true
}
