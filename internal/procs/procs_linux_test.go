//go:build linux

package procs

import "testing"

func TestParseStat(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		wantPID  int
		wantPPID int
		wantComm string
		wantErr  bool
	}{
		{
			name:     "simple comm",
			line:     "123 (bash) S 100 123 123 0 -1 4194304 ...\n",
			wantPID:  123,
			wantPPID: 100,
			wantComm: "bash",
		},
		{
			name:     "comm contains a space",
			line:     "456 (my app) S 100 456 456 0 -1 4194304 ...\n",
			wantPID:  456,
			wantPPID: 100,
			wantComm: "my app",
		},
		{
			name:     "comm contains parentheses and spaces, must split on LAST close paren",
			line:     "789 (node (worker) proc) S 200 789 789 0 -1 4194304 ...\n",
			wantPID:  789,
			wantPPID: 200,
			wantComm: "node (worker) proc",
		},
		{
			name:     "comm is itself just parens",
			line:     "1 (()) S 0 1 1 0 -1 4194304 ...\n",
			wantPID:  1,
			wantPPID: 0,
			wantComm: "()",
		},
		{
			name:    "malformed: no parens",
			line:    "123 bash S 100\n",
			wantErr: true,
		},
		{
			name:    "malformed: too few fields after comm",
			line:    "123 (bash)\n",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pid, ppid, comm, err := parseStat([]byte(tt.line))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseStat(%q) = nil error, want error", tt.line)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseStat(%q) unexpected error: %v", tt.line, err)
			}
			if pid != tt.wantPID || ppid != tt.wantPPID || comm != tt.wantComm {
				t.Fatalf("parseStat(%q) = (pid=%d, ppid=%d, comm=%q), want (pid=%d, ppid=%d, comm=%q)",
					tt.line, pid, ppid, comm, tt.wantPID, tt.wantPPID, tt.wantComm)
			}
		})
	}
}

func TestParseCmdline(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want []string
	}{
		{name: "empty", data: []byte{}, want: nil},
		{name: "single arg", data: []byte("bash\x00"), want: []string{"bash"}},
		{
			name: "multiple args, NUL separated",
			data: []byte("git\x00commit\x00-m\x00hello world\x00"),
			want: []string{"git", "commit", "-m", "hello world"},
		},
		{
			name: "missing trailing NUL still splits correctly",
			data: []byte("git\x00status"),
			want: []string{"git", "status"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseCmdline(tt.data)
			if !equalStringSlices(got, tt.want) {
				t.Fatalf("parseCmdline(%q) = %v, want %v", tt.data, got, tt.want)
			}
		})
	}
}

func equalStringSlices(a, b []string) bool {
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
