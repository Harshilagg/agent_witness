//go:build darwin

package procs

import "testing"

func TestParsePSLine(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		wantOK   bool
		wantPID  int
		wantPPID int
		wantComm string
		wantArgs []string
	}{
		{
			name:     "typical padded columns",
			line:     "  123    1  /usr/bin/python3 script.py --flag value",
			wantOK:   true,
			wantPID:  123,
			wantPPID: 1,
			wantComm: "python3",
			wantArgs: []string{"/usr/bin/python3", "script.py", "--flag", "value"},
		},
		{
			name:     "single-word command",
			line:     "1 0 launchd",
			wantOK:   true,
			wantPID:  1,
			wantPPID: 0,
			wantComm: "launchd",
			wantArgs: []string{"launchd"},
		},
		{
			name:     "ps could not read args, falls back to (name) form",
			line:     "15324 15322 (sleep)",
			wantOK:   true,
			wantPID:  15324,
			wantPPID: 15322,
			wantComm: "sleep",
			wantArgs: []string{"(sleep)"},
		},
		{
			name:   "blank line",
			line:   "",
			wantOK: false,
		},
		{
			name:   "non-numeric pid",
			line:   "abc 1 something",
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parsePSLine(tt.line)
			if ok != tt.wantOK {
				t.Fatalf("parsePSLine(%q) ok = %v, want %v", tt.line, ok, tt.wantOK)
			}
			if !tt.wantOK {
				return
			}
			if got.PID != tt.wantPID || got.PPID != tt.wantPPID || got.Comm != tt.wantComm {
				t.Fatalf("parsePSLine(%q) = %+v, want pid=%d ppid=%d comm=%q",
					tt.line, got, tt.wantPID, tt.wantPPID, tt.wantComm)
			}
			if !equalStringSlices(got.Cmdline, tt.wantArgs) {
				t.Fatalf("parsePSLine(%q) Cmdline = %v, want %v", tt.line, got.Cmdline, tt.wantArgs)
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
