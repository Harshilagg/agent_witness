//go:build linux

package netw

import "testing"

func TestParseSSLine(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		wantOK   bool
		wantHost string
		wantPort int
		wantPID  int
	}{
		{
			name:     "typical established connection",
			line:     `ESTAB 0 0 192.168.1.5:52134 93.184.216.34:443 users:(("curl",pid=12345,fd=5))`,
			wantOK:   true,
			wantHost: "93.184.216.34",
			wantPort: 443,
			wantPID:  12345,
		},
		{
			name:     "ipv6 peer address",
			line:     `ESTAB 0 0 [::1]:52134 [2001:db8::1]:443 users:(("node",pid=999,fd=12))`,
			wantOK:   true,
			wantHost: "2001:db8::1",
			wantPort: 443,
			wantPID:  999,
		},
		{
			name:   "no pid info, cannot attribute",
			line:   `ESTAB 0 0 192.168.1.5:52134 93.184.216.34:443`,
			wantOK: false,
		},
		{
			name:   "too few fields",
			line:   `ESTAB 0 0`,
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, ok := parseSSLine(tt.line)
			if ok != tt.wantOK {
				t.Fatalf("parseSSLine(%q) ok = %v, want %v", tt.line, ok, tt.wantOK)
			}
			if !tt.wantOK {
				return
			}
			if c.RemoteHost != tt.wantHost || c.RemotePort != tt.wantPort || c.PID != tt.wantPID {
				t.Fatalf("parseSSLine(%q) = %+v, want host=%q port=%d pid=%d",
					tt.line, c, tt.wantHost, tt.wantPort, tt.wantPID)
			}
		})
	}
}

func TestSplitHostPort(t *testing.T) {
	tests := []struct {
		in       string
		wantHost string
		wantPort string
		wantOK   bool
	}{
		{"93.184.216.34:443", "93.184.216.34", "443", true},
		{"[2001:db8::1]:443", "2001:db8::1", "443", true},
		{"nohost", "", "", false},
	}
	for _, tt := range tests {
		h, p, ok := splitHostPort(tt.in)
		if ok != tt.wantOK || h != tt.wantHost || p != tt.wantPort {
			t.Errorf("splitHostPort(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tt.in, h, p, ok, tt.wantHost, tt.wantPort, tt.wantOK)
		}
	}
}
