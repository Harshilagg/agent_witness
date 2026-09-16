//go:build darwin

package netw

import "testing"

func TestParseLsofName(t *testing.T) {
	tests := []struct {
		name     string
		val      string
		pid      int
		wantOK   bool
		wantHost string
		wantPort int
	}{
		{
			name:     "established ipv4 connection",
			val:      "192.168.1.5:52134->93.184.216.34:443",
			pid:      12345,
			wantOK:   true,
			wantHost: "93.184.216.34",
			wantPort: 443,
		},
		{
			name:     "established ipv6 connection",
			val:      "[fe80::1]:52134->[fe80::2]:443",
			pid:      999,
			wantOK:   true,
			wantHost: "fe80::2",
			wantPort: 443,
		},
		{
			name:   "listening socket, not connected, must be skipped",
			val:    "*:8080",
			pid:    1,
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, ok := parseLsofName(tt.val, tt.pid)
			if ok != tt.wantOK {
				t.Fatalf("parseLsofName(%q) ok = %v, want %v", tt.val, ok, tt.wantOK)
			}
			if !tt.wantOK {
				return
			}
			if c.RemoteHost != tt.wantHost || c.RemotePort != tt.wantPort || c.PID != tt.pid {
				t.Fatalf("parseLsofName(%q) = %+v, want host=%q port=%d pid=%d",
					tt.val, c, tt.wantHost, tt.wantPort, tt.pid)
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
