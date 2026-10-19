package extract

import (
	"net/netip"
	"testing"
	"time"

	"ostrakon/internal/event"
)

func TestParseNginxAccess(t *testing.T) {
	now := time.Date(2026, 10, 18, 20, 0, 0, 0, time.UTC)

	tests := []struct {
		name   string
		input  string
		ok     bool
		ip     string
		method string
		path   string
		status int
		ua     string
	}{
		{
			name:   "wp-login probe with scanner user agent",
			input:  `203.0.113.7 - - [18/Oct/2026:20:00:01 +0800] "GET /wp-login.php HTTP/1.1" 404 153 "-" "Mozilla/5.0 zgrab/0.x"`,
			ok:     true,
			ip:     "203.0.113.7",
			method: "GET",
			path:   "/wp-login.php",
			status: 404,
			ua:     "Mozilla/5.0 zgrab/0.x",
		},
		{
			name:   "ipv6 client posting to login",
			input:  `2001:db8::1 - - [18/Oct/2026:20:00:01 +0800] "POST /login HTTP/2.0" 401 0 "-" "curl/8"`,
			ok:     true,
			ip:     "2001:db8::1",
			method: "POST",
			path:   "/login",
			status: 401,
			ua:     "curl/8",
		},
		{
			name:   "forged addresses in path and user agent are ignored",
			input:  `203.0.113.8 - - [18/Oct/2026:20:00:01 +0800] "GET /9.9.9.9 HTTP/1.1" 404 1 "-" "1.1.1.1"`,
			ok:     true,
			ip:     "203.0.113.8",
			method: "GET",
			path:   "/9.9.9.9",
			status: 404,
			ua:     "1.1.1.1",
		},
		{
			name:   "forged address in referer and user agent with spaces is ignored",
			input:  `203.0.113.8 - - [18/Oct/2026:20:00:01 +0800] "GET / HTTP/1.1" 200 5 "http://9.9.9.9/ 8.8.8.8" "x 7.7.7.7 - - [1/Jan/2000:00:00:00 +0000] y"`,
			ok:     true,
			ip:     "203.0.113.8",
			method: "GET",
			path:   "/",
			status: 200,
			ua:     "x 7.7.7.7 - - [1/Jan/2000:00:00:00 +0000] y",
		},
		{
			name:   "escaped quote in request is kept verbatim",
			input:  `203.0.113.8 - - [18/Oct/2026:20:00:01 +0800] "GET /a\x22b HTTP/1.1" 404 1 "-" "-"`,
			ok:     true,
			ip:     "203.0.113.8",
			method: "GET",
			path:   `/a\x22b`,
			status: 404,
			ua:     "-",
		},
		{
			name:   "tls probe on the http port",
			input:  `203.0.113.9 - - [18/Oct/2026:20:00:01 +0800] "\x16\x03\x01\x00" 400 157 "-" "-"`,
			ok:     true,
			ip:     "203.0.113.9",
			method: "",
			path:   `\x16\x03\x01\x00`,
			status: 400,
			ua:     "-",
		},
		{
			name:   "request with more than three parts goes whole into path",
			input:  `203.0.113.9 - - [18/Oct/2026:20:00:01 +0800] "GET /a b HTTP/1.1" 400 1 "-" "-"`,
			ok:     true,
			ip:     "203.0.113.9",
			method: "",
			path:   "GET /a b HTTP/1.1",
			status: 400,
			ua:     "-",
		},
		{
			name:   "http/0.9 style request with two parts goes whole into path",
			input:  `203.0.113.9 - - [18/Oct/2026:20:00:01 +0800] "GET /" 400 1 "-" "-"`,
			ok:     true,
			ip:     "203.0.113.9",
			method: "",
			path:   "GET /",
			status: 400,
			ua:     "-",
		},
		{
			name:   "empty request",
			input:  `203.0.113.9 - - [18/Oct/2026:20:00:01 +0800] "" 400 0 "-" "-"`,
			ok:     true,
			ip:     "203.0.113.9",
			method: "",
			path:   "",
			status: 400,
			ua:     "-",
		},
		{
			name:   "common log format without referer and user agent",
			input:  `203.0.113.10 - - [18/Oct/2026:20:00:01 +0800] "GET /x HTTP/1.1" 200 12`,
			ok:     true,
			ip:     "203.0.113.10",
			method: "GET",
			path:   "/x",
			status: 200,
			ua:     "",
		},
		{
			name:   "non-numeric status is zero",
			input:  `203.0.113.10 - - [18/Oct/2026:20:00:01 +0800] "GET /x HTTP/1.1" abc 12 "-" "ua"`,
			ok:     true,
			ip:     "203.0.113.10",
			method: "GET",
			path:   "/x",
			status: 0,
			ua:     "ua",
		},
		{
			name:   "oversized status is zero",
			input:  `203.0.113.10 - - [18/Oct/2026:20:00:01 +0800] "GET /x HTTP/1.1" 99999999999999999999 12 "-" "ua"`,
			ok:     true,
			ip:     "203.0.113.10",
			method: "GET",
			path:   "/x",
			status: 0,
			ua:     "ua",
		},
		{
			name:   "unterminated request quote keeps only the address",
			input:  `203.0.113.10 - - [18/Oct/2026:20:00:01 +0800] "GET /x HTT`,
			ok:     true,
			ip:     "203.0.113.10",
			status: 0,
		},
		{
			name:  "non-standard format keeps only the address",
			input: `203.0.113.10 something weird`,
			ok:    true,
			ip:    "203.0.113.10",
		},
		{
			name:   "ipv4-mapped client address is unmapped",
			input:  `::ffff:203.0.113.12 - - [18/Oct/2026:20:00:01 +0800] "GET / HTTP/1.1" 200 1 "-" "-"`,
			ok:     true,
			ip:     "203.0.113.12",
			method: "GET",
			path:   "/",
			status: 200,
			ua:     "-",
		},
		{
			name:  "hostname instead of address",
			input: `localhost - - [18/Oct/2026:20:00:01 +0800] "GET / HTTP/1.1" 200 1 "-" "-"`,
		},
		{
			name:  "unix socket client",
			input: `unix: - - [18/Oct/2026:20:00:01 +0800] "GET / HTTP/1.1" 200 1 "-" "-"`,
		},
		{
			name:  "address with zone",
			input: `fe80::1%eth0 - - [18/Oct/2026:20:00:01 +0800] "GET / HTTP/1.1" 200 1 "-" "-"`,
		},
		{
			name:  "leading space before address",
			input: ` 203.0.113.7 - - [18/Oct/2026:20:00:01 +0800] "GET / HTTP/1.1" 200 1 "-" "-"`,
		},
		{
			name:  "address only, no separator",
			input: `203.0.113.7`,
		},
		{
			name:  "empty line",
			input: ``,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev, ok := ParseNginxAccess(tc.input, now)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v (event %+v)", ok, tc.ok, ev)
			}
			if !tc.ok {
				return
			}
			want := netip.MustParseAddr(tc.ip)
			if ev.IP != want {
				t.Errorf("IP = %v, want %v", ev.IP, want)
			}
			if ev.IP.Is4In6() {
				t.Errorf("IP %v is not unmapped", ev.IP)
			}
			if ev.Method != tc.method {
				t.Errorf("Method = %q, want %q", ev.Method, tc.method)
			}
			if ev.Path != tc.path {
				t.Errorf("Path = %q, want %q", ev.Path, tc.path)
			}
			if ev.Status != tc.status {
				t.Errorf("Status = %d, want %d", ev.Status, tc.status)
			}
			if ev.UserAgent != tc.ua {
				t.Errorf("UserAgent = %q, want %q", ev.UserAgent, tc.ua)
			}
			if ev.Kind != event.KindHTTPRequest {
				t.Errorf("Kind = %q, want %q", ev.Kind, event.KindHTTPRequest)
			}
			if ev.Source != "nginx-access" {
				t.Errorf("Source = %q, want nginx-access", ev.Source)
			}
			if ev.User != "" {
				t.Errorf("User = %q, want empty", ev.User)
			}
			if !ev.Time.Equal(now) {
				t.Errorf("Time = %v, want %v", ev.Time, now)
			}
		})
	}
}
