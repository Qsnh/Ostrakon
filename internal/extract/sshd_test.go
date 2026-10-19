package extract

import (
	"net/netip"
	"testing"
	"time"

	"ostrakon/internal/event"
)

func TestParseSSHD(t *testing.T) {
	now := time.Date(2026, 10, 18, 20, 0, 0, 0, time.UTC)

	const (
		syslog = "syslog"
		msg    = "message"
	)

	tests := []struct {
		name  string
		mode  string // syslog | message
		input string
		ok    bool
		ip    string
		kind  event.Kind
		user  string
	}{
		{
			name:  "failed password with syslog prefix",
			mode:  syslog,
			input: "Oct 18 20:00:01 web sshd[1234]: Failed password for root from 203.0.113.7 port 52211 ssh2",
			ok:    true, ip: "203.0.113.7", kind: event.KindAuthFail, user: "root",
		},
		{
			name:  "failed password invalid user, RFC3339 prefix, sshd-session",
			mode:  syslog,
			input: "2026-10-18T20:00:01.123456+08:00 web sshd-session[99]: Failed password for invalid user admin from 203.0.113.7 port 52211 ssh2",
			ok:    true, ip: "203.0.113.7", kind: event.KindAuthFail, user: "admin",
		},
		{
			name:  "invalid user ipv6",
			mode:  msg,
			input: "Invalid user oracle from 2001:db8::7 port 40000",
			ok:    true, ip: "2001:db8::7", kind: event.KindInvalidUser, user: "oracle",
		},
		{
			name:  "accepted publickey",
			mode:  msg,
			input: "Accepted publickey for alice from 198.51.100.4 port 50000 ssh2: ED25519 SHA256:abc",
			ok:    true, ip: "198.51.100.4", kind: event.KindAuthSuccess, user: "alice",
		},
		{
			name:  "accepted password without key suffix",
			mode:  msg,
			input: "Accepted password for bob from 198.51.100.5 port 50001 ssh2",
			ok:    true, ip: "198.51.100.5", kind: event.KindAuthSuccess, user: "bob",
		},
		{
			name:  "connection closed by authenticating user",
			mode:  msg,
			input: "Connection closed by authenticating user root 203.0.113.8 port 1234 [preauth]",
			ok:    true, ip: "203.0.113.8", kind: event.KindPreauthClose, user: "root",
		},
		{
			name:  "disconnected from invalid user",
			mode:  msg,
			input: "Disconnected from invalid user test 203.0.113.9 port 22 [preauth]",
			ok:    true, ip: "203.0.113.9", kind: event.KindInvalidUser, user: "test",
		},
		{
			name:  "connection closed by invalid user",
			mode:  msg,
			input: "Connection closed by invalid user guest 203.0.113.13 port 23 [preauth]",
			ok:    true, ip: "203.0.113.13", kind: event.KindInvalidUser, user: "guest",
		},
		{
			name:  "connection closed preauth without user",
			mode:  msg,
			input: "Connection closed by 203.0.113.10 port 5555 [preauth]",
			ok:    true, ip: "203.0.113.10", kind: event.KindPreauthClose, user: "",
		},
		{
			name:  "maximum authentication attempts exceeded",
			mode:  msg,
			input: "maximum authentication attempts exceeded for root from 203.0.113.11 port 22 ssh2 [preauth]",
			ok:    true, ip: "203.0.113.11", kind: event.KindAuthFail, user: "root",
		},
		{
			name:  "maximum authentication attempts exceeded invalid user",
			mode:  msg,
			input: "maximum authentication attempts exceeded for invalid user nobody from 203.0.113.14 port 22 ssh2 [preauth]",
			ok:    true, ip: "203.0.113.14", kind: event.KindAuthFail, user: "nobody",
		},
		{
			name:  "mapped ipv4-in-ipv6 is unmapped",
			mode:  msg,
			input: "Failed password for root from ::ffff:203.0.113.12 port 1 ssh2",
			ok:    true, ip: "203.0.113.12", kind: event.KindAuthFail, user: "root",
		},
		{
			name:  "forged source in invalid user name",
			mode:  msg,
			input: "Invalid user x from 9.9.9.9 port 22 from 203.0.113.20 port 4444",
			ok:    true, ip: "203.0.113.20", kind: event.KindInvalidUser, user: "x from 9.9.9.9 port 22",
		},
		{
			name:  "forged source in failed password user name",
			mode:  msg,
			input: "Failed password for invalid user y from 8.8.8.8 port 1 from 203.0.113.21 port 2 ssh2",
			ok:    true, ip: "203.0.113.21", kind: event.KindAuthFail, user: "y from 8.8.8.8 port 1",
		},
		{
			name:  "forged source through syslog path",
			mode:  syslog,
			input: "Oct 18 20:00:01 web sshd[7]: Invalid user z from 9.9.9.9 port 22 from 203.0.113.22 port 4444",
			ok:    true, ip: "203.0.113.22", kind: event.KindInvalidUser, user: "z from 9.9.9.9 port 22",
		},
		{
			name:  "client-controlled tail is unsupported",
			mode:  msg,
			input: "Received disconnect from 203.0.113.30 port 1:11: Bye from 9.9.9.9 port 2 [preauth]",
			ok:    false,
		},
		{
			name:  "trailing text after anchored tail is rejected",
			mode:  msg,
			input: "Failed password for root from 203.0.113.7 port 52211 ssh2 from 9.9.9.9 port 1 evil",
			ok:    false,
		},
		{
			name:  "embedded newline is rejected",
			mode:  msg,
			input: "Invalid user a\nfrom 9.9.9.9 port 1 from 203.0.113.23 port 2",
			ok:    false,
		},
		{
			name:  "not sshd program (sudo)",
			mode:  syslog,
			input: "Oct 18 20:00:01 web sudo[1]: alice : TTY=pts/0 ; COMMAND=/bin/ls",
			ok:    false,
		},
		{
			name:  "sshd text smuggled inside another program's line",
			mode:  syslog,
			input: "Oct 18 20:00:01 web cron[5]: (root) CMD (sshd[1]: Failed password for root from 9.9.9.9 port 1 ssh2)",
			ok:    false,
		},
		{
			name:  "syslog parser requires a prefix",
			mode:  syslog,
			input: "Failed password for root from 203.0.113.7 port 52211 ssh2",
			ok:    false,
		},
		{
			name:  "invalid ip literal",
			mode:  msg,
			input: "Failed password for root from not-an-ip port 22 ssh2",
			ok:    false,
		},
		{
			name:  "malformed ip made of address characters",
			mode:  msg,
			input: "Failed password for root from 999.1.1.1 port 22 ssh2",
			ok:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var (
				ev event.Event
				ok bool
			)
			switch tc.mode {
			case syslog:
				ev, ok = ParseSSHDSyslog(tc.input, now)
			default:
				ev, ok = ParseSSHDMessage(tc.input, now)
			}
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
			if ev.Kind != tc.kind {
				t.Errorf("Kind = %q, want %q", ev.Kind, tc.kind)
			}
			if ev.User != tc.user {
				t.Errorf("User = %q, want %q", ev.User, tc.user)
			}
			if ev.Source != "sshd" {
				t.Errorf("Source = %q, want sshd", ev.Source)
			}
			if !ev.Time.Equal(now) {
				t.Errorf("Time = %v, want %v", ev.Time, now)
			}
		})
	}
}

func TestParseSSHDMappedIsIPv4(t *testing.T) {
	now := time.Date(2026, 10, 18, 20, 0, 0, 0, time.UTC)
	ev, ok := ParseSSHDMessage("Failed password for root from ::ffff:203.0.113.12 port 1 ssh2", now)
	if !ok {
		t.Fatal("expected ok")
	}
	if !ev.IP.Is4() {
		t.Fatalf("IP %v: Is4() = false, want true", ev.IP)
	}
}
