package allowlist

import (
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)

func addr(s string) netip.Addr     { return netip.MustParseAddr(s) }
func prefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }

func prefixStrings(ps []netip.Prefix) string {
	s := make([]string, len(ps))
	for i, p := range ps {
		s[i] = p.String()
	}
	return strings.Join(s, " ")
}

// checkAllowed asserts l.Allowed(ip, now) == want for each ip.
func checkAllowed(t *testing.T, l *List, now time.Time, want bool, ips ...string) {
	t.Helper()
	for _, s := range ips {
		if got := l.Allowed(addr(s), now); got != want {
			t.Errorf("Allowed(%s) = %v, want %v", s, got, want)
		}
	}
}

func TestConstants(t *testing.T) {
	if SuccessTTL != 24*time.Hour {
		t.Errorf("SuccessTTL = %v, want 24h", SuccessTTL)
	}
	if UTMPPath != "/var/run/utmp" {
		t.Errorf("UTMPPath = %q", UTMPPath)
	}
}

func TestListsVerbatim(t *testing.T) {
	wantBuiltin := "127.0.0.0/8 ::1/128 0.0.0.0/8 ::/128 169.254.0.0/16 fe80::/10 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 fc00::/7"
	if got := prefixStrings(Builtin); got != wantBuiltin {
		t.Errorf("Builtin =\n %s\nwant\n %s", got, wantBuiltin)
	}
	wantCF := "173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13 104.24.0.0/14 172.64.0.0/13 131.0.72.0/22 2400:cb00::/32 2606:4700::/32 2803:f800::/32 2405:b500::/32 2405:8100::/32 2a06:98c0::/29 2c0f:f248::/32"
	if got := prefixStrings(Cloudflare); got != wantCF {
		t.Errorf("Cloudflare =\n %s\nwant\n %s", got, wantCF)
	}
}

func TestBuiltin(t *testing.T) {
	l := New()
	checkAllowed(t, l, t0, true,
		"127.0.0.1", "10.1.2.3", "172.16.5.5", "192.168.1.1", "100.64.1.1",
		"fe80::1", "fd00::1", "::1", "::ffff:10.0.0.1")
	checkAllowed(t, l, t0, false, "203.0.113.7")
}

func TestBuiltinEdges(t *testing.T) {
	l := New()
	checkAllowed(t, l, t0, true,
		"0.0.0.0", "0.255.255.255", "::", "127.255.255.255", "169.254.1.1",
		"172.31.255.255", "100.127.255.255", "10.255.255.255", "192.168.255.255",
		"febf::1", "fc00::", "fdff:ffff::1", "::ffff:127.0.0.1", "::ffff:192.168.0.1")
	checkAllowed(t, l, t0, false,
		"1.0.0.0", "11.0.0.1", "126.255.255.255", "128.0.0.1", "169.253.255.255", "169.255.0.0",
		"172.15.255.255", "172.32.0.0", "192.167.255.255", "192.169.0.0",
		"100.63.255.255", "100.128.0.0", "fec0::1", "fe7f::1", "fe00::1", "fbff::1", "fe00::",
		"2001:db8::1", "::2", "::ffff:203.0.113.7")
}

func TestCloudflare(t *testing.T) {
	l := New()
	checkAllowed(t, l, t0, true, "104.16.0.1", "2606:4700::1")
	checkAllowed(t, l, t0, false, "104.28.0.1")
}

func TestCloudflareEveryPrefix(t *testing.T) {
	l := New()
	for _, p := range Cloudflare {
		first := p.Masked().Addr()
		if !l.Allowed(first, t0) {
			t.Errorf("first address %s of %s not allowed", first, p)
		}
	}
	checkAllowed(t, l, t0, true, "104.27.255.255", "2a06:98c7:ffff::1", "162.159.255.255", "172.71.255.255")
	checkAllowed(t, l, t0, false,
		"104.15.255.255", "104.28.0.0", "172.72.0.0", "172.63.255.255", "162.160.0.0", "162.157.255.255",
		"2a06:98c8::", "2606:4701::", "2400:cb01::")
}

func TestSuccessTTL(t *testing.T) {
	l := New()
	ip := addr("203.0.113.7")
	if l.Allowed(ip, t0) {
		t.Fatal("allowed before any success")
	}
	l.NoteSuccess(ip, t0)
	if !l.Allowed(ip, t0.Add(23*time.Hour)) {
		t.Error("not allowed at t0+23h")
	}
	if l.Allowed(ip, t0.Add(25*time.Hour)) {
		t.Error("allowed at t0+25h")
	}
	if l.Allowed(ip, t0.Add(SuccessTTL)) {
		t.Error("allowed at exactly t0+24h (entry should have expired)")
	}
}

func TestSuccessRefreshed(t *testing.T) {
	l := New()
	ip := addr("203.0.113.7")
	l.NoteSuccess(ip, t0)
	l.NoteSuccess(ip, t0.Add(20*time.Hour))
	if !l.Allowed(ip, t0.Add(43*time.Hour)) {
		t.Error("second success did not extend the expiry to t0+44h")
	}
	if l.Allowed(ip, t0.Add(45*time.Hour)) {
		t.Error("allowed at t0+45h")
	}
	// A stale, out-of-order timestamp must never shorten an existing entry.
	l.NoteSuccess(ip, t0)
	if !l.Allowed(ip, t0.Add(43*time.Hour)) {
		t.Error("older NoteSuccess shortened the expiry")
	}
}

func TestSuccessMapped(t *testing.T) {
	l := New()
	l.NoteSuccess(addr("::ffff:203.0.113.7"), t0)
	checkAllowed(t, l, t0.Add(time.Hour), true, "203.0.113.7", "::ffff:203.0.113.7")
}

func TestSuccessSweepBoundsMemory(t *testing.T) {
	l := New()
	for i := range 1000 {
		l.NoteSuccess(netip.AddrFrom4([4]byte{203, 0, byte(i >> 8), byte(i)}), t0)
	}
	if n := len(l.success); n != 1000 {
		t.Fatalf("len(success) = %d, want 1000", n)
	}
	// Long after the entries expired, one new success sweeps all of them.
	later := t0.Add(SuccessTTL + 2*time.Hour)
	l.NoteSuccess(addr("198.51.100.1"), later)
	if n := len(l.success); n != 1 {
		t.Fatalf("len(success) after sweep = %d, want 1 (only the fresh entry)", n)
	}
	checkAllowed(t, l, later, true, "198.51.100.1")
	checkAllowed(t, l, later, false, "203.0.0.1")
}

func TestSessionsReplace(t *testing.T) {
	l := New()
	a, b := "203.0.113.10", "203.0.113.11"
	l.SetSessions([]netip.Addr{addr(a)})
	checkAllowed(t, l, t0, true, a)
	checkAllowed(t, l, t0, false, b)
	l.SetSessions([]netip.Addr{addr(b)})
	checkAllowed(t, l, t0, false, a)
	checkAllowed(t, l, t0, true, b)
	l.SetSessions(nil)
	checkAllowed(t, l, t0, false, a, b)
}

func TestSessionsMapped(t *testing.T) {
	l := New()
	l.SetSessions([]netip.Addr{addr("::ffff:203.0.113.10")})
	checkAllowed(t, l, t0, true, "203.0.113.10", "::ffff:203.0.113.10")
}

func TestLocalAndUser(t *testing.T) {
	l := New()
	l.SetLocal([]netip.Addr{addr("203.0.113.50")})
	l.SetUser([]netip.Prefix{prefix("198.51.100.0/24")})
	checkAllowed(t, l, t0, true, "203.0.113.50", "198.51.100.9")
	checkAllowed(t, l, t0, false, "203.0.113.51", "198.51.101.9")
}

func TestLocalReplace(t *testing.T) {
	l := New()
	l.SetLocal([]netip.Addr{addr("203.0.113.50"), addr("2001:db8::50")})
	checkAllowed(t, l, t0, true, "203.0.113.50", "2001:db8::50")
	l.SetLocal([]netip.Addr{addr("203.0.113.51")})
	checkAllowed(t, l, t0, false, "203.0.113.50", "2001:db8::50")
	checkAllowed(t, l, t0, true, "203.0.113.51")
}

func TestLocalMapped(t *testing.T) {
	l := New()
	l.SetLocal([]netip.Addr{addr("::ffff:203.0.113.50")})
	checkAllowed(t, l, t0, true, "203.0.113.50", "::ffff:203.0.113.50")
}

func TestUserReplaceAndNormalize(t *testing.T) {
	l := New()
	l.SetUser([]netip.Prefix{prefix("198.51.100.0/24"), prefix("2001:db8:1::/48")})
	checkAllowed(t, l, t0, true, "198.51.100.9", "2001:db8:1::5")
	l.SetUser([]netip.Prefix{prefix("192.0.2.0/24")})
	checkAllowed(t, l, t0, false, "198.51.100.9", "2001:db8:1::5")
	checkAllowed(t, l, t0, true, "192.0.2.77")

	// Unmasked prefix: host bits set.
	l.SetUser([]netip.Prefix{prefix("198.51.100.77/24")})
	checkAllowed(t, l, t0, true, "198.51.100.1", "198.51.100.255")
	checkAllowed(t, l, t0, false, "198.51.101.1")

	// IPv4-mapped prefix is converted to an IPv4 prefix: ::ffff:198.51.100.0/120 == 198.51.100.0/24.
	l.SetUser([]netip.Prefix{prefix("::ffff:198.51.100.0/120")})
	checkAllowed(t, l, t0, true, "198.51.100.9", "::ffff:198.51.100.9")
	checkAllowed(t, l, t0, false, "198.51.101.9")

	// Single-host prefixes.
	l.SetUser([]netip.Prefix{prefix("203.0.113.9/32"), prefix("2001:db8::9/128")})
	checkAllowed(t, l, t0, true, "203.0.113.9", "2001:db8::9")
	checkAllowed(t, l, t0, false, "203.0.113.10", "2001:db8::a")

	l.SetUser(nil)
	checkAllowed(t, l, t0, false, "203.0.113.9", "2001:db8::9")
}

func TestUserInvalidPrefixIgnored(t *testing.T) {
	l := New()
	l.SetUser([]netip.Prefix{{}, prefix("198.51.100.0/24")})
	checkAllowed(t, l, t0, true, "198.51.100.9")
	checkAllowed(t, l, t0, false, "203.0.113.9")
}

func TestSettersCopyInput(t *testing.T) {
	l := New()
	sess := []netip.Addr{addr("203.0.113.10")}
	loc := []netip.Addr{addr("203.0.113.11")}
	usr := []netip.Prefix{prefix("198.51.100.0/24")}
	l.SetSessions(sess)
	l.SetLocal(loc)
	l.SetUser(usr)
	sess[0] = addr("192.0.2.1")
	loc[0] = addr("192.0.2.2")
	usr[0] = prefix("192.0.2.0/24")
	checkAllowed(t, l, t0, true, "203.0.113.10", "203.0.113.11", "198.51.100.9")
	checkAllowed(t, l, t0, false, "192.0.2.1", "192.0.2.2", "192.0.2.3")
}

func TestInvalidAddrNotAllowed(t *testing.T) {
	l := New()
	l.SetLocal([]netip.Addr{{}})
	l.SetSessions([]netip.Addr{{}})
	l.NoteSuccess(netip.Addr{}, t0)
	if l.Allowed(netip.Addr{}, t0) {
		t.Error("zero Addr allowed")
	}
	if n := len(l.success); n != 0 {
		t.Errorf("zero Addr recorded as success (%d entries)", n)
	}
}

func TestZoneIgnored(t *testing.T) {
	l := New()
	l.SetLocal([]netip.Addr{addr("2001:db8::50%eth0")})
	checkAllowed(t, l, t0, true, "2001:db8::50", "2001:db8::50%eth0")
	l.SetUser([]netip.Prefix{prefix("2001:db8:1::/48")})
	checkAllowed(t, l, t0, true, "2001:db8:1::5%eth0")
}

// Allowed must be safe against concurrent setters (run with -race).
func TestConcurrent(t *testing.T) {
	l := New()
	var wg sync.WaitGroup
	for g := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ip := netip.AddrFrom4([4]byte{203, 0, 113, byte(g)})
			for i := range 500 {
				now := t0.Add(time.Duration(i) * time.Minute)
				l.Allowed(ip, now)
				l.NoteSuccess(ip, now)
				l.SetSessions([]netip.Addr{ip})
				l.SetLocal([]netip.Addr{ip})
				l.SetUser([]netip.Prefix{prefix("198.51.100.0/24")})
			}
		}()
	}
	wg.Wait()
}

func TestLocalAddrs(t *testing.T) {
	got, err := LocalAddrs()
	if err != nil {
		t.Fatalf("LocalAddrs: %v", err)
	}
	for _, a := range got {
		if !a.IsValid() {
			t.Errorf("invalid address in result: %v", got)
		}
		if a.Is4In6() {
			t.Errorf("address %v not unmapped", a)
		}
		if a.Zone() != "" {
			t.Errorf("address %v has a zone", a)
		}
	}
}

func TestAddrsFromNet(t *testing.T) {
	in := []net.Addr{
		&net.IPNet{IP: net.ParseIP("203.0.113.5"), Mask: net.CIDRMask(24, 32)}, // 16-byte form
		&net.IPNet{IP: net.IP{198, 51, 100, 6}, Mask: net.CIDRMask(24, 32)},    // 4-byte form
		&net.IPNet{IP: net.ParseIP("2001:db8::5"), Mask: net.CIDRMask(64, 128)},
		&net.IPAddr{IP: net.ParseIP("fe80::1"), Zone: "eth0"},
		&net.IPAddr{IP: net.ParseIP("::ffff:192.0.2.7")},
		&net.IPNet{IP: net.IP{1, 2, 3}}, // malformed: skipped
		&net.UnixAddr{Name: "/tmp/x", Net: "unix"},
	}
	want := []netip.Addr{
		addr("203.0.113.5"), addr("198.51.100.6"), addr("2001:db8::5"), addr("fe80::1"), addr("192.0.2.7"),
	}
	if got := addrsFromNet(in); !slices.Equal(got, want) {
		t.Errorf("addrsFromNet = %v, want %v", got, want)
	}
}
