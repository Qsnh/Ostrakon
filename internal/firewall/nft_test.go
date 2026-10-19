package firewall

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// recorder is a Runner that remembers every script it was asked to run.
type recorder struct {
	scripts []string
	err     error
}

func (r *recorder) run(_ context.Context, script string) error {
	r.scripts = append(r.scripts, script)
	return r.err
}

func newNFT(r *recorder) *NFT { return &NFT{Run: r.run} }

// oneScript fails the test unless exactly one script was run, and returns it.
func oneScript(t *testing.T, r *recorder) string {
	t.Helper()
	if len(r.scripts) != 1 {
		t.Fatalf("Runner called %d times, want 1: %q", len(r.scripts), r.scripts)
	}
	return r.scripts[0]
}

func TestEnsureScript(t *testing.T) {
	r := &recorder{}
	if err := newNFT(r).Ensure(context.Background()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	want := "add table inet ostrakon\n" +
		"add set inet ostrakon banned_v4 { type ipv4_addr; flags timeout; }\n" +
		"add set inet ostrakon banned_v6 { type ipv6_addr; flags timeout; }\n" +
		"add chain inet ostrakon prerouting { type filter hook prerouting priority -200; policy accept; }\n" +
		"flush chain inet ostrakon prerouting\n" +
		"add rule inet ostrakon prerouting ip saddr @banned_v4 drop\n" +
		"add rule inet ostrakon prerouting ip6 saddr @banned_v6 drop\n"
	if got := oneScript(t, r); got != want {
		t.Fatalf("Ensure script mismatch\ngot:\n%s\nwant:\n%s", got, want)
	}
}

func TestBanScriptV4(t *testing.T) {
	r := &recorder{}
	if err := newNFT(r).Ban(context.Background(), netip.MustParseAddr("203.0.113.7"), time.Hour); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	want := "add element inet ostrakon banned_v4 { 203.0.113.7 }\n" +
		"delete element inet ostrakon banned_v4 { 203.0.113.7 }\n" +
		"add element inet ostrakon banned_v4 { 203.0.113.7 timeout 3600s }\n"
	if got := oneScript(t, r); got != want {
		t.Fatalf("Ban script mismatch\ngot:\n%s\nwant:\n%s", got, want)
	}
}

func TestBanScriptV6(t *testing.T) {
	r := &recorder{}
	if err := newNFT(r).Ban(context.Background(), netip.MustParseAddr("2001:db8::7"), 90*time.Second); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	want := "add element inet ostrakon banned_v6 { 2001:db8::7 }\n" +
		"delete element inet ostrakon banned_v6 { 2001:db8::7 }\n" +
		"add element inet ostrakon banned_v6 { 2001:db8::7 timeout 90s }\n"
	if got := oneScript(t, r); got != want {
		t.Fatalf("Ban script mismatch\ngot:\n%s\nwant:\n%s", got, want)
	}
}

func TestUnbanScript(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want string
	}{
		{"v4", "203.0.113.7",
			"add element inet ostrakon banned_v4 { 203.0.113.7 }\n" +
				"delete element inet ostrakon banned_v4 { 203.0.113.7 }\n"},
		{"v6", "2001:db8::7",
			"add element inet ostrakon banned_v6 { 2001:db8::7 }\n" +
				"delete element inet ostrakon banned_v6 { 2001:db8::7 }\n"},
		{"mapped", "::ffff:203.0.113.12",
			"add element inet ostrakon banned_v4 { 203.0.113.12 }\n" +
				"delete element inet ostrakon banned_v4 { 203.0.113.12 }\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &recorder{}
			if err := newNFT(r).Unban(context.Background(), netip.MustParseAddr(tt.ip)); err != nil {
				t.Fatalf("Unban: %v", err)
			}
			if got := oneScript(t, r); got != tt.want {
				t.Fatalf("Unban script mismatch\ngot:\n%s\nwant:\n%s", got, tt.want)
			}
		})
	}
}

// An IPv4-mapped IPv6 address must land in the IPv4 set, otherwise the
// prerouting "ip saddr" rule would never match the attacker.
func TestBanMapped(t *testing.T) {
	r := &recorder{}
	if err := newNFT(r).Ban(context.Background(), netip.MustParseAddr("::ffff:203.0.113.12"), time.Minute); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	want := "add element inet ostrakon banned_v4 { 203.0.113.12 }\n" +
		"delete element inet ostrakon banned_v4 { 203.0.113.12 }\n" +
		"add element inet ostrakon banned_v4 { 203.0.113.12 timeout 60s }\n"
	if got := oneScript(t, r); got != want {
		t.Fatalf("Ban script mismatch\ngot:\n%s\nwant:\n%s", got, want)
	}
}

// A zone is not valid nft element syntax; it must never reach the script.
func TestBanDropsZone(t *testing.T) {
	r := &recorder{}
	ip := netip.MustParseAddr("fe80::1%eth0")
	if err := newNFT(r).Ban(context.Background(), ip, time.Minute); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	want := "add element inet ostrakon banned_v6 { fe80::1 }\n" +
		"delete element inet ostrakon banned_v6 { fe80::1 }\n" +
		"add element inet ostrakon banned_v6 { fe80::1 timeout 60s }\n"
	if got := oneScript(t, r); got != want {
		t.Fatalf("Ban script mismatch\ngot:\n%s\nwant:\n%s", got, want)
	}
}

func TestTTLRounding(t *testing.T) {
	ip := netip.MustParseAddr("203.0.113.7")
	tests := []struct {
		ttl  time.Duration
		want string
	}{
		{1500 * time.Millisecond, "2s"},
		{time.Second, "1s"},
		{2 * time.Second, "2s"},
		{2*time.Second + time.Nanosecond, "3s"},
		{time.Duration(1<<63 - 1), "9223372037s"}, // must not overflow while rounding up
	}
	for _, tt := range tests {
		t.Run(tt.ttl.String(), func(t *testing.T) {
			r := &recorder{}
			if err := newNFT(r).Ban(context.Background(), ip, tt.ttl); err != nil {
				t.Fatalf("Ban(%v): %v", tt.ttl, err)
			}
			want := "add element inet ostrakon banned_v4 { 203.0.113.7 }\n" +
				"delete element inet ostrakon banned_v4 { 203.0.113.7 }\n" +
				"add element inet ostrakon banned_v4 { 203.0.113.7 timeout " + tt.want + " }\n"
			if got := oneScript(t, r); got != want {
				t.Fatalf("Ban(%v) script mismatch\ngot:\n%s\nwant:\n%s", tt.ttl, got, want)
			}
		})
	}
}

func TestBanRejectsBadTTL(t *testing.T) {
	ip := netip.MustParseAddr("203.0.113.7")
	for _, ttl := range []time.Duration{0, -time.Second, time.Nanosecond, 999 * time.Millisecond} {
		r := &recorder{}
		if err := newNFT(r).Ban(context.Background(), ip, ttl); err == nil {
			t.Fatalf("Ban(ttl=%v) = nil, want error", ttl)
		}
		if len(r.scripts) != 0 {
			t.Fatalf("Runner called for ttl %v: %q", ttl, r.scripts)
		}
	}
}

func TestInvalidAddr(t *testing.T) {
	r := &recorder{}
	n := newNFT(r)
	if err := n.Ban(context.Background(), netip.Addr{}, time.Hour); err == nil {
		t.Fatal("Ban(zero addr) = nil, want error")
	}
	if err := n.Unban(context.Background(), netip.Addr{}); err == nil {
		t.Fatal("Unban(zero addr) = nil, want error")
	}
	if len(r.scripts) != 0 {
		t.Fatalf("Runner called for invalid address: %q", r.scripts)
	}
}

func TestRunnerError(t *testing.T) {
	boom := errors.New("nft exploded")
	ip := netip.MustParseAddr("203.0.113.7")
	calls := map[string]func(*NFT) error{
		"Ensure": func(n *NFT) error { return n.Ensure(context.Background()) },
		"Ban":    func(n *NFT) error { return n.Ban(context.Background(), ip, time.Hour) },
		"Unban":  func(n *NFT) error { return n.Unban(context.Background(), ip) },
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			r := &recorder{err: boom}
			err := call(newNFT(r))
			if !errors.Is(err, boom) {
				t.Fatalf("%s error = %v, want it to wrap %v", name, err, boom)
			}
		})
	}
}

// The context handed to Ban must be the one the Runner sees, so a daemon
// shutdown can cancel a stuck nft.
func TestContextPassedToRunner(t *testing.T) {
	type key struct{}
	ctx := context.WithValue(context.Background(), key{}, "marker")
	var seen context.Context
	n := &NFT{Run: func(c context.Context, _ string) error { seen = c; return nil }}
	if err := n.Ban(ctx, netip.MustParseAddr("203.0.113.7"), time.Hour); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	if seen == nil || seen.Value(key{}) != "marker" {
		t.Fatal("Runner did not receive the caller's context")
	}
}

// cmdRecorder is a CmdRunner that remembers its arguments and answers err.
type cmdRecorder struct {
	args [][]string
	err  error
}

func (c *cmdRecorder) run(_ context.Context, args ...string) error {
	c.args = append(c.args, args)
	return c.err
}

func TestPresent(t *testing.T) {
	notFound := errors.New("nft: exit status 1: Error: No such file or directory; did you mean table 'ostrakon' in family ip?\n" +
		"list table inet ostrakon\n                 ^^^^^^^^")
	denied := errors.New("nft: exit status 1: Error: Operation not permitted")
	tests := []struct {
		name    string
		err     error
		present bool
		wantErr bool
	}{
		{"listed", nil, true, false},
		{"no such table", notFound, false, false},
		{"other failure", denied, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, c := &recorder{}, &cmdRecorder{err: tt.err}
			n := &NFT{Run: r.run, Cmd: c.run}
			present, err := n.Present(context.Background())
			if present != tt.present || (err != nil) != tt.wantErr {
				t.Fatalf("Present = %v, %v; want %v, error %v", present, err, tt.present, tt.wantErr)
			}
			if tt.wantErr && !errors.Is(err, denied) {
				t.Errorf("error %v does not wrap the command's", err)
			}
			if want := [][]string{{"list", "table", "inet", "ostrakon"}}; !reflect.DeepEqual(c.args, want) {
				t.Errorf("command args = %q, want %q", c.args, want)
			}
			if len(r.scripts) != 0 {
				t.Errorf("Present ran an nft script: %q", r.scripts)
			}
		})
	}
}

// ExecCmd runs the nft on PATH with the arguments, drops what it prints on
// stdout (a listing of every ban) and reports its stderr on failure. A stub
// nft stands in for the real one.
func TestExecCmdWithStubNFT(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs a shell")
	}
	dir := t.TempDir()
	stub := "#!/bin/sh\n" +
		"[ \"$*\" = \"list table inet ostrakon\" ] || { echo \"Error: unexpected arguments: $*\" >&2; exit 1; }\n" +
		"if [ -n \"$STUB_MISSING\" ]; then echo \"Error: No such file or directory; did you mean table 'ostrakon' in family ip?\" >&2; exit 1; fi\n" +
		"echo 'table inet ostrakon {'\n"
	if err := os.WriteFile(filepath.Join(dir, "nft"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	n := &NFT{Run: ExecRunner, Cmd: ExecCmd}

	t.Setenv("STUB_MISSING", "")
	if present, err := n.Present(context.Background()); !present || err != nil {
		t.Fatalf("Present = %v, %v; want true, nil", present, err)
	}
	t.Setenv("STUB_MISSING", "1")
	if present, err := n.Present(context.Background()); present || err != nil {
		t.Fatalf("Present = %v, %v; want false, nil", present, err)
	}
	err := ExecCmd(context.Background(), "list", "ruleset")
	if err == nil || !strings.Contains(err.Error(), "unexpected arguments: list ruleset") {
		t.Fatalf("ExecCmd error = %v, want the stub's stderr", err)
	}
}

// --- Fake ---

func TestFakeMissing(t *testing.T) {
	f := NewFake()
	ctx := context.Background()
	ip := netip.MustParseAddr("203.0.113.7")
	if present, err := f.Present(ctx); !present || err != nil {
		t.Fatalf("Present = %v, %v; want true, nil", present, err)
	}
	f.Missing = true
	if present, err := f.Present(ctx); present || err != nil {
		t.Fatalf("Present with Missing = %v, %v; want false, nil", present, err)
	}
	// Like nft, no element can be added to or removed from a missing table.
	if err := f.Ban(ctx, ip, time.Hour); err == nil {
		t.Fatal("Ban succeeded on a missing table")
	}
	if err := f.Unban(ctx, ip); err == nil {
		t.Fatal("Unban succeeded on a missing table")
	}
	if err := f.Ensure(ctx); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if f.Missing {
		t.Fatal("Ensure did not rebuild the table")
	}
	if err := f.Ban(ctx, ip, time.Hour); err != nil {
		t.Fatalf("Ban after Ensure: %v", err)
	}
	// A failing Ensure rebuilds nothing.
	f.Missing = true
	f.Err = errors.New("injected")
	if err := f.Ensure(ctx); err == nil || !f.Missing {
		t.Fatalf("failing Ensure = %v, Missing = %v; want an error and still missing", err, f.Missing)
	}
	if _, err := f.Present(ctx); !errors.Is(err, f.Err) {
		t.Fatalf("Present with Err = %v, want %v", err, f.Err)
	}
}

func TestFakeRecordsAndNormalises(t *testing.T) {
	f := NewFake()
	ctx := context.Background()
	if err := f.Ensure(ctx); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if err := f.Ensure(ctx); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if f.EnsureCalls != 2 {
		t.Fatalf("EnsureCalls = %d, want 2", f.EnsureCalls)
	}

	if err := f.Ban(ctx, netip.MustParseAddr("::ffff:203.0.113.12"), time.Hour); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	if err := f.Ban(ctx, netip.MustParseAddr("2001:db8::7"), time.Minute); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	v4, v6 := netip.MustParseAddr("203.0.113.12"), netip.MustParseAddr("2001:db8::7")
	if got, ok := f.Banned[v4]; !ok || got != time.Hour {
		t.Fatalf("Banned[%v] = %v, %v; want 1h, true", v4, got, ok)
	}
	if got, ok := f.Banned[v6]; !ok || got != time.Minute {
		t.Fatalf("Banned[%v] = %v, %v; want 1m, true", v6, got, ok)
	}

	// Re-banning refreshes the timeout rather than adding a second entry.
	if err := f.Ban(ctx, v4, 2*time.Hour); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	if len(f.Banned) != 2 || f.Banned[v4] != 2*time.Hour {
		t.Fatalf("Banned = %v, want v4 refreshed to 2h and 2 entries", f.Banned)
	}

	if err := f.Unban(ctx, netip.MustParseAddr("::ffff:203.0.113.12")); err != nil {
		t.Fatalf("Unban: %v", err)
	}
	if _, ok := f.Banned[v4]; ok || len(f.Banned) != 1 {
		t.Fatalf("Banned = %v, want only %v", f.Banned, v6)
	}
	// Unbanning something that is not banned is not an error, like the
	// real add-then-delete script.
	if err := f.Unban(ctx, v4); err != nil {
		t.Fatalf("Unban of absent address: %v", err)
	}
}

func TestFakeErr(t *testing.T) {
	boom := errors.New("injected")
	f := NewFake()
	f.Err = boom
	ctx := context.Background()
	ip := netip.MustParseAddr("203.0.113.7")

	if err := f.Ensure(ctx); !errors.Is(err, boom) {
		t.Fatalf("Ensure = %v, want %v", err, boom)
	}
	if err := f.Ban(ctx, ip, time.Hour); !errors.Is(err, boom) {
		t.Fatalf("Ban = %v, want %v", err, boom)
	}
	if err := f.Unban(ctx, ip); !errors.Is(err, boom) {
		t.Fatalf("Unban = %v, want %v", err, boom)
	}
	if len(f.Banned) != 0 {
		t.Fatalf("Banned = %v, want nothing recorded while failing", f.Banned)
	}
}

func TestFakeConcurrent(t *testing.T) {
	f := NewFake()
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ip := netip.AddrFrom4([4]byte{203, 0, 113, byte(i)})
			_ = f.Ensure(ctx)
			_ = f.Ban(ctx, ip, time.Hour)
			if i%2 == 0 {
				_ = f.Unban(ctx, ip)
			}
		}()
	}
	wg.Wait()
	f.Mu.Lock()
	defer f.Mu.Unlock()
	if f.EnsureCalls != 50 || len(f.Banned) != 25 {
		t.Fatalf("EnsureCalls=%d banned=%d, want 50 and 25", f.EnsureCalls, len(f.Banned))
	}
}

// Both implementations satisfy the interface Task 11 depends on.
var (
	_ Firewall = (*NFT)(nil)
	_ Firewall = (*Fake)(nil)
)
