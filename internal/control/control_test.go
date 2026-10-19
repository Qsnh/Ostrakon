package control

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"syscall"
	"testing"
	"time"

	"ostrakon/internal/daemon"
	"ostrakon/internal/state"
)

// fakeBackend records what the server asked of it. The mutex is needed
// because the race detector cannot see the happens-before edge that a socket
// round trip provides.
type fakeBackend struct {
	mu         sync.Mutex
	status     daemon.Status
	bans       []state.Ban
	unbanned   []netip.Addr
	allowed    []netip.Prefix
	disallowed []netip.Prefix
	err        error // returned by Unban, Allow and Disallow
}

func (f *fakeBackend) Status() daemon.Status { return f.status }
func (f *fakeBackend) Bans() []state.Ban     { return f.bans }

func (f *fakeBackend) Unban(_ context.Context, ip netip.Addr) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.unbanned = append(f.unbanned, ip)
	return f.err
}

func (f *fakeBackend) Allow(_ context.Context, p netip.Prefix) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.allowed = append(f.allowed, p)
	return f.err
}

func (f *fakeBackend) Disallow(p netip.Prefix) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.disallowed = append(f.disallowed, p)
	return f.err
}

// tempDir returns a short directory: unix socket paths are limited to about
// 104 bytes on macOS, and t.TempDir() paths are longer than that.
func tempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "ostk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// startServe runs Serve on path and waits until it accepts connections. The
// returned function cancels Serve and returns its result.
func startServe(t *testing.T, path string, b Backend) (stop func() error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, path, b) }()

	deadline := time.Now().Add(5 * time.Second)
	for {
		// A dial that works, not just a file that exists: the file may be a
		// stale socket that Serve has yet to replace.
		if c, err := net.Dial("unix", path); err == nil {
			_ = c.Close()
			break
		}
		select {
		case err := <-done:
			cancel()
			t.Fatalf("Serve returned before it was listening: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("Serve did not start listening")
		}
		time.Sleep(5 * time.Millisecond)
	}
	stopped := false
	stopFn := func() error {
		cancel()
		select {
		case err := <-done:
			stopped = true
			return err
		case <-time.After(5 * time.Second):
			t.Fatal("Serve did not return after cancel")
			return nil
		}
	}
	t.Cleanup(func() {
		if !stopped {
			_ = stopFn()
		}
	})
	return stopFn
}

func TestServeRoundTrip(t *testing.T) {
	now := time.Date(2026, 10, 18, 20, 0, 0, 0, time.UTC)
	b := &fakeBackend{
		status: daemon.Status{
			Paused:       true,
			PauseReason:  "jev: status 401",
			PausedSince:  now,
			Sources:      []string{"sshd(/var/log/auth.log)"},
			BanCount:     1,
			LastDecision: "2026-10-18T20:00:05Z 203.0.113.7 ssh_bruteforce p=0.93 ban 1h",
		},
		bans: []state.Ban{{
			IP:       netip.MustParseAddr("203.0.113.7"),
			Since:    now,
			Until:    now.Add(time.Hour),
			Category: "ssh_bruteforce",
		}},
	}
	dir := tempDir(t)
	path := filepath.Join(dir, "ostrakon.sock")
	stop := startServe(t, path, b)

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("socket mode = %v, want 0600", fi.Mode().Perm())
	}

	t.Run("status", func(t *testing.T) {
		resp, err := Call(path, Request{Cmd: "status"})
		if err != nil {
			t.Fatal(err)
		}
		if !resp.OK || resp.Status == nil {
			t.Fatalf("resp = %+v", resp)
		}
		if !reflect.DeepEqual(*resp.Status, b.status) {
			t.Errorf("status = %+v, want %+v", *resp.Status, b.status)
		}
	})

	t.Run("bans", func(t *testing.T) {
		resp, err := Call(path, Request{Cmd: "bans"})
		if err != nil {
			t.Fatal(err)
		}
		if !resp.OK || !reflect.DeepEqual(resp.Bans, b.bans) {
			t.Errorf("resp = %+v, want bans %+v", resp, b.bans)
		}
	})

	t.Run("unban", func(t *testing.T) {
		resp, err := Call(path, Request{Cmd: "unban", Arg: "203.0.113.7"})
		if err != nil || !resp.OK {
			t.Fatalf("resp = %+v, err = %v", resp, err)
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		if want := []netip.Addr{netip.MustParseAddr("203.0.113.7")}; !reflect.DeepEqual(b.unbanned, want) {
			t.Errorf("unbanned = %v, want %v", b.unbanned, want)
		}
	})

	t.Run("unban of a mapped address reaches the backend unmapped", func(t *testing.T) {
		resp, err := Call(path, Request{Cmd: "unban", Arg: "::ffff:203.0.113.8"})
		if err != nil || !resp.OK {
			t.Fatalf("resp = %+v, err = %v", resp, err)
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		if got := b.unbanned[len(b.unbanned)-1]; got != netip.MustParseAddr("203.0.113.8") {
			t.Errorf("backend got %v, want 203.0.113.8", got)
		}
	})

	t.Run("unban of garbage", func(t *testing.T) {
		b.mu.Lock()
		before := len(b.unbanned)
		b.mu.Unlock()
		resp, err := Call(path, Request{Cmd: "unban", Arg: "nope"})
		if err != nil {
			t.Fatal(err)
		}
		if resp.OK || resp.Error == "" {
			t.Errorf("resp = %+v, want a failure with a message", resp)
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		if len(b.unbanned) != before {
			t.Error("the backend was called for an invalid address")
		}
	})

	t.Run("allow", func(t *testing.T) {
		resp, err := Call(path, Request{Cmd: "allow", Arg: "198.51.100.0/24"})
		if err != nil || !resp.OK {
			t.Fatalf("resp = %+v, err = %v", resp, err)
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		if want := []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}; !reflect.DeepEqual(b.allowed, want) {
			t.Errorf("allowed = %v, want %v", b.allowed, want)
		}
	})

	t.Run("allow of a single address becomes a host prefix", func(t *testing.T) {
		resp, err := Call(path, Request{Cmd: "allow", Arg: "2001:db8::1"})
		if err != nil || !resp.OK {
			t.Fatalf("resp = %+v, err = %v", resp, err)
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		if got := b.allowed[len(b.allowed)-1]; got != netip.MustParsePrefix("2001:db8::1/128") {
			t.Errorf("backend got %v, want 2001:db8::1/128", got)
		}
	})

	t.Run("disallow", func(t *testing.T) {
		resp, err := Call(path, Request{Cmd: "disallow", Arg: "198.51.100.0/24"})
		if err != nil || !resp.OK {
			t.Fatalf("resp = %+v, err = %v", resp, err)
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		if want := []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}; !reflect.DeepEqual(b.disallowed, want) {
			t.Errorf("disallowed = %v, want %v", b.disallowed, want)
		}
	})

	t.Run("allow of garbage", func(t *testing.T) {
		resp, err := Call(path, Request{Cmd: "allow", Arg: "x"})
		if err != nil {
			t.Fatal(err)
		}
		if resp.OK || resp.Error == "" {
			t.Errorf("resp = %+v, want a failure with a message", resp)
		}
	})

	t.Run("unknown command", func(t *testing.T) {
		resp, err := Call(path, Request{Cmd: "reboot"})
		if err != nil {
			t.Fatal(err)
		}
		if resp.OK || resp.Error != "unknown command" {
			t.Errorf("resp = %+v, want Error %q", resp, "unknown command")
		}
	})

	t.Run("backend error is reported", func(t *testing.T) {
		b.mu.Lock()
		b.err = errors.New("nft: boom")
		b.mu.Unlock()
		defer func() {
			b.mu.Lock()
			b.err = nil
			b.mu.Unlock()
		}()
		resp, err := Call(path, Request{Cmd: "unban", Arg: "203.0.113.9"})
		if err != nil {
			t.Fatal(err)
		}
		if resp.OK || resp.Error != "nft: boom" {
			t.Errorf("resp = %+v, want Error %q", resp, "nft: boom")
		}
	})

	if err := stop(); err != nil {
		t.Errorf("Serve returned %v after cancel, want nil", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("socket file still there after Serve returned: %v", err)
	}
}

func TestServeCreatesParentDirectory(t *testing.T) {
	dir := tempDir(t)
	parent := filepath.Join(dir, "run", "ostrakon")
	path := filepath.Join(parent, "ostrakon.sock")
	startServe(t, path, &fakeBackend{})

	fi, err := os.Stat(parent)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o755 {
		t.Errorf("parent mode = %v, want 0755", fi.Mode().Perm())
	}
}

func TestServeReplacesStaleSocket(t *testing.T) {
	dir := tempDir(t)
	path := filepath.Join(dir, "ostrakon.sock")

	// A socket file nobody listens on, as a crashed daemon leaves behind.
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = ln.Close()
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("stale socket not set up: %v", err)
	}

	startServe(t, path, &fakeBackend{})
	resp, err := Call(path, Request{Cmd: "status"})
	if err != nil || !resp.OK {
		t.Fatalf("resp = %+v, err = %v", resp, err)
	}
}

func TestServeRefusesToStealALiveSocket(t *testing.T) {
	dir := tempDir(t)
	path := filepath.Join(dir, "ostrakon.sock")
	startServe(t, path, &fakeBackend{})

	err := Serve(context.Background(), path, &fakeBackend{})
	if err == nil {
		t.Fatal("a second Serve on a live socket succeeded")
	}
	// The first daemon must be unharmed.
	resp, err := Call(path, Request{Cmd: "status"})
	if err != nil || !resp.OK {
		t.Fatalf("first server broken: resp = %+v, err = %v", resp, err)
	}
}

func TestServeDoesNotRemoveANonSocket(t *testing.T) {
	dir := tempDir(t)
	path := filepath.Join(dir, "ostrakon.sock")
	if err := os.WriteFile(path, []byte("precious"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Serve(context.Background(), path, &fakeBackend{}); err == nil {
		t.Fatal("Serve succeeded over a regular file")
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "precious" {
		t.Errorf("the file was damaged: %q, %v", data, err)
	}
}

func TestServeSurvivesBadClients(t *testing.T) {
	dir := tempDir(t)
	path := filepath.Join(dir, "ostrakon.sock")
	startServe(t, path, &fakeBackend{})

	// Connects and hangs up without a word (what Running does).
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()

	// Sends garbage and expects a failure answer, not a dead server.
	c, err = net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte("this is not json\n")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 512)
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := c.Read(buf)
	_ = c.Close()
	if err != nil || n == 0 {
		t.Fatalf("no answer to garbage: n=%d err=%v", n, err)
	}

	resp, err := Call(path, Request{Cmd: "status"})
	if err != nil || !resp.OK {
		t.Fatalf("server not usable after bad clients: resp = %+v, err = %v", resp, err)
	}
}

func TestCallErrors(t *testing.T) {
	dir := tempDir(t)

	t.Run("missing socket", func(t *testing.T) {
		_, err := Call(filepath.Join(dir, "nope.sock"), Request{Cmd: "status"})
		if err == nil || !NotRunning(err) {
			t.Errorf("err = %v, want one NotRunning accepts", err)
		}
	})

	t.Run("socket nobody listens on", func(t *testing.T) {
		path := filepath.Join(dir, "stale.sock")
		ln, err := net.Listen("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		ln.(*net.UnixListener).SetUnlinkOnClose(false)
		_ = ln.Close()
		_, err = Call(path, Request{Cmd: "status"})
		if err == nil || !NotRunning(err) {
			t.Errorf("err = %v, want one NotRunning accepts", err)
		}
	})
}

func TestNotRunning(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"missing", fmt.Errorf("dial: %w", fs.ErrNotExist), true},
		{"refused", fmt.Errorf("dial: %w", syscall.ECONNREFUSED), true},
		{"permission", fmt.Errorf("dial: %w", syscall.EACCES), false},
		{"other", errors.New("boom"), false},
	}
	for _, c := range cases {
		if got := NotRunning(c.err); got != c.want {
			t.Errorf("%s: NotRunning = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestRunning(t *testing.T) {
	dir := tempDir(t)
	path := filepath.Join(dir, "ostrakon.sock")
	if Running(path) {
		t.Error("Running = true with no socket")
	}
	stop := startServe(t, path, &fakeBackend{})
	if !Running(path) {
		t.Error("Running = false with a live server")
	}
	_ = stop()
	if Running(path) {
		t.Error("Running = true after the server stopped")
	}
}

func TestParsePrefix(t *testing.T) {
	cases := []struct {
		in   string
		want string // "" means an error is expected
	}{
		{"203.0.113.7", "203.0.113.7/32"},
		{"2001:db8::1", "2001:db8::1/128"},
		{"10.0.0.0/8", "10.0.0.0/8"},
		{"2001:db8::/32", "2001:db8::/32"},
		{"10.1.2.3/8", "10.0.0.0/8"},                 // masked
		{"::ffff:203.0.113.7", "203.0.113.7/32"},     // mapped host becomes IPv4
		{"::ffff:203.0.113.0/120", "203.0.113.0/24"}, // mapped prefix becomes IPv4
		{"0.0.0.0/0", "0.0.0.0/0"},                   // the administrator's call
		{"::ffff:0:0/80", ""},                        // can never match IPv4 traffic
		{"::ffff:203.0.113.0/64", ""},                // likewise
		{"x", ""},
		{"", ""},
		{"1.2.3.4/33", ""},
		{"1.2.3.4/", ""},
		{"1.2.3.4/8/8", ""},
		{"fe80::1%eth0", ""},    // zones make no sense in an allowlist
		{"fe80::1%eth0/64", ""}, // parses as an address with zone "eth0/64"

	}
	for _, c := range cases {
		got, err := ParsePrefix(c.in)
		if c.want == "" {
			if err == nil {
				t.Errorf("ParsePrefix(%q) = %v, want an error", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParsePrefix(%q): %v", c.in, err)
			continue
		}
		if got.String() != c.want {
			t.Errorf("ParsePrefix(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
