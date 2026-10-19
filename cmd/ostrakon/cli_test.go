package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"reflect"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"ostrakon/internal/control"
	"ostrakon/internal/daemon"
	"ostrakon/internal/state"
)

var testNow = time.Date(2026, 10, 18, 20, 0, 0, 0, time.UTC)

// cliRun runs runCLI with a fake Call that answers resp/err and a Running
// that answers running, and returns the exit code, the two outputs and the
// requests that reached Call.
func cliRun(t *testing.T, args []string, running bool, resp control.Response, err error) (code int, stdout, stderr string, calls []control.Request) {
	t.Helper()
	var out, errb bytes.Buffer
	d := cliDeps{
		Call: func(req control.Request) (control.Response, error) {
			calls = append(calls, req)
			return resp, err
		},
		Running: func() bool { return running },
		Now:     func() time.Time { return testNow },
	}
	code = runCLI(args, &out, &errb, d)
	return code, out.String(), errb.String(), calls
}

func statusResp(s daemon.Status) control.Response {
	return control.Response{OK: true, Status: &s}
}

func TestCLIStatusNotRunning(t *testing.T) {
	code, stdout, _, calls := cliRun(t, []string{"status"}, false, control.Response{}, nil)
	if code != 3 {
		t.Errorf("exit code = %d, want 3", code)
	}
	if stdout != "ostrakon is not running\n" {
		t.Errorf("stdout = %q", stdout)
	}
	if len(calls) != 0 {
		t.Errorf("Call was used although the daemon is not running: %v", calls)
	}
}

func TestCLIStatusRunning(t *testing.T) {
	code, stdout, stderr, calls := cliRun(t, []string{"status"}, true, statusResp(daemon.Status{
		Sources:      []string{"sshd(/var/log/auth.log)", "nginx-access(/var/log/nginx/access.log)"},
		BanCount:     3,
		LastDecision: "2026-10-18T20:00:05Z 203.0.113.7 ssh_bruteforce p=0.93 ban 1h",
		LastJev:      "2026-10-18T20:00:05Z ok",
	}), nil)
	if code != 0 || stderr != "" {
		t.Errorf("code = %d, stderr = %q", code, stderr)
	}
	want := "status:  running\n" +
		"mode:    normal\n" +
		"sources: sshd(/var/log/auth.log), nginx-access(/var/log/nginx/access.log)\n" +
		"bans:    3\n" +
		"last:    2026-10-18T20:00:05Z 203.0.113.7 ssh_bruteforce p=0.93 ban 1h\n" +
		"jev:     2026-10-18T20:00:05Z ok\n"
	if stdout != want {
		t.Errorf("stdout:\n%s\nwant:\n%s", stdout, want)
	}
	if !reflect.DeepEqual(calls, []control.Request{{Cmd: "status"}}) {
		t.Errorf("calls = %v", calls)
	}
}

func TestCLIStatusDryRunAndNothingYet(t *testing.T) {
	_, stdout, _, _ := cliRun(t, []string{"status"}, true, statusResp(daemon.Status{DryRun: true}), nil)
	want := "status:  running\n" +
		"mode:    dry-run\n" +
		"sources: -\n" +
		"bans:    0\n" +
		"last:    -\n" +
		"jev:     -\n"
	if stdout != want {
		t.Errorf("stdout:\n%s\nwant:\n%s", stdout, want)
	}
}

func TestCLIStatusPaused(t *testing.T) {
	since := time.Date(2026, 10, 18, 19, 30, 0, 0, time.UTC)
	code, stdout, _, _ := cliRun(t, []string{"status"}, true, statusResp(daemon.Status{
		Paused:      true,
		PauseReason: "jev: status 401: invalid key",
		PausedSince: since,
	}), nil)
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	for _, want := range []string{
		"status:  paused (reason: jev: status 401: invalid key, since 2026-10-18T19:30:00Z)\n",
		"mode:    normal\n",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout lacks %q:\n%s", want, stdout)
		}
	}
}

func TestCLIStatusPauseReasonIsOneLine(t *testing.T) {
	_, stdout, _, _ := cliRun(t, []string{"status"}, true, statusResp(daemon.Status{
		Paused:      true,
		PauseReason: "jev: status 502: <html>\n\x1b[2Jbad gateway</html>",
		PausedSince: testNow,
	}), nil)
	if strings.Contains(stdout, "\x1b") {
		t.Errorf("a control character reached the terminal: %q", stdout)
	}
	if lines := strings.Count(stdout, "\n"); lines != 6 {
		t.Errorf("status has %d lines, want 6:\n%s", lines, stdout)
	}
}

func TestCLIStatusDegraded(t *testing.T) {
	_, stdout, _, _ := cliRun(t, []string{"status"}, true, statusResp(daemon.Status{
		Degraded:    "5 consecutive Jev request failures: jev: HTTP 422: bad state",
		JevFailures: 5,
		LastJev:     "2026-10-18T20:00:05Z error: jev: HTTP 422: bad state",
	}), nil)
	for _, want := range []string{
		"status:  degraded (5 consecutive Jev request failures: jev: HTTP 422: bad state)\n",
		"jev:     2026-10-18T20:00:05Z error: jev: HTTP 422: bad state\n",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout lacks %q:\n%s", want, stdout)
		}
	}
}

// A firewall problem gets its own line, shown only while there is one.
func TestCLIStatusFirewall(t *testing.T) {
	_, stdout, _, _ := cliRun(t, []string{"status"}, true, statusResp(daemon.Status{
		LastDecision: "2026-10-18T20:00:05Z 203.0.113.7 ssh_bruteforce p=0.93 ban 1h failed: nft: Operation not permitted",
		LastJev:      "2026-10-18T20:00:05Z ok",
		Firewall:     "ban failed: nft: Operation not permitted\nsecond line",
	}), nil)
	want := "status:  running\n" +
		"mode:    normal\n" +
		"sources: -\n" +
		"bans:    0\n" +
		"last:    2026-10-18T20:00:05Z 203.0.113.7 ssh_bruteforce p=0.93 ban 1h failed: nft: Operation not permitted\n" +
		"jev:     2026-10-18T20:00:05Z ok\n" +
		"firewall: ban failed: nft: Operation not permitted second line\n"
	if stdout != want {
		t.Errorf("stdout:\n%s\nwant:\n%s", stdout, want)
	}
}

func TestCLIStatusPausedOutranksDegraded(t *testing.T) {
	_, stdout, _, _ := cliRun(t, []string{"status"}, true, statusResp(daemon.Status{
		Paused:      true,
		PauseReason: "jev: HTTP 401",
		PausedSince: testNow,
		Degraded:    "5 consecutive Jev request failures: x",
	}), nil)
	if !strings.HasPrefix(stdout, "status:  paused (reason: jev: HTTP 401, since 2026-10-18T20:00:00Z)\n") {
		t.Errorf("stdout:\n%s\nwant the pause first", stdout)
	}
}

// Text that came from Jev or nft may hold newlines and escapes; each status
// line stays one line.
func TestCLIStatusExternalTextIsOneLine(t *testing.T) {
	_, stdout, _, _ := cliRun(t, []string{"status"}, true, statusResp(daemon.Status{
		Degraded:     "5 consecutive Jev request failures: a\nb",
		LastDecision: "2026-10-18T20:00:05Z 203.0.113.7 - p=0.93 ban 1h failed: nft: Error:\n\x1b[2Jx",
		LastJev:      "2026-10-18T20:00:05Z error: \r\nboom",
	}), nil)
	if strings.Contains(stdout, "\x1b") || strings.Contains(stdout, "\r") {
		t.Errorf("a control character reached the terminal: %q", stdout)
	}
	if lines := strings.Count(stdout, "\n"); lines != 6 {
		t.Errorf("status has %d lines, want 6:\n%s", lines, stdout)
	}
}

func TestCLIBans(t *testing.T) {
	bans := []state.Ban{
		{IP: netip.MustParseAddr("198.51.100.20"), Until: testNow.Add(2*time.Hour + 5*time.Minute + 30*time.Second), Category: "web_scan"},
		{IP: netip.MustParseAddr("203.0.113.7"), Until: testNow.Add(30 * time.Minute), Category: "ssh_bruteforce"},
	}
	code, stdout, stderr, calls := cliRun(t, []string{"bans"}, true, control.Response{OK: true, Bans: bans}, nil)
	if code != 0 || stderr != "" {
		t.Errorf("code = %d, stderr = %q", code, stderr)
	}
	if !reflect.DeepEqual(calls, []control.Request{{Cmd: "bans"}}) {
		t.Errorf("calls = %v", calls)
	}
	lines := strings.Split(strings.TrimSuffix(stdout, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d lines, want 3:\n%s", len(lines), stdout)
	}
	// Soonest to expire first, whatever order the daemon sent them in.
	wantRows := [][]string{
		{"IP", "CATEGORY", "REMAINING"},
		{"203.0.113.7", "ssh_bruteforce", "30m"},
		{"198.51.100.20", "web_scan", "2h5m"},
	}
	for i, want := range wantRows {
		if got := strings.Fields(lines[i]); !reflect.DeepEqual(got, want) {
			t.Errorf("line %d = %q, want fields %v", i, lines[i], want)
		}
	}
	// The columns line up.
	col := strings.Index(lines[0], "CATEGORY")
	if strings.Index(lines[1], "ssh_bruteforce") != col || strings.Index(lines[2], "web_scan") != col {
		t.Errorf("CATEGORY column is not aligned:\n%s", stdout)
	}
}

func TestCLIBansEmpty(t *testing.T) {
	code, stdout, _, _ := cliRun(t, []string{"bans"}, true, control.Response{OK: true}, nil)
	if code != 0 || stdout != "no active bans\n" {
		t.Errorf("code = %d, stdout = %q", code, stdout)
	}
}

func TestCLIBansMissingCategory(t *testing.T) {
	bans := []state.Ban{{IP: netip.MustParseAddr("203.0.113.7"), Until: testNow.Add(time.Hour)}}
	_, stdout, _, _ := cliRun(t, []string{"bans"}, true, control.Response{OK: true, Bans: bans}, nil)
	if got := strings.Fields(strings.Split(stdout, "\n")[1]); !reflect.DeepEqual(got, []string{"203.0.113.7", "-", "1h0m"}) {
		t.Errorf("row = %v", got)
	}
}

func TestFormatRemaining(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{30 * time.Minute, "30m"},
		{2*time.Hour + 5*time.Minute, "2h5m"},
		{2*time.Hour + 5*time.Minute + 59*time.Second, "2h5m"},
		{time.Hour + 30*time.Minute, "1h30m"},
		{time.Hour, "1h0m"},
		{7 * 24 * time.Hour, "168h0m"},
		{time.Minute, "1m"},
		{time.Minute + 59*time.Second, "1m"},
		{59 * time.Second, "<1m"},
		{time.Second, "<1m"},
		{0, "<1m"},
		{-5 * time.Minute, "<1m"},
	}
	for _, c := range cases {
		if got := formatRemaining(c.d); got != c.want {
			t.Errorf("formatRemaining(%v) = %q, want %q", c.d, got, c.want)
		}
	}
}

func TestCLIUnbanBadIP(t *testing.T) {
	for _, arg := range []string{"nope", "1.2.3.4/24", "999.1.1.1"} {
		code, stdout, stderr, calls := cliRun(t, []string{"unban", arg}, true, control.Response{OK: true}, nil)
		if code != 1 {
			t.Errorf("unban %q: exit code = %d, want 1", arg, code)
		}
		if len(calls) != 0 {
			t.Errorf("unban %q: Call was used: %v", arg, calls)
		}
		if stdout != "" || stderr == "" {
			t.Errorf("unban %q: stdout = %q, stderr = %q", arg, stdout, stderr)
		}
	}
}

func TestCLIBadArguments(t *testing.T) {
	for _, args := range [][]string{
		{"unban"},
		{"unban", "1.2.3.4", "5.6.7.8"},
		{"allow"},
		{"allow", "x"},
		{"allow", "::ffff:0:0/80"},
		{"disallow"},
		{"disallow", "10.0.0.0/33"},
		{"status", "extra"},
		{"bans", "extra"},
	} {
		code, _, stderr, calls := cliRun(t, args, true, control.Response{OK: true}, nil)
		if code != 1 || stderr == "" || len(calls) != 0 {
			t.Errorf("%v: code = %d, stderr = %q, calls = %v; want exit 1, a message, no call", args, code, stderr, calls)
		}
	}
}

func TestCLIBadArgumentsNeedNoDaemon(t *testing.T) {
	// A typo is reported as a typo, not as a missing daemon.
	code, stdout, _, _ := cliRun(t, []string{"unban", "nope"}, false, control.Response{}, nil)
	if code != 1 || stdout != "" {
		t.Errorf("code = %d, stdout = %q", code, stdout)
	}
}

func TestCLIAdminCommands(t *testing.T) {
	cases := []struct {
		args []string
		want control.Request
	}{
		{[]string{"unban", "203.0.113.7"}, control.Request{Cmd: "unban", Arg: "203.0.113.7"}},
		{[]string{"unban", "2001:db8::1"}, control.Request{Cmd: "unban", Arg: "2001:db8::1"}},
		{[]string{"allow", "203.0.113.7"}, control.Request{Cmd: "allow", Arg: "203.0.113.7"}},
		{[]string{"allow", "198.51.100.0/24"}, control.Request{Cmd: "allow", Arg: "198.51.100.0/24"}},
		{[]string{"disallow", "198.51.100.0/24"}, control.Request{Cmd: "disallow", Arg: "198.51.100.0/24"}},
	}
	for _, c := range cases {
		code, stdout, stderr, calls := cliRun(t, c.args, true, control.Response{OK: true}, nil)
		if code != 0 || stdout != "ok\n" || stderr != "" {
			t.Errorf("%v: code = %d, stdout = %q, stderr = %q", c.args, code, stdout, stderr)
		}
		if !reflect.DeepEqual(calls, []control.Request{c.want}) {
			t.Errorf("%v: calls = %v, want %v", c.args, calls, c.want)
		}
	}
}

func TestCLINotRunningForAdminCommands(t *testing.T) {
	code, stdout, _, calls := cliRun(t, []string{"allow", "203.0.113.7"}, false, control.Response{}, nil)
	if code != 3 || stdout != "ostrakon is not running\n" || len(calls) != 0 {
		t.Errorf("code = %d, stdout = %q, calls = %v", code, stdout, calls)
	}
}

func TestCLIDaemonRefuses(t *testing.T) {
	code, stdout, stderr, _ := cliRun(t, []string{"unban", "203.0.113.7"}, true,
		control.Response{Error: "nft: exit status 1"}, nil)
	if code != 1 || stdout != "" {
		t.Errorf("code = %d, stdout = %q", code, stdout)
	}
	if stderr != "ostrakon: nft: exit status 1\n" {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestCLICallFailures(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{"permission", fmt.Errorf("dial unix /run/ostrakon/ostrakon.sock: %w", syscall.EACCES), 1, "", "ostrakon: permission denied (run as root)\n"},
		{"permission sentinel", fs.ErrPermission, 1, "", "ostrakon: permission denied (run as root)\n"},
		{"daemon went away", fmt.Errorf("dial: %w", syscall.ECONNREFUSED), 3, "ostrakon is not running\n", ""},
		{"socket vanished", fmt.Errorf("dial: %w", fs.ErrNotExist), 3, "ostrakon is not running\n", ""},
		{"other", errors.New("control: reading response: EOF"), 1, "", "ostrakon: control: reading response: EOF\n"},
	}
	for _, c := range cases {
		code, stdout, stderr, _ := cliRun(t, []string{"status"}, true, control.Response{}, c.err)
		if code != c.wantCode || stdout != c.wantStdout || stderr != c.wantStderr {
			t.Errorf("%s: code = %d, stdout = %q, stderr = %q; want %d, %q, %q",
				c.name, code, stdout, stderr, c.wantCode, c.wantStdout, c.wantStderr)
		}
	}
}

func TestCLIStatusWithoutStatus(t *testing.T) {
	code, stdout, stderr, _ := cliRun(t, []string{"status"}, true, control.Response{OK: true}, nil)
	if code != 1 || stdout != "" || stderr == "" {
		t.Errorf("code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
	}
}

func TestCLIUsage(t *testing.T) {
	for _, args := range [][]string{nil, {}, {"bogus"}, {"setup"}, {"--help"}} {
		code, stdout, stderr, calls := cliRun(t, args, true, control.Response{OK: true}, nil)
		if code != 2 {
			t.Errorf("%v: exit code = %d, want 2", args, code)
		}
		if stdout != "" || !strings.Contains(stderr, "usage: ostrakon") || len(calls) != 0 {
			t.Errorf("%v: stdout = %q, stderr = %q, calls = %v", args, stdout, stderr, calls)
		}
	}
}

func TestRunTogether(t *testing.T) {
	waitDone := func(ctx context.Context) error { <-ctx.Done(); return nil }

	t.Run("shutdown stops both and succeeds", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		var stopped atomic.Int32
		fn := func(ctx context.Context) error { <-ctx.Done(); stopped.Add(1); return nil }
		done := make(chan error, 1)
		go func() { done <- runTogether(ctx, fn, fn) }()
		cancel()
		if err := <-done; err != nil {
			t.Errorf("err = %v, want nil", err)
		}
		if stopped.Load() != 2 {
			t.Errorf("%d of 2 functions saw the cancel", stopped.Load())
		}
	})

	t.Run("an error in one cancels the other and is returned", func(t *testing.T) {
		boom := errors.New("boom")
		var otherSawCancel atomic.Bool
		other := func(ctx context.Context) error { <-ctx.Done(); otherSawCancel.Store(true); return nil }
		failing := func(context.Context) error { return boom }
		err := runTogether(context.Background(), other, failing)
		if !errors.Is(err, boom) {
			t.Errorf("err = %v, want %v", err, boom)
		}
		if !otherSawCancel.Load() {
			t.Error("the other function was not cancelled (or runTogether returned before it finished)")
		}
	})

	t.Run("a clean early return also stops the rest", func(t *testing.T) {
		err := runTogether(context.Background(), waitDone, func(context.Context) error { return nil })
		if err != nil {
			t.Errorf("err = %v, want nil", err)
		}
	})

	t.Run("both errors are kept", func(t *testing.T) {
		e1, e2 := errors.New("one"), errors.New("two")
		err := runTogether(context.Background(),
			func(ctx context.Context) error { <-ctx.Done(); return e2 },
			func(context.Context) error { return e1 })
		if !errors.Is(err, e1) || !errors.Is(err, e2) {
			t.Errorf("err = %v, want both %v and %v", err, e1, e2)
		}
	})
}
