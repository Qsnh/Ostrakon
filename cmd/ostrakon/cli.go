package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"slices"
	"strings"
	"text/tabwriter"
	"time"
	"unicode"

	"github.com/Qsnh/Ostrakon/internal/control"
	"github.com/Qsnh/Ostrakon/internal/daemon"
	"github.com/Qsnh/Ostrakon/internal/state"
)

// Exit codes. exitNotRunning follows systemctl's convention for "status of
// something that is not running".
const (
	exitOK         = 0
	exitError      = 1
	exitUsage      = 2
	exitNotRunning = 3
)

const usageText = `usage: ostrakon <command>

commands:
  setup               save your Jev API key, install and start the service (root only)
  run [--dry-run]     run the daemon (root only; --dry-run logs bans instead of applying them)
  status              show whether protection is running
  bans                list the active bans
  unban <ip>          lift the ban on an address
  allow <ip|cidr>     never ban this address or range
  disallow <ip|cidr>  remove an entry added with allow
`

// cliDeps is what the control commands depend on, so that tests need neither
// a daemon nor a socket.
type cliDeps struct {
	Call    func(req control.Request) (control.Response, error)
	Running func() bool // whether a daemon may be listening on the control socket
	Now     func() time.Time
}

// runCLI runs one of the control commands (status, bans, unban, allow,
// disallow) and returns the process exit code. Arguments are checked before
// the daemon is contacted.
func runCLI(args []string, stdout, stderr io.Writer, d cliDeps) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usageText)
		return exitUsage
	}
	cmd, rest := args[0], args[1:]

	var req control.Request
	switch cmd {
	case "status", "bans":
		if len(rest) != 0 {
			fmt.Fprintf(stderr, "usage: ostrakon %s\n", cmd)
			return exitError
		}
		req = control.Request{Cmd: cmd}
	case "unban", "allow", "disallow":
		arg, msg := oneArgument(cmd, rest)
		if msg != "" {
			fmt.Fprintf(stderr, "ostrakon: %s\n", msg)
			return exitError
		}
		req = control.Request{Cmd: cmd, Arg: arg}
	default:
		fmt.Fprint(stderr, usageText)
		return exitUsage
	}

	if !d.Running() {
		return notRunning(stdout)
	}
	resp, err := d.Call(req)
	if err != nil {
		switch {
		case control.NotRunning(err):
			return notRunning(stdout)
		case errors.Is(err, fs.ErrPermission):
			fmt.Fprintln(stderr, "ostrakon: permission denied (run as root)")
		default:
			fmt.Fprintf(stderr, "ostrakon: %v\n", err)
		}
		return exitError
	}
	if !resp.OK {
		fmt.Fprintf(stderr, "ostrakon: %s\n", resp.Error)
		return exitError
	}

	switch cmd {
	case "status":
		if resp.Status == nil {
			fmt.Fprintln(stderr, "ostrakon: the daemon sent no status")
			return exitError
		}
		printStatus(stdout, *resp.Status)
	case "bans":
		printBans(stdout, resp.Bans, d.Now())
	default:
		fmt.Fprintln(stdout, "ok")
	}
	return exitOK
}

func notRunning(stdout io.Writer) int {
	fmt.Fprintln(stdout, "ostrakon is not running")
	return exitNotRunning
}

// oneArgument checks that cmd got exactly one argument and that it is valid
// for cmd: an IP address for unban, an IP address or prefix for allow and
// disallow. It returns the argument, or a message saying what is wrong.
func oneArgument(cmd string, args []string) (arg, msg string) {
	want := "<ip>"
	if cmd != "unban" {
		want = "<ip|cidr>"
	}
	if len(args) != 1 {
		return "", fmt.Sprintf("usage: ostrakon %s %s", cmd, want)
	}
	arg = args[0]
	if cmd == "unban" {
		if _, err := netip.ParseAddr(arg); err != nil {
			return "", fmt.Sprintf("invalid IP address %q", arg)
		}
		return arg, ""
	}
	if _, err := control.ParsePrefix(arg); err != nil {
		return "", err.Error()
	}
	return arg, ""
}

func printStatus(w io.Writer, s daemon.Status) {
	status := "running"
	switch {
	case s.Paused:
		status = fmt.Sprintf("paused (reason: %s, since %s)", oneLine(s.PauseReason), s.PausedSince.Format(time.RFC3339))
	case s.Degraded != "":
		status = fmt.Sprintf("degraded (%s)", oneLine(s.Degraded))
	}
	mode := "normal"
	if s.DryRun {
		mode = "dry-run"
	}
	sources := "-"
	if len(s.Sources) > 0 {
		sources = strings.Join(s.Sources, ", ")
	}
	fmt.Fprintf(w, "status:  %s\nmode:    %s\nsources: %s\nbans:    %d\nlast:    %s\njev:     %s\n",
		status, mode, sources, s.BanCount, orDash(s.LastDecision), orDash(s.LastJev))
	if s.Firewall != "" {
		fmt.Fprintf(w, "firewall: %s\n", oneLine(s.Firewall))
	}
}

// orDash makes s one line, or "-" when it is empty.
func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return oneLine(s)
}

// oneLine replaces control characters, so that text that came from outside
// (a pause reason quotes Jev's reply, a failed ban quotes nft) cannot move
// the cursor or start a second line in the administrator's terminal.
func oneLine(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
}

// printBans lists bans, soonest to expire first.
func printBans(w io.Writer, bans []state.Ban, now time.Time) {
	if len(bans) == 0 {
		fmt.Fprintln(w, "no active bans")
		return
	}
	bans = slices.Clone(bans)
	slices.SortStableFunc(bans, func(a, b state.Ban) int { return a.Until.Compare(b.Until) })

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "IP\tCATEGORY\tREMAINING")
	for _, b := range bans {
		category := b.Category
		if category == "" {
			category = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", b.IP, category, formatRemaining(b.Until.Sub(now)))
	}
	tw.Flush()
}

// formatRemaining shows d in whole minutes, as 30m, 2h5m or 1h0m, and
// anything under a minute as "<1m".
func formatRemaining(d time.Duration) string {
	if d < time.Minute {
		return "<1m"
	}
	return strings.TrimSuffix(d.Truncate(time.Minute).String(), "0s")
}
