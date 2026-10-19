// Package source finds the log sources Ostrakon watches (sshd and nginx
// access logs, as files or as journald units) and follows them as they grow,
// surviving log rotation. It emits one string per log line, terminator
// removed, because the extractors' regexes are end-anchored.
package source

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"time"
)

// Names of the log sources Ostrakon knows how to parse.
const (
	NameSSHD        = "sshd"
	NameNginxAccess = "nginx-access"
)

// filePoll is how often a file source is checked for new data.
const filePoll = 250 * time.Millisecond

// Spec describes one log source: either a file (Path) or journald units
// (JournalUnits), never both.
type Spec struct {
	Name         string
	Path         string
	JournalUnits []string
}

// Line is one log line together with the Spec it came from.
type Line struct {
	Spec Spec
	Text string
}

// Discover returns the log sources present on this host, sshd first. exists
// reports whether a file exists; haveJournalctl whether journalctl is
// installed. sshd falls back to the journal only when neither auth log file
// exists; nginx is included only when its access log exists.
func Discover(exists func(string) bool, haveJournalctl bool) []Spec {
	var specs []Spec

	sshd := Spec{Name: NameSSHD}
	for _, p := range []string{"/var/log/auth.log", "/var/log/secure"} {
		if exists(p) {
			sshd.Path = p
			break
		}
	}
	if sshd.Path == "" && haveJournalctl {
		sshd.JournalUnits = []string{"ssh.service", "sshd.service"}
	}
	if sshd.Path != "" || sshd.JournalUnits != nil {
		specs = append(specs, sshd)
	}

	const nginxLog = "/var/log/nginx/access.log"
	if exists(nginxLog) {
		specs = append(specs, Spec{Name: NameNginxAccess, Path: nginxLog})
	}
	return specs
}

// Start follows every spec in its own goroutine and sends each line to out,
// tagged with its Spec. It returns immediately; the goroutines stop when ctx
// is done. Sends on out give up once ctx is done, so out need not be drained
// during shutdown.
func Start(ctx context.Context, specs []Spec, out chan<- Line, log *slog.Logger) {
	for _, spec := range specs {
		raw := make(chan string)
		go forward(ctx, spec, raw, out)
		switch {
		case spec.Path != "":
			go func() { _ = tailFile(ctx, spec.Path, filePoll, raw, fileProblemLogger(log, spec)) }()
		case len(spec.JournalUnits) > 0:
			go func() {
				_ = tailJournal(ctx, spec.JournalUnits, raw, func(err error) {
					log.Warn("journalctl is not running; restarting",
						"source", spec.Name, "units", spec.JournalUnits,
						"err", err, "retry_in", journalRestartDelay)
				})
			}()
		}
	}
}

// fileProblemLogger returns the tailFile hook that reports a file source's
// health to log. Each call marks a change, never a repeat: a file that does not
// exist yet is normal waiting (Info), any other failure is a Warn because the
// detector is blind to that log until it clears, and nil means it cleared.
func fileProblemLogger(log *slog.Logger, spec Spec) func(error) {
	return func(err error) {
		switch {
		case err == nil:
			log.Info("log file is available; following it", "source", spec.Name, "path", spec.Path)
		case errors.Is(err, fs.ErrNotExist):
			log.Info("log file does not exist yet; waiting for it", "source", spec.Name, "path", spec.Path)
		default:
			log.Warn("cannot read log file; will keep retrying", "source", spec.Name, "path", spec.Path, "err", err)
		}
	}
}

// forward wraps raw lines into Lines until ctx is done.
func forward(ctx context.Context, spec Spec, raw <-chan string, out chan<- Line) {
	for {
		select {
		case <-ctx.Done():
			return
		case s := <-raw:
			select {
			case out <- Line{Spec: spec, Text: s}:
			case <-ctx.Done():
				return
			}
		}
	}
}
