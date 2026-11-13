package source

import (
	"context"
	"errors"
	"os/exec"
	"time"
)

// journalRestartDelay is how long TailJournal waits before restarting
// journalctl after it exits or fails to start.
const journalRestartDelay = 5 * time.Second

// JournalArgs returns the journalctl arguments that follow units from now on,
// printing the bare message (no timestamp or host prefix).
func JournalArgs(units []string) []string {
	args := []string{"-f", "-n", "0", "-o", "cat"}
	for _, u := range units {
		args = append(args, "-u", u)
	}
	return args
}

// TailJournal follows the journald units with journalctl and sends each line
// to out. If journalctl cannot start or exits, it is restarted after 5
// seconds. TailJournal returns ctx.Err() once ctx is done and never otherwise.
func TailJournal(ctx context.Context, units []string, out chan<- string) error {
	return tailJournal(ctx, units, out, nil)
}

// tailJournal is TailJournal with a hook: onExit, when non-nil, is called with
// the reason each time journalctl stops, so Start can log it.
func tailJournal(ctx context.Context, units []string, out chan<- string, onExit func(error)) error {
	for {
		err := runJournalctl(ctx, units, out)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if onExit != nil {
			onExit(err)
		}
		t := time.NewTimer(journalRestartDelay)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
}

// runJournalctl runs journalctl once, sending its output lines to out. It
// returns when the process ends (error describes why) or ctx is done.
func runJournalctl(ctx context.Context, units []string, out chan<- string) error {
	cmd := exec.CommandContext(ctx, "journalctl", JournalArgs(units)...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}

	var ls lineSplitter
	emit := func(s string) bool {
		select {
		case out <- s:
			return true
		case <-ctx.Done():
			return false
		}
	}
	chunk := make([]byte, readChunk)
	for {
		n, rerr := stdout.Read(chunk)
		if !ls.feed(chunk[:n], emit) {
			break
		}
		if rerr != nil {
			break
		}
	}
	// Stop reading means the process ended, or ctx is done and CommandContext
	// is killing it; Wait reaps it either way.
	werr := cmd.Wait()
	if werr == nil {
		werr = errors.New("journalctl exited")
	}
	return werr
}
