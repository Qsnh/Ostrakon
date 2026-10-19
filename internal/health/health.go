// Package health is Ostrakon's pause/resume state machine. Every Jev decision
// goes through Monitor.Call, which retries transient failures with backoff and
// pauses protection (no new bans) when Jev stays unusable; ProbeLoop then polls
// Jev in the background and resumes by itself once it answers again.
package health

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"ostrakon/internal/jev"
	"ostrakon/internal/logging"
	"ostrakon/internal/notify"
)

// FailureBudget is how long a streak of retryable failures may last, measured
// from its first failure, before protection pauses.
const FailureBudget = 60 * time.Second

const (
	backoffStart  = 1 * time.Second
	backoffMax    = 16 * time.Second
	retryAfterMax = 30 * time.Second

	probeStart = 1 * time.Minute
	probeMax   = 5 * time.Minute
)

// ErrPaused is returned by Monitor.Call when protection is paused. When Call
// itself caused the pause, the returned error also wraps the cause.
var ErrPaused = errors.New("jev unavailable: protection paused")

// Sleeper waits for d or until ctx is done, in which case it returns ctx's
// error. Tests inject one that records durations instead of waiting.
type Sleeper func(ctx context.Context, d time.Duration) error

// RealSleep is the Sleeper that actually waits.
func RealSleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Monitor tracks whether Jev is usable. It is safe for concurrent use: the
// daemon's workers share one Monitor, and the failure streak is shared too.
type Monitor struct {
	now      func() time.Time
	notifier notify.Notifier
	log      *slog.Logger

	mu          sync.Mutex
	paused      bool
	reason      string
	since       time.Time
	streakStart time.Time // first failure of the current streak; zero if none
}

// NewMonitor returns a running (not paused) Monitor. A nil notifier or logger
// means notify.Noop and slog.Default.
func NewMonitor(now func() time.Time, n notify.Notifier, log *slog.Logger) *Monitor {
	if n == nil {
		n = notify.Noop{}
	}
	if log == nil {
		log = slog.Default()
	}
	return &Monitor{now: now, notifier: n, log: log}
}

// Paused reports whether protection is paused, why, and since when.
func (m *Monitor) Paused() (paused bool, reason string, since time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.paused, m.reason, m.since
}

// Pause puts the monitor straight into the paused state, for example at
// startup when there is no API key. Pausing an already paused monitor keeps
// the original reason and time and notifies nobody.
func (m *Monitor) Pause(reason string) {
	at := m.now()
	m.mu.Lock()
	if m.paused {
		m.mu.Unlock()
		return
	}
	m.paused, m.reason, m.since = true, reason, at
	m.mu.Unlock()

	// Outside the mutex: neither logging nor a Notifier may block the others.
	m.log.Error("protection paused", "reason", reason)
	m.notifier.Paused(reason, at)
}

// resume leaves the paused state and forgets the failure streak.
func (m *Monitor) resume() {
	at := m.now()
	m.mu.Lock()
	if !m.paused {
		m.mu.Unlock()
		return
	}
	m.paused, m.reason, m.since = false, "", time.Time{}
	m.streakStart = time.Time{}
	m.mu.Unlock()

	m.log.Log(context.Background(), logging.LevelNotice, "protection resumed")
	m.notifier.Resumed(at)
}

func (m *Monitor) isPaused() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.paused
}

func (m *Monitor) clearStreak() {
	m.mu.Lock()
	m.streakStart = time.Time{}
	m.mu.Unlock()
}

// budgetSpent records one more retryable failure, seen at now, and reports
// whether the shared streak has now lasted FailureBudget or longer.
func (m *Monitor) budgetSpent(now time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.streakStart.IsZero() {
		m.streakStart = now
	}
	return now.Sub(m.streakStart) >= FailureBudget
}

// pauseFor pauses because of cause and returns ErrPaused wrapping it.
func (m *Monitor) pauseFor(cause error) error {
	m.Pause(cause.Error())
	return fmt.Errorf("%w: %w", ErrPaused, cause)
}

// Call runs fn, one Jev decision, and applies the retry policy to its error.
//
//   - Already paused: returns ErrPaused without calling fn.
//   - Success: clears the failure streak and returns nil.
//   - Canceled or bad-request errors (including errors that did not come from
//     Jev at all) are returned as they are; they say nothing about Jev's health.
//   - Auth errors pause immediately; retrying cannot help.
//   - Retryable errors back off (1s, 2s, 4s, 8s, 16s, then 16s again; a
//     Retry-After from Jev replaces the wait, capped at 30s) and retry, until
//     the streak, shared by all callers, is FailureBudget old. Then Call pauses.
//     A pause makes Call return an error that wraps both ErrPaused and the last
//     failure. If another caller pauses meanwhile, this Call returns ErrPaused
//     instead of calling fn again.
//   - Each Call also has a bound of its own: other workers' successes keep
//     resetting the shared streak, so a request that alone keeps failing would
//     otherwise retry forever. Once this Call's own failures span FailureBudget
//     (and the shared streak did not pause), Call gives up: it returns the last
//     error, wrapped (errors.As still finds the cause, errors.Is(ErrPaused) is
//     false), without pausing and without calling fn again.
//   - If sleep fails (ctx done), Call returns that error.
func (m *Monitor) Call(ctx context.Context, sleep Sleeper, fn func(ctx context.Context) error) error {
	backoff := backoffStart
	var firstFailure time.Time // this Call's first retryable failure
	for {
		if m.isPaused() {
			return ErrPaused
		}
		err := fn(ctx)
		if err == nil {
			m.clearStreak()
			return nil
		}
		switch jev.Classify(err) {
		case jev.ClassCanceled, jev.ClassBadRequest:
			return err
		case jev.ClassAuth:
			return m.pauseFor(err)
		}

		// Retryable.
		now := m.now()
		if m.budgetSpent(now) {
			return m.pauseFor(err)
		}
		if firstFailure.IsZero() {
			firstFailure = now
		}
		if now.Sub(firstFailure) >= FailureBudget {
			return fmt.Errorf("giving up on this request after %v of retries: %w",
				now.Sub(firstFailure).Round(time.Second), err)
		}
		wait := backoff
		backoff = min(backoff*2, backoffMax)
		var apiErr *jev.APIError
		if errors.As(err, &apiErr) && apiErr.RetryAfter > 0 {
			wait = min(apiErr.RetryAfter, retryAfterMax)
		}
		if serr := sleep(ctx, wait); serr != nil {
			return serr
		}
	}
}

// ProbeLoop is run in the background while paused. It waits, then calls ping,
// at growing intervals (1m, 2m, 4m, then 5m); the first successful ping
// resumes protection and ends the loop. It also returns when sleep fails
// (ctx done), and immediately if the monitor is not paused.
func (m *Monitor) ProbeLoop(ctx context.Context, sleep Sleeper, ping func(ctx context.Context) error) {
	interval := probeStart
	for m.isPaused() {
		if err := sleep(ctx, interval); err != nil {
			return
		}
		err := ping(ctx)
		if err == nil {
			m.resume()
			return
		}
		if ctx.Err() != nil {
			return
		}
		m.log.Debug("probe failed, still paused", "err", err)
		interval = min(interval*2, probeMax)
	}
}
