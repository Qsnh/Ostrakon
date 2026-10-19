package health

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"ostrakon/internal/apikey"
	"ostrakon/internal/jev"
	"ostrakon/internal/judge"
	"ostrakon/internal/logging"
)

// fakeClock is a manually advanced clock, safe for concurrent use.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// fakeSleeper records every requested duration and advances the clock by it
// instead of waiting. hook, when set, runs before the clock moves.
type fakeSleeper struct {
	clock *fakeClock
	mu    sync.Mutex
	got   []time.Duration
	hook  func(n int)
}

func (s *fakeSleeper) sleep(ctx context.Context, d time.Duration) error {
	s.mu.Lock()
	s.got = append(s.got, d)
	n := len(s.got)
	s.mu.Unlock()
	if s.hook != nil {
		s.hook(n)
	}
	s.clock.advance(d)
	return nil
}

func (s *fakeSleeper) sleeps() []time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]time.Duration(nil), s.got...)
}

func (s *fakeSleeper) total() time.Duration {
	var sum time.Duration
	for _, d := range s.sleeps() {
		sum += d
	}
	return sum
}

// fakeNotifier counts notifications.
type fakeNotifier struct {
	mu      sync.Mutex
	paused  int
	resumed int
	reasons []string
	pausedA []time.Time
	resumeA []time.Time
	onPause func()
	onResum func()
}

func (n *fakeNotifier) Paused(reason string, at time.Time) {
	n.mu.Lock()
	n.paused++
	n.reasons = append(n.reasons, reason)
	n.pausedA = append(n.pausedA, at)
	f := n.onPause
	n.mu.Unlock()
	if f != nil {
		f()
	}
}

func (n *fakeNotifier) Resumed(at time.Time) {
	n.mu.Lock()
	n.resumed++
	n.resumeA = append(n.resumeA, at)
	f := n.onResum
	n.mu.Unlock()
	if f != nil {
		f()
	}
}

func (n *fakeNotifier) counts() (paused, resumed int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.paused, n.resumed
}

type rig struct {
	clock *fakeClock
	sl    *fakeSleeper
	nt    *fakeNotifier
	m     *Monitor
	logs  *bytes.Buffer
}

func newRig() *rig {
	c := newClock()
	nt := &fakeNotifier{}
	logs := &bytes.Buffer{}
	log := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug, ReplaceAttr: logging.ReplaceLevel}))
	return &rig{clock: c, sl: &fakeSleeper{clock: c}, nt: nt, m: NewMonitor(c.now, nt, log), logs: logs}
}

// step is one scripted fn invocation: advance the clock (the call "took"
// that long), then return err.
type step struct {
	advance time.Duration
	err     error
}

// script returns an fn that plays the steps in order and fails the test if
// called more often than scripted. calls reports how many times it ran.
func (r *rig) script(t *testing.T, steps ...step) (fn func(context.Context) error, calls func() int) {
	t.Helper()
	var mu sync.Mutex
	n := 0
	fn = func(context.Context) error {
		mu.Lock()
		i := n
		n++
		mu.Unlock()
		if i >= len(steps) {
			t.Errorf("fn called %d times, only %d steps scripted", i+1, len(steps))
			return errors.New("script exhausted")
		}
		r.clock.advance(steps[i].advance)
		return steps[i].err
	}
	calls = func() int {
		mu.Lock()
		defer mu.Unlock()
		return n
	}
	return fn, calls
}

func api(status int) error { return &jev.APIError{Status: status} }

func sleepsEqual(a, b []time.Duration) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestRetryThenSuccess(t *testing.T) {
	r := newRig()
	fn, calls := r.script(t, step{err: api(529)}, step{err: api(529)}, step{})
	if err := r.m.Call(context.Background(), r.sl.sleep, fn); err != nil {
		t.Fatalf("Call = %v, want nil", err)
	}
	want := []time.Duration{time.Second, 2 * time.Second}
	if got := r.sl.sleeps(); !sleepsEqual(got, want) {
		t.Errorf("sleeps = %v, want %v", got, want)
	}
	if calls() != 3 {
		t.Errorf("fn calls = %d, want 3", calls())
	}
	if p, _, _ := r.m.Paused(); p {
		t.Error("monitor paused after eventual success")
	}
	if p, rs := r.nt.counts(); p != 0 || rs != 0 {
		t.Errorf("notifications = %d paused, %d resumed; want 0, 0", p, rs)
	}
}

func TestPauseAfterBudget(t *testing.T) {
	r := newRig()
	t0 := r.clock.now()
	calls := 0
	fn := func(context.Context) error { calls++; return api(529) }

	err := r.m.Call(context.Background(), r.sl.sleep, fn)
	if !errors.Is(err, ErrPaused) {
		t.Fatalf("Call = %v, want ErrPaused", err)
	}
	var apiErr *jev.APIError
	if !errors.As(err, &apiErr) || apiErr.Status != 529 {
		t.Errorf("errors.As(APIError) = %v, %+v; want status 529", errors.As(err, &apiErr), apiErr)
	}

	// 1s, 2s, 4s, 8s, 16s, then held at 16s until the 60s budget is spent.
	s := time.Second
	want := []time.Duration{1 * s, 2 * s, 4 * s, 8 * s, 16 * s, 16 * s, 16 * s}
	if got := r.sl.sleeps(); !sleepsEqual(got, want) {
		t.Errorf("sleeps = %v, want %v", got, want)
	}
	if tot := r.sl.total(); tot < FailureBudget || tot >= 90*time.Second {
		t.Errorf("total sleep = %v, want in [60s, 90s)", tot)
	}
	if calls != len(want)+1 {
		t.Errorf("fn calls = %d, want %d", calls, len(want)+1)
	}

	paused, reason, since := r.m.Paused()
	if !paused {
		t.Fatal("monitor not paused after budget exhausted")
	}
	if !strings.Contains(reason, "529") {
		t.Errorf("reason = %q, want it to contain 529", reason)
	}
	if want := t0.Add(r.sl.total()); !since.Equal(want) {
		t.Errorf("since = %v, want %v", since, want)
	}
	if p, rs := r.nt.counts(); p != 1 || rs != 0 {
		t.Errorf("notifications = %d paused, %d resumed; want 1, 0", p, rs)
	}
	if !strings.Contains(r.logs.String(), `level=ERROR msg="protection paused"`) ||
		!strings.Contains(r.logs.String(), "529") {
		t.Errorf("log lacks Error \"protection paused\" with reason:\n%s", r.logs.String())
	}
}

func TestAuthPausesImmediately(t *testing.T) {
	r := newRig()
	fn, calls := r.script(t, step{err: api(401)})
	err := r.m.Call(context.Background(), r.sl.sleep, fn)
	if !errors.Is(err, ErrPaused) {
		t.Fatalf("Call = %v, want ErrPaused", err)
	}
	var apiErr *jev.APIError
	if !errors.As(err, &apiErr) || apiErr.Status != 401 {
		t.Errorf("cause not preserved: errors.As = %v, %+v", errors.As(err, &apiErr), apiErr)
	}
	if got := r.sl.sleeps(); len(got) != 0 {
		t.Errorf("sleeps = %v, want none", got)
	}
	if calls() != 1 {
		t.Errorf("fn calls = %d, want 1", calls())
	}
	paused, reason, _ := r.m.Paused()
	if !paused || !strings.Contains(reason, "401") {
		t.Errorf("Paused = %v, %q; want true with reason containing 401", paused, reason)
	}
	if strings.Contains(strings.ToLower(reason), "invalid key") {
		t.Errorf("reason %q must be the error text, not a canned message", reason)
	}
	if p, _ := r.nt.counts(); p != 1 {
		t.Errorf("Paused notifications = %d, want 1", p)
	}
}

func TestNoKeyPausesImmediately(t *testing.T) {
	r := newRig()
	fn, _ := r.script(t, step{err: fmt.Errorf("request: %w", apikey.ErrNoKey)})
	err := r.m.Call(context.Background(), r.sl.sleep, fn)
	if !errors.Is(err, ErrPaused) || !errors.Is(err, apikey.ErrNoKey) {
		t.Fatalf("Call = %v, want ErrPaused wrapping ErrNoKey", err)
	}
	if p, reason, _ := r.m.Paused(); !p || !strings.Contains(reason, "no Jev API key") {
		t.Errorf("Paused = %v, %q", p, reason)
	}
	if got := r.sl.sleeps(); len(got) != 0 {
		t.Errorf("sleeps = %v, want none", got)
	}
}

func TestBadRequestNoPause(t *testing.T) {
	r := newRig()
	fn, calls := r.script(t, step{err: api(422)})
	err := r.m.Call(context.Background(), r.sl.sleep, fn)
	var apiErr *jev.APIError
	if !errors.As(err, &apiErr) || apiErr.Status != 422 {
		t.Fatalf("Call = %v, want the 422 APIError", err)
	}
	if errors.Is(err, ErrPaused) {
		t.Error("BadRequest error must not be ErrPaused")
	}
	if p, _, _ := r.m.Paused(); p {
		t.Error("monitor paused on BadRequest")
	}
	if got := r.sl.sleeps(); len(got) != 0 {
		t.Errorf("sleeps = %v, want none", got)
	}
	if calls() != 1 {
		t.Errorf("fn calls = %d, want 1", calls())
	}
}

func TestNonJevErrorsAreReturnedUnchanged(t *testing.T) {
	for name, cause := range map[string]error{
		"malformed answer": fmt.Errorf("decide: %w", judge.ErrMalformedAnswer),
		"canceled":         context.Canceled,
		"deadline":         fmt.Errorf("wait: %w", context.DeadlineExceeded),
		"plain":            errors.New("boom"),
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig()
			fn, calls := r.script(t, step{err: cause})
			err := r.m.Call(context.Background(), r.sl.sleep, fn)
			if err != cause {
				t.Errorf("Call = %v, want the original error %v", err, cause)
			}
			if p, _, _ := r.m.Paused(); p {
				t.Error("monitor paused")
			}
			if len(r.sl.sleeps()) != 0 || calls() != 1 {
				t.Errorf("sleeps %v, fn calls %d; want none, 1", r.sl.sleeps(), calls())
			}
		})
	}
}

func TestRetryAfterHonored(t *testing.T) {
	r := newRig()
	fn, _ := r.script(t,
		step{err: &jev.APIError{Status: 429, RetryAfter: 7 * time.Second}},
		step{})
	if err := r.m.Call(context.Background(), r.sl.sleep, fn); err != nil {
		t.Fatalf("Call = %v, want nil", err)
	}
	if got, want := r.sl.sleeps(), []time.Duration{7 * time.Second}; !sleepsEqual(got, want) {
		t.Errorf("sleeps = %v, want %v", got, want)
	}
}

func TestRetryAfterCapped(t *testing.T) {
	r := newRig()
	fn, _ := r.script(t,
		step{err: &jev.APIError{Status: 429, RetryAfter: 10 * time.Minute}},
		step{})
	if err := r.m.Call(context.Background(), r.sl.sleep, fn); err != nil {
		t.Fatalf("Call = %v, want nil", err)
	}
	if got, want := r.sl.sleeps(), []time.Duration{30 * time.Second}; !sleepsEqual(got, want) {
		t.Errorf("sleeps = %v, want %v", got, want)
	}
}

// netTimeout is a net.Error, like a dial or read timeout.
type netTimeout struct{}

func (netTimeout) Error() string   { return "i/o timeout" }
func (netTimeout) Timeout() bool   { return true }
func (netTimeout) Temporary() bool { return true }

func TestNetworkErrorIsRetried(t *testing.T) {
	r := newRig()
	var cause error = netTimeout{}
	if jev.Classify(cause) != jev.ClassRetryable {
		t.Fatalf("test premise broken: Classify(%v) is not Retryable", cause)
	}
	fn, _ := r.script(t, step{err: cause}, step{})
	if err := r.m.Call(context.Background(), r.sl.sleep, fn); err != nil {
		t.Fatalf("Call = %v, want nil", err)
	}
	if got, want := r.sl.sleeps(), []time.Duration{time.Second}; !sleepsEqual(got, want) {
		t.Errorf("sleeps = %v, want %v", got, want)
	}
}

func TestCallWhilePaused(t *testing.T) {
	r := newRig()
	r.m.Pause("x")
	fn, calls := r.script(t)
	err := r.m.Call(context.Background(), r.sl.sleep, fn)
	if !errors.Is(err, ErrPaused) {
		t.Fatalf("Call = %v, want ErrPaused", err)
	}
	if calls() != 0 {
		t.Errorf("fn calls = %d, want 0", calls())
	}
	if len(r.sl.sleeps()) != 0 {
		t.Errorf("sleeps = %v, want none", r.sl.sleeps())
	}
}

func TestPauseKeepsFirstReasonAndNotifiesOnce(t *testing.T) {
	r := newRig()
	t0 := r.clock.now()
	r.m.Pause("no API key")
	r.clock.advance(time.Minute)
	r.m.Pause("something else")

	paused, reason, since := r.m.Paused()
	if !paused || reason != "no API key" || !since.Equal(t0) {
		t.Errorf("Paused = %v, %q, %v; want true, %q, %v", paused, reason, since, "no API key", t0)
	}
	if p, _ := r.nt.counts(); p != 1 {
		t.Errorf("Paused notifications = %d, want 1", p)
	}
	if !r.nt.pausedA[0].Equal(t0) {
		t.Errorf("notified at %v, want %v", r.nt.pausedA[0], t0)
	}
	if n := strings.Count(r.logs.String(), "protection paused"); n != 1 {
		t.Errorf("logged \"protection paused\" %d times, want 1", n)
	}
}

func TestPausedWhenNotPaused(t *testing.T) {
	r := newRig()
	paused, reason, since := r.m.Paused()
	if paused || reason != "" || !since.IsZero() {
		t.Errorf("Paused = %v, %q, %v; want false, \"\", zero", paused, reason, since)
	}
}

func TestProbeLoop(t *testing.T) {
	r := newRig()
	r.m.Pause("jev: HTTP 529")
	pings := 0
	ping := func(context.Context) error {
		pings++
		if pings <= 3 {
			return api(529)
		}
		return nil
	}
	r.m.ProbeLoop(context.Background(), r.sl.sleep, ping)

	m := time.Minute
	want := []time.Duration{1 * m, 2 * m, 4 * m, 5 * m}
	if got := r.sl.sleeps(); !sleepsEqual(got, want) {
		t.Errorf("sleeps = %v, want %v", got, want)
	}
	if pings != 4 {
		t.Errorf("pings = %d, want 4", pings)
	}
	if p, reason, since := r.m.Paused(); p || reason != "" || !since.IsZero() {
		t.Errorf("Paused = %v, %q, %v after resume", p, reason, since)
	}
	if p, rs := r.nt.counts(); p != 1 || rs != 1 {
		t.Errorf("notifications = %d paused, %d resumed; want 1, 1", p, rs)
	}
	if want := r.clock.now(); !r.nt.resumeA[0].Equal(want) {
		t.Errorf("resumed at %v, want %v", r.nt.resumeA[0], want)
	}
	// Notice, so that journald files the end of a pause apart from routine
	// Info lines.
	if !strings.Contains(r.logs.String(), `level=NOTICE msg="protection resumed"`) {
		t.Errorf("log lacks Notice \"protection resumed\":\n%s", r.logs.String())
	}
}

func TestProbeLoopIntervalsStayAtFiveMinutes(t *testing.T) {
	r := newRig()
	r.m.Pause("x")
	pings := 0
	ping := func(context.Context) error {
		pings++
		if pings < 7 {
			return errors.New("still down")
		}
		return nil
	}
	r.m.ProbeLoop(context.Background(), r.sl.sleep, ping)
	m := time.Minute
	want := []time.Duration{1 * m, 2 * m, 4 * m, 5 * m, 5 * m, 5 * m, 5 * m}
	if got := r.sl.sleeps(); !sleepsEqual(got, want) {
		t.Errorf("sleeps = %v, want %v", got, want)
	}
}

func TestProbeLoopNotPausedReturnsImmediately(t *testing.T) {
	r := newRig()
	ping := func(context.Context) error { t.Error("ping called"); return nil }
	r.m.ProbeLoop(context.Background(), r.sl.sleep, ping)
	if len(r.sl.sleeps()) != 0 {
		t.Errorf("sleeps = %v, want none", r.sl.sleeps())
	}
	if p, rs := r.nt.counts(); p != 0 || rs != 0 {
		t.Errorf("notifications = %d, %d; want 0, 0", p, rs)
	}
}

func TestProbeLoopSleepErrorReturns(t *testing.T) {
	r := newRig()
	r.m.Pause("x")
	ping := func(context.Context) error { t.Error("ping called after sleep error"); return nil }
	sleep := func(context.Context, time.Duration) error { return context.Canceled }
	done := make(chan struct{})
	go func() { r.m.ProbeLoop(context.Background(), sleep, ping); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ProbeLoop did not return after sleep error")
	}
	if p, _, _ := r.m.Paused(); !p {
		t.Error("monitor resumed although never probed successfully")
	}
	if _, rs := r.nt.counts(); rs != 0 {
		t.Errorf("Resumed notifications = %d, want 0", rs)
	}
}

func TestProbeLoopCtxCanceledDuringPing(t *testing.T) {
	r := newRig()
	r.m.Pause("x")
	ctx, cancel := context.WithCancel(context.Background())
	ping := func(context.Context) error { cancel(); return context.Canceled }
	done := make(chan struct{})
	instant := func(ctx context.Context, _ time.Duration) error { return ctx.Err() }
	go func() { r.m.ProbeLoop(ctx, instant, ping); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("ProbeLoop did not return after ctx was canceled")
	}
	if p, _, _ := r.m.Paused(); !p {
		t.Error("monitor resumed after canceled ping")
	}
}

func TestCallSleepErrorReturnedImmediately(t *testing.T) {
	r := newRig()
	fn, calls := r.script(t, step{err: api(529)})
	stop := errors.New("ctx done")
	sleep := func(context.Context, time.Duration) error { return stop }
	err := r.m.Call(context.Background(), sleep, fn)
	if err != stop {
		t.Fatalf("Call = %v, want %v", err, stop)
	}
	if calls() != 1 {
		t.Errorf("fn calls = %d, want 1", calls())
	}
	if p, _, _ := r.m.Paused(); p {
		t.Error("monitor paused by an aborted retry")
	}
}

func TestStreakResetsOnSuccess(t *testing.T) {
	r := newRig()
	ctx := context.Background()

	// t0: fail. The 1s backoff and a 49s call bring the success to t0+50s.
	fn1, _ := r.script(t, step{err: api(529)}, step{advance: 49 * time.Second})
	if err := r.m.Call(ctx, r.sl.sleep, fn1); err != nil {
		t.Fatalf("first Call = %v, want nil", err)
	}
	// t0+100s: fail again (streak would be 100s old if it had not been reset),
	// then succeed.
	fn2, _ := r.script(t, step{advance: 50 * time.Second, err: api(529)}, step{})
	if err := r.m.Call(ctx, r.sl.sleep, fn2); err != nil {
		t.Fatalf("second Call = %v, want nil", err)
	}
	if p, _, _ := r.m.Paused(); p {
		t.Error("monitor paused although every streak was under the budget")
	}
	if p, _ := r.nt.counts(); p != 0 {
		t.Errorf("Paused notifications = %d, want 0", p)
	}
}

func TestStreakIsSharedAcrossCalls(t *testing.T) {
	// Worker A fails at t0 and gives up its retries elsewhere (sleep error);
	// worker B's failure 61s later belongs to the same streak and must pause.
	r := newRig()
	ctx := context.Background()
	stop := errors.New("ctx done")
	fnA, _ := r.script(t, step{err: api(529)})
	if err := r.m.Call(ctx, func(context.Context, time.Duration) error { return stop }, fnA); err != stop {
		t.Fatalf("A: Call = %v, want %v", err, stop)
	}
	fnB, _ := r.script(t, step{advance: 61 * time.Second, err: api(529)})
	err := r.m.Call(ctx, r.sl.sleep, fnB)
	if !errors.Is(err, ErrPaused) {
		t.Fatalf("B: Call = %v, want ErrPaused", err)
	}
	if got := r.sl.sleeps(); len(got) != 0 {
		t.Errorf("B slept %v; the shared streak was already over budget", got)
	}
}

func TestCallGivesUpWithoutPausing(t *testing.T) {
	// Worker A's request keeps failing with 529 while other workers' requests
	// succeed, so the shared streak is reset again and again and never reaches
	// the budget. A must still stop after FailureBudget of its own failures,
	// without pausing protection and without pinning its worker forever.
	r := newRig()
	ctx := context.Background()
	calls := 0
	fnA := func(context.Context) error {
		calls++
		if calls > 20 { // runaway guard: end the call with a non-Jev error
			t.Error("fn still being called: Call has no bound of its own")
			return context.Canceled
		}
		return api(529)
	}
	otherOK := func(context.Context) error { return nil }
	r.sl.hook = func(int) {
		// Another worker succeeds during A's backoff.
		if err := r.m.Call(ctx, r.sl.sleep, otherOK); err != nil {
			t.Errorf("other worker: Call = %v", err)
		}
	}

	err := r.m.Call(ctx, r.sl.sleep, fnA)
	if err == nil {
		t.Fatal("Call = nil, want the last error")
	}
	if errors.Is(err, ErrPaused) {
		t.Errorf("Call = %v; giving up must not be reported as ErrPaused", err)
	}
	var apiErr *jev.APIError
	if !errors.As(err, &apiErr) || apiErr.Status != 529 {
		t.Errorf("cause not preserved: errors.As = %v, %+v", errors.As(err, &apiErr), apiErr)
	}
	s := time.Second
	want := []time.Duration{1 * s, 2 * s, 4 * s, 8 * s, 16 * s, 16 * s, 16 * s}
	if got := r.sl.sleeps(); !sleepsEqual(got, want) {
		t.Errorf("sleeps = %v, want %v", got, want)
	}
	if calls != len(want)+1 {
		t.Errorf("fn calls = %d, want %d (no call after giving up)", calls, len(want)+1)
	}
	if p, _, _ := r.m.Paused(); p {
		t.Error("monitor paused although the shared streak never reached the budget")
	}
	if p, _ := r.nt.counts(); p != 0 {
		t.Errorf("Paused notifications = %d, want 0", p)
	}
}

func TestBackoffIsPerCall(t *testing.T) {
	// A second Call starts again at 1s, even though the first ended mid-backoff.
	r := newRig()
	ctx := context.Background()
	fn1, _ := r.script(t, step{err: api(529)}, step{err: api(529)}, step{err: api(529)}, step{})
	if err := r.m.Call(ctx, r.sl.sleep, fn1); err != nil {
		t.Fatal(err)
	}
	fn2, _ := r.script(t, step{err: api(529)}, step{})
	if err := r.m.Call(ctx, r.sl.sleep, fn2); err != nil {
		t.Fatal(err)
	}
	s := time.Second
	want := []time.Duration{1 * s, 2 * s, 4 * s, 1 * s}
	if got := r.sl.sleeps(); !sleepsEqual(got, want) {
		t.Errorf("sleeps = %v, want %v", got, want)
	}
}

func TestPausedByOtherWorkerWhileSleeping(t *testing.T) {
	r := newRig()
	fn, calls := r.script(t, step{err: api(529)})
	r.sl.hook = func(n int) {
		if n == 1 {
			r.m.Pause("other worker saw 401")
		}
	}
	err := r.m.Call(context.Background(), r.sl.sleep, fn)
	if !errors.Is(err, ErrPaused) {
		t.Fatalf("Call = %v, want ErrPaused", err)
	}
	if calls() != 1 {
		t.Errorf("fn calls = %d, want 1 (no call after the pause)", calls())
	}
	if _, reason, _ := r.m.Paused(); reason != "other worker saw 401" {
		t.Errorf("reason = %q, want the first pauser's", reason)
	}
	if p, _ := r.nt.counts(); p != 1 {
		t.Errorf("Paused notifications = %d, want 1", p)
	}
}

func TestResumeClearsStreak(t *testing.T) {
	r := newRig()
	ctx := context.Background()
	failing := func(context.Context) error { return api(529) }
	if err := r.m.Call(ctx, r.sl.sleep, failing); !errors.Is(err, ErrPaused) {
		t.Fatalf("Call = %v, want ErrPaused", err)
	}
	r.m.ProbeLoop(ctx, r.sl.sleep, func(context.Context) error { return nil })
	if p, _, _ := r.m.Paused(); p {
		t.Fatal("still paused after successful probe")
	}
	// One failure right after resuming must start a fresh streak, not inherit
	// the old one (which is minutes old by now).
	fn, _ := r.script(t, step{err: api(529)}, step{})
	if err := r.m.Call(ctx, r.sl.sleep, fn); err != nil {
		t.Fatalf("Call after resume = %v, want nil", err)
	}
	if p, rs := r.nt.counts(); p != 1 || rs != 1 {
		t.Errorf("notifications = %d paused, %d resumed; want 1, 1", p, rs)
	}
}

func TestPauseAgainAfterResume(t *testing.T) {
	r := newRig()
	r.m.Pause("first")
	r.m.ProbeLoop(context.Background(), r.sl.sleep, func(context.Context) error { return nil })
	r.m.Pause("second")
	if p, reason, _ := r.m.Paused(); !p || reason != "second" {
		t.Errorf("Paused = %v, %q; want true, second", p, reason)
	}
	if p, rs := r.nt.counts(); p != 2 || rs != 1 {
		t.Errorf("notifications = %d paused, %d resumed; want 2, 1", p, rs)
	}
}

func TestNotifierCalledOutsideMutex(t *testing.T) {
	r := newRig()
	// A notifier that reads monitor state would deadlock if called under the lock.
	r.nt.onPause = func() { r.m.Paused() }
	r.nt.onResum = func() { r.m.Paused() }
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.m.Pause("x")
		r.m.ProbeLoop(context.Background(), r.sl.sleep, func(context.Context) error { return nil })
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("deadlock: notifier called while holding the monitor mutex")
	}
}

func TestConcurrentCallsPauseOnce(t *testing.T) {
	r := newRig()
	const workers = 8
	failing := func(context.Context) error { return api(529) }
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- r.m.Call(context.Background(), r.sl.sleep, failing)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if !errors.Is(err, ErrPaused) {
			t.Errorf("Call = %v, want ErrPaused", err)
		}
	}
	if p, _ := r.nt.counts(); p != 1 {
		t.Errorf("Paused notifications = %d, want exactly 1", p)
	}
	if p, _, _ := r.m.Paused(); !p {
		t.Error("monitor not paused")
	}
}

func TestConcurrentSuccessKeepsStreakFromPausing(t *testing.T) {
	// Workers that succeed keep resetting the shared streak: with failures and
	// successes interleaved, and each call far shorter than the budget, the
	// monitor never pauses.
	r := newRig()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				n := 0
				fn := func(context.Context) error {
					n++
					if n == 1 && (i+j)%2 == 0 {
						return api(503)
					}
					return nil
				}
				if err := r.m.Call(context.Background(), r.sl.sleep, fn); err != nil {
					t.Errorf("Call = %v", err)
					return
				}
			}
		}(i)
	}
	wg.Wait()
	if p, _, _ := r.m.Paused(); p {
		t.Error("monitor paused")
	}
}

func TestRealSleep(t *testing.T) {
	if err := RealSleep(context.Background(), time.Millisecond); err != nil {
		t.Errorf("RealSleep = %v, want nil", err)
	}
	if err := RealSleep(context.Background(), 0); err != nil {
		t.Errorf("RealSleep(0) = %v, want nil", err)
	}
}

func TestRealSleepCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(10 * time.Millisecond); cancel() }()
	start := time.Now()
	err := RealSleep(ctx, time.Hour)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("RealSleep = %v, want context.Canceled", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Error("RealSleep did not return promptly after cancel")
	}
}

func TestNilNotifierAndLogger(t *testing.T) {
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer slog.SetDefault(old)

	c := newClock()
	m := NewMonitor(c.now, nil, nil)
	m.Pause("x")
	if p, _, _ := m.Paused(); !p {
		t.Error("not paused")
	}
	m.ProbeLoop(context.Background(), (&fakeSleeper{clock: c}).sleep, func(context.Context) error { return nil })
	if p, _, _ := m.Paused(); p {
		t.Error("still paused")
	}
}
