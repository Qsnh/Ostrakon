package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ostrakon/internal/allowlist"
	"ostrakon/internal/event"
	"ostrakon/internal/firewall"
	"ostrakon/internal/health"
	"ostrakon/internal/jev"
	"ostrakon/internal/judge"
	"ostrakon/internal/source"
	"ostrakon/internal/state"
)

var sshdFile = source.Spec{Name: source.NameSSHD, Path: "/var/log/auth.log"}

func failLine(ip string) string {
	return "Oct 18 20:00:01 web sshd[1234]: Failed password for root from " + ip + " port 52211 ssh2"
}

func acceptedLine(ip string) string {
	return "Oct 18 20:00:01 web sshd[1234]: Accepted publickey for alice from " + ip + " port 50000 ssh2: ED25519 SHA256:abc"
}

var (
	banDecision    = judge.Decision{Ban: true, Duration: time.Hour, Category: "ssh_bruteforce", AttackProb: 0.93, InputTokens: 2000}
	benignDecision = judge.Decision{Category: "benign", AttackProb: 0.1, InputTokens: 1500}
)

func answerWith(dec judge.Decision, err error) func(netip.Addr) (judge.Decision, error) {
	return func(netip.Addr) (judge.Decision, error) { return dec, err }
}

type decideCall struct {
	ip      netip.Addr
	events  []event.Event
	history judge.History
}

// fakeDecider records every call and answers with answer, which runs outside
// the lock so that it may block.
type fakeDecider struct {
	mu     sync.Mutex
	calls  []decideCall
	answer func(ip netip.Addr) (judge.Decision, error)
}

func (f *fakeDecider) Decide(_ context.Context, ip netip.Addr, evs []event.Event, h judge.History) (judge.Decision, error) {
	f.mu.Lock()
	f.calls = append(f.calls, decideCall{ip: ip, events: evs, history: h})
	answer := f.answer
	f.mu.Unlock()
	return answer(ip)
}

func (f *fakeDecider) setAnswer(answer func(netip.Addr) (judge.Decision, error)) {
	f.mu.Lock()
	f.answer = answer
	f.mu.Unlock()
}

func (f *fakeDecider) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func (f *fakeDecider) countFor(ip string) int {
	a := netip.MustParseAddr(ip)
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if c.ip == a {
			n++
		}
	}
	return n
}

func (f *fakeDecider) call(i int) decideCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[i]
}

// syncBuffer is a bytes.Buffer safe for the daemon's concurrent loggers.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// fakeClock is a manually advanced clock, safe for concurrent use.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
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

type harness struct {
	t         *testing.T
	deps      Deps
	d         *Daemon
	fw        *firewall.Fake
	store     *state.Store
	statePath string
	mon       *health.Monitor
	dec       *fakeDecider
	lines     chan source.Line
	logs      *syncBuffer

	pingOK     atomic.Bool
	pinging    atomic.Int32 // ping calls in progress
	maxPinging atomic.Int32 // most ping calls ever in progress at once
}

// newHarness builds Deps with a fake firewall, a fake decider that bans,
// a real store, monitor and allowlist, an unbuffered Lines channel, a Sleep
// that returns at once and the real clock. Tests may edit h.deps before start.
func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{
		t:     t,
		fw:    firewall.NewFake(),
		dec:   &fakeDecider{answer: answerWith(banDecision, nil)},
		lines: make(chan source.Line),
		logs:  &syncBuffer{},
	}
	log := slog.New(slog.NewTextHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	h.statePath = filepath.Join(t.TempDir(), "state.json")
	store, err := state.Open(h.statePath, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	h.store = store
	h.mon = health.NewMonitor(time.Now, nil, log)
	h.deps = Deps{
		Specs:    []source.Spec{sshdFile},
		Lines:    h.lines,
		Firewall: h.fw,
		Decider:  h.dec,
		Ping:     h.ping,
		Store:    store,
		Allow:    allowlist.New(),
		Monitor:  h.mon,
		Sleep:    func(ctx context.Context, _ time.Duration) error { return ctx.Err() },
		Now:      time.Now,
		Log:      log,
	}
	return h
}

func (h *harness) ping(context.Context) error {
	n := h.pinging.Add(1)
	defer h.pinging.Add(-1)
	for {
		m := h.maxPinging.Load()
		if n <= m || h.maxPinging.CompareAndSwap(m, n) {
			break
		}
	}
	if h.pingOK.Load() {
		return nil
	}
	time.Sleep(time.Millisecond) // the test Sleep returns at once; don't spin
	return errors.New("jev still unreachable")
}

// start runs the daemon until the test ends; tweaks adjust it before Run.
// Cleanup cancels Run and requires it to return nil within 2s.
func (h *harness) start(tweaks ...func(*Daemon)) {
	h.t.Helper()
	h.d = New(h.deps)
	for _, tw := range tweaks {
		tw(h.d)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.d.Run(ctx) }()
	h.t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				h.t.Errorf("Run returned %v after cancel, want nil", err)
			}
		case <-time.After(2 * time.Second):
			h.t.Errorf("Run did not return within 2s of cancel")
		}
	})
}

// send hands lines to the daemon as if they came from the sshd auth log.
func (h *harness) send(texts ...string) {
	h.t.Helper()
	for _, s := range texts {
		select {
		case h.lines <- source.Line{Spec: sshdFile, Text: s}:
		case <-time.After(2 * time.Second):
			h.t.Fatalf("daemon did not read line %q within 2s", s)
		}
	}
}

// barrier returns once every line sent before it has been fully handled
// (parsed, filtered, tracked, queued): the daemon takes lines one at a time
// from the unbuffered channel and only takes the next after handling one.
func (h *harness) barrier() {
	h.t.Helper()
	h.send("not a log line")
}

func (h *harness) banned(ip string) (time.Duration, bool) {
	h.fw.Mu.Lock()
	defer h.fw.Mu.Unlock()
	ttl, ok := h.fw.Banned[netip.MustParseAddr(ip)]
	return ttl, ok
}

func (h *harness) bannedCount() int {
	h.fw.Mu.Lock()
	defer h.fw.Mu.Unlock()
	return len(h.fw.Banned)
}

func (h *harness) paused() bool {
	p, _, _ := h.mon.Paused()
	return p
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after 2s waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// settle gives the idle workers time to pick up a job, for asserting that
// none was queued.
func settle() { time.Sleep(50 * time.Millisecond) }

func repeat(s string, n int) []string { return slices.Repeat([]string{s}, n) }

func TestBansAttacker(t *testing.T) {
	h := newHarness(t)
	h.start()
	const ip = "203.0.113.7"
	addr := netip.MustParseAddr(ip)

	h.send(repeat(failLine(ip), 3)...)
	waitFor(t, ip+" banned in the firewall", func() bool { _, ok := h.banned(ip); return ok })
	if ttl, _ := h.banned(ip); ttl != time.Hour {
		t.Errorf("firewall ttl = %v, want 1h", ttl)
	}
	waitFor(t, "the ban recorded in the store", func() bool { return len(h.store.ActiveBans(time.Now())) == 1 })
	b := h.store.ActiveBans(time.Now())[0]
	if b.IP != addr || b.Category != "ssh_bruteforce" || b.Until.Sub(b.Since) != time.Hour {
		t.Errorf("stored ban = %+v, want %s ssh_bruteforce for 1h", b, ip)
	}
	if got := h.store.History(addr).Count; got != 1 {
		t.Errorf("History.Count = %d, want 1", got)
	}

	if n := h.dec.count(); n != 1 {
		t.Fatalf("Decide called %d times, want 1", n)
	}
	c := h.dec.call(0)
	if c.ip != addr || len(c.events) != 3 || c.history != (judge.History{}) {
		t.Errorf("Decide(ip=%v, %d events, %+v), want (%s, 3 events, no history)", c.ip, len(c.events), c.history, ip)
	}
	waitFor(t, "the tracker to forget the banned IP", func() bool { return h.d.tracker.Len() == 0 })
	waitFor(t, "the decision recorded", func() bool { return h.d.Status().LastDecision != "" })

	st := h.d.Status()
	if st.BanCount != 1 {
		t.Errorf("Status().BanCount = %d, want 1", st.BanCount)
	}
	if want := " 203.0.113.7 ssh_bruteforce p=0.93 ban 1h"; !strings.HasSuffix(st.LastDecision, want) {
		t.Errorf("Status().LastDecision = %q, want suffix %q", st.LastDecision, want)
	}
	if _, err := time.Parse(time.RFC3339, strings.Fields(st.LastDecision)[0]); err != nil {
		t.Errorf("LastDecision does not start with an RFC3339 time: %q", st.LastDecision)
	}
	if bans := h.d.Bans(); len(bans) != 1 || bans[0].IP != addr {
		t.Errorf("Bans() = %+v, want the ban of %s", bans, ip)
	}

	logs := h.logs.String()
	for _, want := range []string{
		"msg=decision ip=203.0.113.7 category=ssh_bruteforce attack_prob=0.93 ban=true duration=1h0m0s input_tokens=2000",
		"msg=banned ip=203.0.113.7",
	} {
		if !strings.Contains(logs, want) {
			t.Errorf("logs lack %q:\n%s", want, logs)
		}
	}
}

func TestAllowlistedNotJudged(t *testing.T) {
	h := newHarness(t)
	h.start()
	h.send(repeat(failLine("10.0.0.5"), 3)...)
	h.barrier()
	if n := h.dec.count(); n != 0 {
		t.Errorf("Decide called %d times for an allowlisted IP, want 0", n)
	}
	if n := h.d.tracker.Len(); n != 0 {
		t.Errorf("tracker holds %d IPs, want 0: allowlisted events must be dropped before the tracker", n)
	}
}

func TestSuccessfulLoginProtects(t *testing.T) {
	h := newHarness(t)
	h.start()
	const ip = "198.51.100.4"
	h.send(acceptedLine(ip))
	h.send(repeat(failLine(ip), 5)...)
	h.barrier()
	if n := h.dec.count(); n != 0 {
		t.Errorf("Decide called %d times after a successful login, want 0", n)
	}
	if n := h.d.tracker.Len(); n != 0 {
		t.Errorf("tracker holds %d IPs, want 0", n)
	}
}

func TestBenignNotBanned(t *testing.T) {
	h := newHarness(t)
	h.dec.setAnswer(answerWith(benignDecision, nil))
	h.start()
	const ip = "203.0.113.9"

	h.send(repeat(failLine(ip), 3)...)
	waitFor(t, "the decision", func() bool { return h.d.Status().LastDecision != "" })
	h.send(repeat(failLine(ip), 2)...)
	h.barrier()
	settle()

	if n := h.dec.count(); n != 1 {
		t.Errorf("Decide called %d times, want 1 (benign verdict cached)", n)
	}
	if n := h.bannedCount(); n != 0 {
		t.Errorf("firewall holds %d bans, want 0", n)
	}
	if got := h.d.Status().LastDecision; !strings.HasSuffix(got, " 203.0.113.9 benign p=0.10 no ban") {
		t.Errorf("LastDecision = %q, want it to end in %q", got, " 203.0.113.9 benign p=0.10 no ban")
	}
}

func TestDryRun(t *testing.T) {
	h := newHarness(t)
	h.deps.DryRun = true
	h.start()
	const ip = "203.0.113.10"

	h.send(repeat(failLine(ip), 3)...)
	waitFor(t, `"would ban" logged`, func() bool { return strings.Contains(h.logs.String(), "msg=\"would ban\" ip="+ip) })
	waitFor(t, "the decision recorded", func() bool { return h.d.Status().LastDecision != "" })

	if n := h.bannedCount(); n != 0 {
		t.Errorf("firewall holds %d bans in dry-run, want 0", n)
	}
	if bans := h.store.ActiveBans(time.Now()); len(bans) != 0 {
		t.Errorf("store holds %v in dry-run, want none", bans)
	}
	if got := h.store.History(netip.MustParseAddr(ip)).Count; got != 0 {
		t.Errorf("History.Count = %d in dry-run, want 0", got)
	}
	st := h.d.Status()
	if !st.DryRun {
		t.Error("Status().DryRun = false, want true")
	}
	if !strings.HasSuffix(st.LastDecision, " 203.0.113.10 ssh_bruteforce p=0.93 would ban 1h") {
		t.Errorf("LastDecision = %q, want a dry-run ban decision", st.LastDecision)
	}
}

func TestPauseAndResume(t *testing.T) {
	h := newHarness(t)
	h.dec.setAnswer(answerWith(judge.Decision{}, &jev.APIError{Status: 401}))
	h.start()

	h.send(repeat(failLine("203.0.113.20"), 3)...)
	waitFor(t, "protection to pause", func() bool { return h.d.Status().Paused })
	st := h.d.Status()
	if !strings.Contains(st.PauseReason, "401") || st.PausedSince.IsZero() {
		t.Errorf("Status() = %+v, want a reason mentioning 401 and a pause time", st)
	}

	// More triggers while paused: every worker that sees ErrPaused asks for
	// a prober, yet at most one may run.
	for _, ip := range []string{"203.0.113.21", "203.0.113.22", "203.0.113.23"} {
		h.send(repeat(failLine(ip), 3)...)
	}
	waitFor(t, "the paused triggers to be skipped", func() bool {
		logs := h.logs.String()
		return strings.Contains(logs, "ip=203.0.113.21") && strings.Contains(logs, "ip=203.0.113.22") &&
			strings.Contains(logs, "ip=203.0.113.23")
	})
	if n := h.dec.count(); n != 1 {
		t.Errorf("Decide called %d times, want 1 (no calls while paused)", n)
	}

	h.pingOK.Store(true)
	waitFor(t, "protection to resume", func() bool { return !h.d.Status().Paused })
	if got := h.maxPinging.Load(); got != 1 {
		t.Errorf("at most %d pings ran at once, want exactly 1 prober", got)
	}

	h.dec.setAnswer(answerWith(banDecision, nil))
	h.send(repeat(failLine("203.0.113.30"), 3)...)
	waitFor(t, "203.0.113.30 banned after resuming", func() bool { _, ok := h.banned("203.0.113.30"); return ok })
}

func TestProbesWhenPausedAtStart(t *testing.T) {
	h := newHarness(t)
	h.mon.Pause("no API key: set TYPESAFE_API_KEY")
	h.start()

	h.barrier() // Run is past start-up
	st := h.d.Status()
	if !st.Paused || st.PauseReason != "no API key: set TYPESAFE_API_KEY" {
		t.Fatalf("Status() = %+v, want paused with the caller's reason", st)
	}
	h.pingOK.Store(true)
	waitFor(t, "the start-up prober to resume protection", func() bool { return !h.paused() })

	h.send(repeat(failLine("203.0.113.31"), 3)...)
	waitFor(t, "203.0.113.31 banned", func() bool { _, ok := h.banned("203.0.113.31"); return ok })
}

func TestRestoreBans(t *testing.T) {
	h := newHarness(t)
	now := time.Now()
	for _, b := range []state.Ban{
		{IP: netip.MustParseAddr("203.0.113.40"), Since: now.Add(-30 * time.Minute), Until: now.Add(30 * time.Minute), Category: "ssh_bruteforce"},
		{IP: netip.MustParseAddr("203.0.113.41"), Since: now.Add(-2 * time.Hour), Until: now.Add(-time.Hour), Category: "web_scan"},
	} {
		if err := h.store.AddBan(b); err != nil {
			t.Fatal(err)
		}
	}
	h.start()
	h.barrier() // Run reads lines only after restoring

	ttl, ok := h.banned("203.0.113.40")
	if !ok || ttl < 30*time.Minute-time.Second || ttl > 30*time.Minute {
		t.Errorf("restored ttl = %v (present %v), want within [29m59s, 30m]", ttl, ok)
	}
	if _, ok := h.banned("203.0.113.41"); ok {
		t.Error("an expired ban was restored")
	}
}

func TestEnsureFailureIsFatal(t *testing.T) {
	h := newHarness(t)
	h.fw.Err = errors.New("nft: Operation not permitted")
	d := New(h.deps)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()
	select {
	case err := <-done:
		if err == nil || !errors.Is(err, h.fw.Err) {
			t.Errorf("Run = %v, want an error wrapping %v", err, h.fw.Err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after Ensure failed")
	}
	if h.fw.EnsureCalls != 1 {
		t.Errorf("EnsureCalls = %d, want 1", h.fw.EnsureCalls)
	}
}

func TestUnbanAndAllow(t *testing.T) {
	h := newHarness(t)
	h.start()
	ctx := context.Background()
	const ip = "203.0.113.50"
	addr := netip.MustParseAddr(ip)

	h.send(repeat(failLine(ip), 3)...)
	waitFor(t, "the ban to be stored", func() bool { return len(h.store.ActiveBans(time.Now())) == 1 })
	if err := h.d.Unban(ctx, addr); err != nil {
		t.Fatalf("Unban: %v", err)
	}
	if _, ok := h.banned(ip); ok {
		t.Error("firewall still bans the IP after Unban")
	}
	if bans := h.store.ActiveBans(time.Now()); len(bans) != 0 {
		t.Errorf("store still holds %v after Unban", bans)
	}
	if n := h.d.Status().BanCount; n != 0 {
		t.Errorf("Status().BanCount = %d after Unban, want 0", n)
	}
	if err := h.d.Unban(ctx, netip.Addr{}); err == nil {
		t.Error("Unban of an invalid address succeeded")
	}

	p := netip.MustParsePrefix("198.51.100.0/24")
	if err := h.d.Allow(p); err != nil {
		t.Fatalf("Allow: %v", err)
	}
	if got := h.store.AllowList(); !slices.Equal(got, []netip.Prefix{p}) {
		t.Errorf("store allowlist = %v, want [%v]", got, p)
	}
	h.send(repeat(failLine("198.51.100.77"), 3)...)
	h.barrier()
	if n := h.dec.countFor("198.51.100.77"); n != 0 {
		t.Errorf("Decide called %d times for an allowed prefix, want 0", n)
	}
	if n := h.d.tracker.Len(); n != 0 {
		t.Errorf("tracker holds %d IPs, want 0", n)
	}

	if err := h.d.Disallow(p); err != nil {
		t.Fatalf("Disallow: %v", err)
	}
	if err := h.d.Disallow(p); err != nil {
		t.Errorf("Disallow of a missing prefix = %v, want nil", err)
	}
	h.send(repeat(failLine("198.51.100.77"), 3)...)
	waitFor(t, "198.51.100.77 judged once disallowed", func() bool { return h.dec.countFor("198.51.100.77") == 1 })
}

func TestSessionsProtectFromFirstLine(t *testing.T) {
	h := newHarness(t)
	h.deps.Sessions = func() ([]netip.Addr, error) { return []netip.Addr{netip.MustParseAddr("203.0.113.60")}, nil }
	h.deps.Local = func() ([]netip.Addr, error) { return []netip.Addr{netip.MustParseAddr("203.0.113.61")}, nil }
	h.start()

	h.send(repeat(failLine("203.0.113.60"), 3)...)
	h.send(repeat(failLine("203.0.113.61"), 3)...)
	h.barrier()
	if n := h.dec.count(); n != 0 {
		t.Errorf("Decide called %d times for a session / local address, want 0", n)
	}
	if n := h.d.tracker.Len(); n != 0 {
		t.Errorf("tracker holds %d IPs, want 0", n)
	}
}

func TestRefreshKeepsOldListOnError(t *testing.T) {
	h := newHarness(t)
	var sessionCalls, localCalls atomic.Int32
	h.deps.Sessions = func() ([]netip.Addr, error) {
		if sessionCalls.Add(1) == 1 {
			return []netip.Addr{netip.MustParseAddr("203.0.113.62")}, nil
		}
		return nil, errors.New("open /var/run/utmp: no such file or directory")
	}
	h.deps.Local = func() ([]netip.Addr, error) {
		if localCalls.Add(1) == 1 {
			return nil, nil
		}
		return []netip.Addr{netip.MustParseAddr("203.0.113.63")}, nil // a new address appeared
	}
	h.start(func(d *Daemon) {
		d.sessionsEvery = 5 * time.Millisecond
		d.localEvery = 5 * time.Millisecond
	})

	waitFor(t, "periodic refreshes", func() bool { return sessionCalls.Load() >= 3 && localCalls.Load() >= 3 })
	h.send(repeat(failLine("203.0.113.62"), 3)...)
	h.send(repeat(failLine("203.0.113.63"), 3)...)
	h.barrier()
	if n := h.dec.count(); n != 0 {
		t.Errorf("Decide called %d times, want 0: a failed refresh keeps the old sessions and a later one adds addresses", n)
	}
	if n := h.d.tracker.Len(); n != 0 {
		t.Errorf("tracker holds %d IPs, want 0: a failed refresh keeps the old sessions and a later one adds addresses", n)
	}
	if logs := h.logs.String(); !strings.Contains(logs, "level=DEBUG") || !strings.Contains(logs, "no such file or directory") {
		t.Errorf("the refresh error was not logged at Debug:\n%s", logs)
	}
}

func TestQueueFullDropsAndRetriggers(t *testing.T) {
	h := newHarness(t)
	h.deps.Workers = 1
	release := make(chan struct{})
	var once sync.Once
	h.dec.setAnswer(func(ip netip.Addr) (judge.Decision, error) {
		if ip == netip.MustParseAddr("203.0.113.80") {
			<-release
		}
		return benignDecision, nil
	})
	h.start(func(d *Daemon) { d.queueCap = 1 })
	t.Cleanup(func() { once.Do(func() { close(release) }) }) // runs before Run is canceled

	h.send(repeat(failLine("203.0.113.80"), 3)...)
	waitFor(t, "the only worker to be busy", func() bool { return h.dec.countFor("203.0.113.80") == 1 })
	h.send(repeat(failLine("203.0.113.81"), 3)...) // fills the queue
	h.send(repeat(failLine("203.0.113.82"), 3)...) // dropped
	h.barrier()
	if logs := h.logs.String(); !strings.Contains(logs, "level=WARN") || !strings.Contains(logs, "ip=203.0.113.82") {
		t.Errorf("the dropped batch was not logged at Warn:\n%s", logs)
	}

	once.Do(func() { close(release) })
	waitFor(t, "the queued batch", func() bool { return h.dec.countFor("203.0.113.81") == 1 })
	settle()
	if n := h.dec.countFor("203.0.113.82"); n != 0 {
		t.Fatalf("the dropped batch was judged %d times, want 0", n)
	}
	// Dropping released the IP, so its next event triggers again.
	h.send(failLine("203.0.113.82"))
	waitFor(t, "the dropped IP to trigger again", func() bool { return h.dec.countFor("203.0.113.82") == 1 })
}

func TestLoginDuringDecisionNotBanned(t *testing.T) {
	h := newHarness(t)
	release := make(chan struct{})
	var once sync.Once
	h.dec.setAnswer(func(netip.Addr) (judge.Decision, error) {
		<-release
		return banDecision, nil
	})
	h.start()
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	const ip = "198.51.100.9"

	h.send(repeat(failLine(ip), 3)...)
	waitFor(t, "the decision to start", func() bool { return h.dec.count() == 1 })
	h.send(acceptedLine(ip)) // the administrator got in while Jev was deciding
	h.barrier()
	once.Do(func() { close(release) })

	waitFor(t, "the skipped ban to be logged", func() bool { return strings.Contains(h.logs.String(), "allowlisted") })
	if n := h.bannedCount(); n != 0 {
		t.Errorf("firewall holds %d bans, want 0: the address logged in successfully", n)
	}
	waitFor(t, "the decision recorded", func() bool { return h.d.Status().LastDecision != "" })
	if got, want := h.d.Status().LastDecision, " 198.51.100.9 ssh_bruteforce p=0.93 skipped (allowlisted)"; !strings.HasSuffix(got, want) {
		t.Errorf("LastDecision = %q, want suffix %q", got, want)
	}
}

func TestPeriodicPrune(t *testing.T) {
	h := newHarness(t)
	clock := &fakeClock{t: time.Now()}
	h.deps.Now = clock.now
	h.dec.setAnswer(answerWith(benignDecision, nil))
	old := netip.MustParseAddr("203.0.113.70")
	if err := h.store.AddBan(state.Ban{IP: old, Since: clock.now(), Until: clock.now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	h.start(func(d *Daemon) {
		d.trackerPruneEvery = 5 * time.Millisecond
		d.storePruneEvery = 5 * time.Millisecond
	})

	h.send(repeat(failLine("203.0.113.71"), 3)...)
	waitFor(t, "the decision", func() bool { return h.dec.count() == 1 })
	h.barrier()
	if h.d.tracker.Len() != 1 || h.store.History(old).Count != 1 {
		t.Fatalf("before pruning: tracker holds %d IPs, history count %d; want 1 and 1", h.d.tracker.Len(), h.store.History(old).Count)
	}

	clock.advance(state.HistoryTTL + time.Hour)
	waitFor(t, "the tracker to be pruned", func() bool { return h.d.tracker.Len() == 0 })
	waitFor(t, "stale history to be pruned", func() bool { return h.store.History(old).Count == 0 })
}

func TestRealSourcesWhenNoLines(t *testing.T) {
	h := newHarness(t)
	path := filepath.Join(t.TempDir(), "auth.log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	h.deps.Lines = nil
	h.deps.Specs = []source.Spec{{Name: source.NameSSHD, Path: path}}
	h.start()

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	// The tailer starts at the end of the file, so keep writing until it has
	// seen three lines.
	waitFor(t, "a ban from the tailed file", func() bool {
		if _, err := f.WriteString(failLine("203.0.113.90") + "\n"); err != nil {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
		_, ok := h.banned("203.0.113.90")
		return ok
	})
	if got := h.d.Status().Sources; !slices.Equal(got, []string{"sshd(" + path + ")"}) {
		t.Errorf("Status().Sources = %v", got)
	}
}

func TestStatusSources(t *testing.T) {
	h := newHarness(t)
	h.deps.Specs = []source.Spec{
		{Name: source.NameSSHD, Path: "/var/log/auth.log"},
		{Name: source.NameSSHD, JournalUnits: []string{"ssh.service", "sshd.service"}},
		{Name: source.NameNginxAccess, Path: "/var/log/nginx/access.log"},
	}
	st := New(h.deps).Status()
	want := []string{"sshd(/var/log/auth.log)", "sshd(journald)", "nginx-access(/var/log/nginx/access.log)"}
	if !slices.Equal(st.Sources, want) {
		t.Errorf("Sources = %q, want %q", st.Sources, want)
	}
	if st.Paused || st.BanCount != 0 || st.LastDecision != "" {
		t.Errorf("fresh Status() = %+v", st)
	}

	h.deps.Specs = nil
	data, err := json.Marshal(New(h.deps).Status())
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(data), `{"paused":false,"dry_run":false,"sources":[],"ban_count":0}`; got != want {
		t.Errorf("JSON = %s, want %s", got, want)
	}
}

func TestParse(t *testing.T) {
	now := time.Date(2026, 10, 18, 20, 0, 0, 0, time.UTC)
	journal := source.Spec{Name: source.NameSSHD, JournalUnits: []string{"ssh.service"}}
	nginx := source.Spec{Name: source.NameNginxAccess, Path: "/var/log/nginx/access.log"}
	tests := []struct {
		name string
		spec source.Spec
		text string
		ok   bool
		kind event.Kind
	}{
		{"sshd file, syslog line", sshdFile, failLine("203.0.113.7"), true, event.KindAuthFail},
		{"sshd file, bare message lacks the syslog prefix", sshdFile, "Failed password for root from 203.0.113.7 port 1 ssh2", false, ""},
		{"sshd journal, bare message", journal, "Invalid user oracle from 203.0.113.7 port 40000", true, event.KindInvalidUser},
		{"nginx access", nginx, `203.0.113.7 - - [18/Oct/2026:20:00:00 +0000] "GET /.env HTTP/1.1" 404 153 "-" "curl/8"`, true, event.KindHTTPRequest},
		{"unknown source", source.Spec{Name: "postfix", Path: "/var/log/mail.log"}, failLine("203.0.113.7"), false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev, ok := parse(tt.spec, tt.text, now)
			if ok != tt.ok {
				t.Fatalf("ok = %v, want %v", ok, tt.ok)
			}
			if !ok {
				return
			}
			if ev.Kind != tt.kind || ev.IP != netip.MustParseAddr("203.0.113.7") || !ev.Time.Equal(now) {
				t.Errorf("event = %+v, want kind %s from 203.0.113.7 at %v", ev, tt.kind, now)
			}
		})
	}
}

// Requests Jev keeps rejecting (422) do not pause protection, but they must
// not go unnoticed either, nor be re-asked for every new line.
func TestNonPausingFailuresDegradeAndBackOff(t *testing.T) {
	h := newHarness(t)
	h.dec.setAnswer(answerWith(judge.Decision{}, &jev.APIError{Status: 422, Body: "bad state"}))
	h.start()
	ips := []string{"203.0.113.101", "203.0.113.102", "203.0.113.103", "203.0.113.104", "203.0.113.105"}
	for i, ip := range ips {
		h.send(repeat(failLine(ip), 3)...)
		waitFor(t, "a failed decision for "+ip, func() bool { return h.d.Status().JevFailures == i+1 })
		if st := h.d.Status(); i < 4 && st.Degraded != "" {
			t.Fatalf("degraded after %d failures: %q", i+1, st.Degraded)
		}
	}
	st := h.d.Status()
	if !strings.Contains(st.Degraded, "5 consecutive Jev request failures") || !strings.Contains(st.Degraded, "HTTP 422") {
		t.Errorf("Status().Degraded = %q, want it to count 5 failures and name the error", st.Degraded)
	}
	if st.Paused {
		t.Error("a rejected request paused protection")
	}
	if !strings.HasSuffix(st.LastJev, " error: jev: HTTP 422: bad state") {
		t.Errorf("Status().LastJev = %q, want the 422 error", st.LastJev)
	}
	if _, err := time.Parse(time.RFC3339, strings.Fields(st.LastJev)[0]); err != nil {
		t.Errorf("LastJev does not start with an RFC3339 time: %q", st.LastJev)
	}
	errLog := `level=ERROR msg="jev requests failing" count=5`
	if n := strings.Count(h.logs.String(), errLog); n != 1 {
		t.Errorf("%q logged %d times, want once:\n%s", errLog, n, h.logs.String())
	}
	data, _ := json.Marshal(st)
	for _, key := range []string{`"last_jev":`, `"jev_failures":5`, `"degraded":`} {
		if !strings.Contains(string(data), key) {
			t.Errorf("status JSON lacks %s: %s", key, data)
		}
	}

	// The same address keeps failing to log in: backed off, Jev is not asked.
	h.send(repeat(failLine(ips[0]), 10)...)
	h.barrier()
	settle()
	if n := h.dec.countFor(ips[0]); n != 1 {
		t.Errorf("Decide called %d times for %s within the backoff, want 1", n, ips[0])
	}

	// A sixth failure is counted but not logged at Error again.
	h.send(repeat(failLine("203.0.113.106"), 3)...)
	waitFor(t, "the sixth failure", func() bool { return h.d.Status().JevFailures == 6 })
	if n := strings.Count(h.logs.String(), `msg="jev requests failing"`); n != 1 {
		t.Errorf(`"jev requests failing" logged %d times after 6 failures, want once`, n)
	}

	// A success clears it.
	h.dec.setAnswer(answerWith(benignDecision, nil))
	h.send(repeat(failLine("203.0.113.107"), 3)...)
	waitFor(t, "a success to clear the degraded state", func() bool {
		st := h.d.Status()
		return st.Degraded == "" && st.JevFailures == 0
	})
	if got := h.d.Status().LastJev; !strings.HasSuffix(got, " ok") {
		t.Errorf("Status().LastJev = %q after a success, want it to end in ok", got)
	}
}

// Review probe: malformed 200 answers made every further line from the same
// attacker a new billed Jev call.
func TestMalformedAnswerNotReaskedPerLine(t *testing.T) {
	h := newHarness(t)
	h.dec.setAnswer(answerWith(judge.Decision{}, fmt.Errorf("%w: is_attack has no noul value", judge.ErrMalformedAnswer)))
	h.start()
	const ip = "203.0.113.120"
	h.send(repeat(failLine(ip), 3)...)
	waitFor(t, "the first decision to fail", func() bool { return strings.Contains(h.logs.String(), `msg="no decision`) })
	for range 20 {
		h.send(failLine(ip))
		time.Sleep(2 * time.Millisecond) // let a (wrongly) queued decision run
	}
	h.barrier()
	settle()
	if n := h.dec.count(); n != 1 {
		t.Errorf("Decide called %d times for 23 lines from one address, want 1", n)
	}
	if st := h.d.Status(); st.JevFailures != 1 || st.Degraded != "" {
		t.Errorf("Status() = %+v, want 1 failure and not degraded", st)
	}
}

// Something removed the table at runtime (nft flush ruleset, a reload of
// nftables.service): the periodic check rebuilds it and puts the bans back.
func TestFirewallTableRebuiltWhenMissing(t *testing.T) {
	h := newHarness(t)
	now := time.Now()
	stored := netip.MustParseAddr("203.0.113.140")
	if err := h.store.AddBan(state.Ban{IP: stored, Since: now.Add(-10 * time.Minute), Until: now.Add(50 * time.Minute), Category: "ssh_bruteforce"}); err != nil {
		t.Fatal(err)
	}
	h.start(func(d *Daemon) { d.firewallCheckEvery = 5 * time.Millisecond })
	h.send(repeat(failLine("203.0.113.141"), 3)...)
	waitFor(t, "both bans stored", func() bool { return len(h.store.ActiveBans(time.Now())) == 2 })

	h.fw.Mu.Lock()
	h.fw.Missing = true // the table, and every ban in it, is gone
	clear(h.fw.Banned)
	ensures := h.fw.EnsureCalls
	h.fw.Mu.Unlock()

	waitFor(t, "the table rebuilt and both bans restored", func() bool {
		h.fw.Mu.Lock()
		defer h.fw.Mu.Unlock()
		return !h.fw.Missing && h.fw.EnsureCalls > ensures && len(h.fw.Banned) == 2
	})
	if ttl, _ := h.banned("203.0.113.140"); ttl < 49*time.Minute || ttl > 50*time.Minute {
		t.Errorf("restored ttl = %v, want the remaining ~50m", ttl)
	}
	if ttl, _ := h.banned("203.0.113.141"); ttl < 59*time.Minute || ttl > time.Hour {
		t.Errorf("restored ttl = %v, want the remaining ~1h", ttl)
	}
	if !strings.Contains(h.logs.String(), `level=WARN msg="nftables table missing; rebuilding"`) {
		t.Errorf("the rebuild was not logged at Warn:\n%s", h.logs.String())
	}
	if st := h.d.Status(); st.Firewall != "" {
		t.Errorf("Status().Firewall = %q after a successful rebuild, want empty", st.Firewall)
	}
}

// A failed ban repairs the table and tries once more.
func TestBanFailureRepairsAndRetries(t *testing.T) {
	h := newHarness(t)
	h.start() // the periodic check is a minute away: only the failed ban can repair
	h.barrier()
	h.fw.Mu.Lock()
	h.fw.Missing = true
	h.fw.Mu.Unlock()

	const ip = "203.0.113.150"
	h.send(repeat(failLine(ip), 3)...)
	waitFor(t, ip+" banned after the repair", func() bool { _, ok := h.banned(ip); return ok })
	h.fw.Mu.Lock()
	ensures := h.fw.EnsureCalls
	h.fw.Mu.Unlock()
	if ensures != 2 {
		t.Errorf("EnsureCalls = %d, want 2 (start-up and the repair)", ensures)
	}
	waitFor(t, "the ban stored", func() bool { return len(h.store.ActiveBans(time.Now())) == 1 })
	waitFor(t, "the decision recorded", func() bool { return h.d.Status().LastDecision != "" })
	st := h.d.Status()
	if want := " " + ip + " ssh_bruteforce p=0.93 ban 1h"; !strings.HasSuffix(st.LastDecision, want) {
		t.Errorf("LastDecision = %q, want suffix %q", st.LastDecision, want)
	}
	if st.Firewall != "" {
		t.Errorf("Status().Firewall = %q, want empty", st.Firewall)
	}
}

// A ban that cannot be made is not reported as made.
func TestBanFailureRecorded(t *testing.T) {
	h := newHarness(t)
	h.start()
	h.barrier()
	boom := errors.New("nft: Error: Could not process rule: Operation not permitted")
	h.fw.Mu.Lock()
	h.fw.Err = boom
	h.fw.Mu.Unlock()

	const ip = "203.0.113.160"
	h.send(repeat(failLine(ip), 3)...)
	waitFor(t, "the failed ban recorded", func() bool { return strings.Contains(h.d.Status().LastDecision, ip) })
	settle()
	st := h.d.Status()
	if want := " " + ip + " ssh_bruteforce p=0.93 ban 1h failed: " + boom.Error(); !strings.HasSuffix(st.LastDecision, want) {
		t.Errorf("LastDecision = %q, want suffix %q", st.LastDecision, want)
	}
	if !strings.Contains(st.Firewall, boom.Error()) {
		t.Errorf("Status().Firewall = %q, want the nft error", st.Firewall)
	}
	if st.BanCount != 0 || len(h.store.ActiveBans(time.Now())) != 0 {
		t.Errorf("a failed ban was recorded as active: %+v", h.store.ActiveBans(time.Now()))
	}
	h.fw.Mu.Lock()
	ensures := h.fw.EnsureCalls
	h.fw.Mu.Unlock()
	if ensures != 2 {
		t.Errorf("EnsureCalls = %d, want 2 (start-up and the repair attempt)", ensures)
	}
	if !strings.Contains(h.logs.String(), `level=ERROR msg="ban failed" ip=`+ip) {
		t.Errorf("the failed ban was not logged at Error:\n%s", h.logs.String())
	}

	// The firewall works again: the next ban succeeds and clears the error.
	h.fw.Mu.Lock()
	h.fw.Err = nil
	h.fw.Mu.Unlock()
	h.send(repeat(failLine("203.0.113.161"), 3)...)
	waitFor(t, "203.0.113.161 banned", func() bool { _, ok := h.banned("203.0.113.161"); return ok })
	waitFor(t, "the firewall error cleared", func() bool { return h.d.Status().Firewall == "" })
}

// A periodic check that cannot run is shown, and logged once rather than
// every minute.
func TestFirewallCheckErrorShown(t *testing.T) {
	h := newHarness(t)
	h.start(func(d *Daemon) { d.firewallCheckEvery = 5 * time.Millisecond })
	h.barrier()
	boom := errors.New("nft: exec: \"nft\": executable file not found in $PATH")
	h.fw.Mu.Lock()
	h.fw.Err = boom
	h.fw.Mu.Unlock()
	waitFor(t, "the check error in Status", func() bool { return strings.Contains(h.d.Status().Firewall, boom.Error()) })
	time.Sleep(30 * time.Millisecond) // several more ticks
	if n := strings.Count(h.logs.String(), `msg="cannot check the nftables table"`); n != 1 {
		t.Errorf("check failure logged %d times, want once", n)
	}

	// The check works again: the error goes away.
	h.fw.Mu.Lock()
	h.fw.Err = nil
	h.fw.Mu.Unlock()
	waitFor(t, "the check error cleared", func() bool { return h.d.Status().Firewall == "" })
}
