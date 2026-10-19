// Package daemon wires Ostrakon together. It follows the log sources, turns
// lines into events, drops allowlisted addresses, and once an address is
// active enough asks Jev about it (through the health monitor's retry and
// pause policy). Addresses Jev convicts are banned in the firewall and
// recorded in the state file so the ban survives a restart.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"time"

	"ostrakon/internal/allowlist"
	"ostrakon/internal/event"
	"ostrakon/internal/firewall"
	"ostrakon/internal/health"
	"ostrakon/internal/judge"
	"ostrakon/internal/netutil"
	"ostrakon/internal/source"
	"ostrakon/internal/state"
	"ostrakon/internal/tracker"
)

const (
	defaultWorkers = 4
	// jobQueueCap bounds the batches waiting for a worker. When it is full
	// the newest batch is dropped; its IP triggers again on a later event.
	jobQueueCap = 1024
	// lineBuffer decouples the log tailers from line handling.
	lineBuffer = 256
	// minRestoreTTL: a stored ban with less time left is not restored.
	minRestoreTTL = time.Second
	// degradedAfter is how many decisions in a row may fail without pausing
	// (rejected requests, unusable answers) before Status reports degraded.
	degradedAfter = 5
	// failureBackoff is how long an address whose decision failed waits
	// before it may trigger another one, so that a request Jev keeps
	// rejecting is not re-sent (and billed) for every new log line.
	failureBackoff = 5 * time.Minute

	sessionsRefresh       = 30 * time.Second
	localRefresh          = 5 * time.Minute
	trackerPruneInterval  = time.Minute
	storePruneInterval    = time.Hour
	firewallCheckInterval = time.Minute
)

// Decider is the part of *judge.Judge the daemon needs.
type Decider interface {
	Decide(ctx context.Context, ip netip.Addr, evs []event.Event, h judge.History) (judge.Decision, error)
}

// Deps is everything the daemon is built from. Firewall, Decider, Ping,
// Store, Allow and Monitor are required.
type Deps struct {
	Specs    []source.Spec
	Lines    <-chan source.Line // when non-nil, read instead of starting the Specs (tests)
	Firewall firewall.Firewall
	Decider  Decider
	Ping     func(ctx context.Context) error // the probe that ends a pause
	Store    *state.Store
	Allow    *allowlist.List
	Monitor  *health.Monitor
	Sleep    health.Sleeper               // nil means health.RealSleep
	Now      func() time.Time             // nil means time.Now
	DryRun   bool                         // log ban decisions instead of carrying them out
	Log      *slog.Logger                 // nil means slog.Default()
	Workers  int                          // concurrent decisions; 0 means 4
	Sessions func() ([]netip.Addr, error) // addresses with a login session; refreshed every 30s; may be nil
	Local    func() ([]netip.Addr, error) // this machine's addresses; refreshed every 5m; may be nil
}

// Status is what `ostrakon status` shows.
type Status struct {
	Paused       bool      `json:"paused"`
	PauseReason  string    `json:"pause_reason,omitempty"`
	PausedSince  time.Time `json:"paused_since,omitzero"`
	DryRun       bool      `json:"dry_run"`
	Sources      []string  `json:"sources"` // e.g. "sshd(/var/log/auth.log)", "sshd(journald)"
	BanCount     int       `json:"ban_count"`
	LastDecision string    `json:"last_decision,omitempty"` // e.g. "2026-10-18T20:00:05Z 203.0.113.7 ssh_bruteforce p=0.93 ban 1h"
	// LastJev is the outcome of the latest Jev decision request, e.g.
	// "2026-10-18T20:00:05Z ok" or "2026-10-18T20:00:05Z error: jev: HTTP 422".
	LastJev string `json:"last_jev,omitempty"`
	// JevFailures counts the decisions in a row that failed without pausing
	// (rejected requests, unusable answers, requests that kept failing).
	JevFailures int `json:"jev_failures,omitempty"`
	// Degraded is set once JevFailures reaches 5, until a decision succeeds.
	Degraded string `json:"degraded,omitempty"`
	// Firewall is empty while the firewall works, else its latest error.
	Firewall string `json:"firewall,omitempty"`
}

// Daemon is the running pipeline. Status, Bans, Unban, Allow and Disallow
// may be called from any goroutine, before, during or after Run.
type Daemon struct {
	deps    Deps
	log     *slog.Logger
	tracker *tracker.Tracker
	sources []string

	// Production values set by New; tests in this package shorten them.
	queueCap           int
	sessionsEvery      time.Duration
	localEvery         time.Duration
	trackerPruneEvery  time.Duration
	storePruneEvery    time.Duration
	firewallCheckEvery time.Duration

	wg sync.WaitGroup // every goroutine Run starts

	// allowMu makes each allowlist change and the push of the resulting
	// list into Allow one step, so concurrent changes cannot leave Allow
	// with a stale list.
	allowMu sync.Mutex

	// repairMu lets one firewall repair run at a time: a vanished table
	// makes every concurrent ban fail, and one rebuild is enough.
	repairMu sync.Mutex

	mu           sync.Mutex
	probing      bool // a prober goroutine is running
	lastDecision string
	lastJev      string
	jevFailures  int    // decisions in a row that failed without pausing
	degraded     string // set once jevFailures reaches degradedAfter
	firewallErr  string // Status().Firewall
	checkFailing bool   // firewallErr came from the periodic check
}

// New returns a Daemon for d. Nothing runs until Run.
func New(d Deps) *Daemon {
	if d.Workers <= 0 {
		d.Workers = defaultWorkers
	}
	if d.Sleep == nil {
		d.Sleep = health.RealSleep
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Log == nil {
		d.Log = slog.Default()
	}
	sources := make([]string, 0, len(d.Specs))
	for _, s := range d.Specs {
		sources = append(sources, sourceLabel(s))
	}
	return &Daemon{
		deps:               d,
		log:                d.Log,
		tracker:            tracker.New(tracker.DefaultConfig()),
		sources:            sources,
		queueCap:           jobQueueCap,
		sessionsEvery:      sessionsRefresh,
		localEvery:         localRefresh,
		trackerPruneEvery:  trackerPruneInterval,
		storePruneEvery:    storePruneInterval,
		firewallCheckEvery: firewallCheckInterval,
	}
}

// sourceLabel names a source for Status: "sshd(/var/log/auth.log)" for a
// file, "sshd(journald)" for journald units.
func sourceLabel(s source.Spec) string {
	if s.Path != "" {
		return s.Name + "(" + s.Path + ")"
	}
	return s.Name + "(journald)"
}

// Run sets up the firewall, restores the stored bans and then judges log
// activity until ctx is done. A firewall that cannot be set up is fatal and
// returned at once; Jev being unusable is not (protection pauses instead).
// When ctx is done Run waits for the goroutines it started and returns nil,
// leaving every ban in place to expire on its own.
func (d *Daemon) Run(ctx context.Context) error {
	if err := d.deps.Firewall.Ensure(ctx); err != nil {
		return fmt.Errorf("setting up the firewall: %w", err)
	}
	if err := d.restoreBans(ctx); err != nil {
		d.setFirewallErr("cannot restore bans", err, false)
	}
	d.syncAllow()
	// Before the first line, so the administrator is protected from the start.
	d.refreshSessions()
	d.refreshLocal()

	jobs := make(chan tracker.Batch, d.queueCap)
	for range d.deps.Workers {
		d.wg.Go(func() { d.work(ctx, jobs) })
	}
	d.wg.Go(func() { d.maintain(ctx) })
	if paused, reason, _ := d.deps.Monitor.Paused(); paused {
		d.log.Warn("protection is paused; probing Jev until it answers", "reason", reason)
		d.ensureProber(ctx)
	}

	lines := d.deps.Lines
	if lines == nil {
		if len(d.deps.Specs) == 0 {
			d.log.Warn("no log sources found; there is nothing to watch")
		}
		ch := make(chan source.Line, lineBuffer)
		source.Start(ctx, d.deps.Specs, ch, d.log)
		lines = ch
	}
	d.log.Info("ostrakon started", "sources", d.sources, "dry_run", d.deps.DryRun, "workers", d.deps.Workers)

	for {
		select {
		case <-ctx.Done():
			d.wg.Wait()
			d.log.Info("ostrakon stopped; existing bans stay until they expire")
			return nil
		case ln, ok := <-lines:
			if !ok {
				lines = nil // the source is gone; keep serving until ctx is done
				continue
			}
			d.handle(ln, jobs)
		}
	}
}

// restoreBans puts the unexpired bans from the state file back into the
// firewall (its sets are empty after a reboot, or after the table was
// rebuilt) with their remaining time. It returns the first error, having
// tried every ban.
func (d *Daemon) restoreBans(ctx context.Context) error {
	now := d.deps.Now()
	restored := 0
	var first error
	for _, b := range d.deps.Store.ActiveBans(now) {
		left := b.Until.Sub(now)
		if left < minRestoreTTL {
			continue
		}
		if err := d.deps.Firewall.Ban(ctx, b.IP, left); err != nil {
			d.log.Error("cannot restore ban", "ip", b.IP, "until", b.Until, "err", err)
			if first == nil {
				first = err
			}
			continue
		}
		restored++
	}
	if restored > 0 {
		d.log.Info("restored bans", "count", restored)
	}
	return first
}

// checkFirewall is the periodic check that Ostrakon's nftables table still
// exists: `nft flush ruleset` or a reload of the distribution's nftables
// service removes it, and every ban with it. A missing table is rebuilt and
// the stored bans are put back.
func (d *Daemon) checkFirewall(ctx context.Context) {
	present, err := d.deps.Firewall.Present(ctx)
	if ctx.Err() != nil {
		return // shutting down
	}
	if err != nil {
		if d.setFirewallErr("cannot check the nftables table", err, true) {
			d.log.Warn("cannot check the nftables table", "err", err)
		}
		return
	}
	if !present {
		d.log.Warn("nftables table missing; rebuilding")
		d.repairFirewall(ctx)
		return
	}
	d.mu.Lock()
	if d.checkFailing {
		d.firewallErr, d.checkFailing = "", false
	}
	d.mu.Unlock()
}

// repairFirewall rebuilds the table (Ensure keeps whatever is still in it)
// and restores the stored bans. A failure is shown in Status().Firewall and
// logged when it differs from the previous one; success clears it.
func (d *Daemon) repairFirewall(ctx context.Context) {
	d.repairMu.Lock()
	defer d.repairMu.Unlock()
	if err := d.deps.Firewall.Ensure(ctx); err != nil {
		if d.setFirewallErr("cannot rebuild the nftables table", err, false) {
			d.log.Error("cannot rebuild the nftables table", "err", err)
		}
		return
	}
	if err := d.restoreBans(ctx); err != nil {
		d.setFirewallErr("cannot restore bans", err, false)
		return
	}
	d.clearFirewallErr()
}

// setFirewallErr makes "what: err" Status().Firewall and reports whether
// that changed it. fromCheck marks an error of the periodic check, which the
// next successful check clears.
func (d *Daemon) setFirewallErr(what string, err error, fromCheck bool) bool {
	s := what + ": " + err.Error()
	d.mu.Lock()
	defer d.mu.Unlock()
	changed := d.firewallErr != s
	d.firewallErr, d.checkFailing = s, fromCheck
	return changed
}

func (d *Daemon) clearFirewallErr() {
	d.mu.Lock()
	d.firewallErr, d.checkFailing = "", false
	d.mu.Unlock()
}

// handle takes one log line through extraction, the allowlist and the
// tracker, and queues a decision when the tracker asks for one.
func (d *Daemon) handle(ln source.Line, jobs chan<- tracker.Batch) {
	now := d.deps.Now() // one clock for NoteSuccess, Allowed and the event
	ev, ok := parse(ln.Spec, ln.Text, now)
	if !ok {
		return
	}
	if ev.Kind == event.KindAuthSuccess {
		d.deps.Allow.NoteSuccess(ev.IP, now)
		d.log.Debug("successful login; address exempt from bans", "ip", ev.IP, "for", allowlist.SuccessTTL)
		return
	}
	if d.deps.Allow.Allowed(ev.IP, now) {
		return
	}
	b, trigger := d.tracker.Add(ev)
	if !trigger {
		return
	}
	select {
	case jobs <- b:
	default:
		d.tracker.Done(b.IP, false)
		d.log.Warn("decision queue full; dropping this batch", "ip", b.IP, "queued", cap(jobs))
	}
}

func (d *Daemon) work(ctx context.Context, jobs <-chan tracker.Batch) {
	for {
		select {
		case <-ctx.Done():
			return
		case b := <-jobs:
			d.decide(ctx, b)
		}
	}
}

// decide asks Jev about one batch and acts on the answer. Every path ends the
// tracker's in-flight decision: Done, or Forget after a ban.
func (d *Daemon) decide(ctx context.Context, b tracker.Batch) {
	ip := b.IP
	h := d.deps.Store.History(ip)
	hist := judge.History{BanCount: h.Count, LastBan: h.Last}
	var dec judge.Decision
	err := d.deps.Monitor.Call(ctx, d.deps.Sleep, func(ctx context.Context) error {
		var err error
		dec, err = d.deps.Decider.Decide(ctx, ip, b.Events, hist)
		if ctx.Err() == nil {
			d.noteJevCall(err)
		}
		return err
	})
	if err != nil {
		switch {
		case errors.Is(err, health.ErrPaused):
			// The monitor has logged the pause; make sure something
			// probes for the end of it.
			d.tracker.Done(ip, false)
			d.log.Debug("no decision: protection is paused", "ip", ip)
			d.ensureProber(ctx)
		case ctx.Err() != nil:
			// Shutting down.
			d.tracker.Done(ip, false)
		default:
			// A bad request, an unusable answer, or a request that kept
			// failing on its own: drop it, and leave the IP alone for a
			// while rather than asking again on its next line.
			d.log.Warn("no decision; not asking about this address again for a while",
				"ip", ip, "for", failureBackoff, "err", err)
			d.tracker.Backoff(ip, failureBackoff)
			d.noteJevFailure(err)
		}
		return
	}
	d.noteJevSuccess()

	d.log.Info("decision", "ip", ip, "category", dec.Category, "attack_prob", dec.AttackProb,
		"ban", dec.Ban, "duration", dec.Duration, "input_tokens", dec.InputTokens)
	switch {
	case !dec.Ban:
		d.tracker.Done(ip, true)
		d.recordDecision(ip, dec, "no ban")
	case d.deps.Allow.Allowed(ip, d.deps.Now()):
		// Allowlisted while Jev was deciding: a successful login, a new
		// session, or the administrator's allow. Never ban those.
		d.log.Info("not banning: the address is now allowlisted", "ip", ip)
		d.tracker.Forget(ip)
		d.recordDecision(ip, dec, "skipped (allowlisted)")
	case d.deps.DryRun:
		d.log.Info("would ban", "ip", ip, "category", dec.Category, "duration", dec.Duration)
		d.tracker.Done(ip, true)
		d.recordDecision(ip, dec, "would ban "+shortDuration(dec.Duration))
	default:
		d.ban(ctx, ip, dec)
	}
}

// ban carries out a ban decision. A failed ban usually means the table has
// gone, so the table is repaired and the ban tried once more.
func (d *Daemon) ban(ctx context.Context, ip netip.Addr, dec judge.Decision) {
	verdict := "ban " + shortDuration(dec.Duration)
	err := d.deps.Firewall.Ban(ctx, ip, dec.Duration)
	if err != nil && ctx.Err() == nil {
		d.log.Warn("ban failed; rebuilding the nftables table and trying again", "ip", ip, "err", err)
		d.repairFirewall(ctx)
		err = d.deps.Firewall.Ban(ctx, ip, dec.Duration)
	}
	if err != nil {
		d.log.Error("ban failed", "ip", ip, "err", err)
		d.setFirewallErr("ban failed", err, false)
		d.tracker.Done(ip, false)
		d.recordDecision(ip, dec, verdict+" failed: "+err.Error())
		return
	}
	d.clearFirewallErr()
	now := d.deps.Now()
	until := now.Add(dec.Duration)
	if err := d.deps.Store.AddBan(state.Ban{IP: ip, Since: now, Until: until, Category: dec.Category}); err != nil {
		d.log.Error("ban is in effect but could not be saved; it will not be restored after a restart",
			"ip", ip, "err", err)
	}
	d.log.Info("banned", "ip", ip, "category", dec.Category, "duration", dec.Duration, "until", until)
	d.tracker.Forget(ip)
	d.recordDecision(ip, dec, verdict)
}

// recordDecision makes a decision and what came of it (outcome: "no ban",
// "ban 1h", "ban 1h failed: ...", "skipped (allowlisted)") Status().LastDecision.
func (d *Daemon) recordDecision(ip netip.Addr, dec judge.Decision, outcome string) {
	category := dec.Category
	if category == "" {
		category = "-"
	}
	s := fmt.Sprintf("%s %s %s p=%.2f %s",
		d.deps.Now().UTC().Format(time.RFC3339), ip, category, dec.AttackProb, outcome)
	d.mu.Lock()
	d.lastDecision = s
	d.mu.Unlock()
}

// noteJevCall makes the outcome of one Jev request Status().LastJev.
func (d *Daemon) noteJevCall(err error) {
	s := d.deps.Now().UTC().Format(time.RFC3339) + " ok"
	if err != nil {
		s = strings.TrimSuffix(s, "ok") + "error: " + err.Error()
	}
	d.mu.Lock()
	d.lastJev = s
	d.mu.Unlock()
}

// noteJevFailure counts a decision that failed without pausing. The
// degradedAfter-th failure in a row is logged as an error and makes Status
// report degraded until a decision succeeds.
func (d *Daemon) noteJevFailure(err error) {
	d.mu.Lock()
	d.jevFailures++
	n := d.jevFailures
	if n >= degradedAfter {
		d.degraded = fmt.Sprintf("%d consecutive Jev request failures: %v", n, err)
	}
	d.mu.Unlock()
	if n == degradedAfter {
		d.log.Error("jev requests failing", "count", n, "err", err)
	}
}

// noteJevSuccess ends a run of failed decisions.
func (d *Daemon) noteJevSuccess() {
	d.mu.Lock()
	was := d.degraded != ""
	d.jevFailures, d.degraded = 0, ""
	d.mu.Unlock()
	if was {
		d.log.Info("jev requests succeed again")
	}
}

// shortDuration formats d without zero trailing units: 1h, 10m, 168h, 1h30m.
func shortDuration(d time.Duration) string {
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = s[:len(s)-2]
	}
	if strings.HasSuffix(s, "h0m") {
		s = s[:len(s)-2]
	}
	return s
}

func (d *Daemon) paused() bool {
	p, _, _ := d.deps.Monitor.Paused()
	return p
}

// ensureProber starts the prober unless one is already running.
func (d *Daemon) ensureProber(ctx context.Context) {
	d.mu.Lock()
	if d.probing {
		d.mu.Unlock()
		return
	}
	d.probing = true
	d.mu.Unlock()
	d.wg.Go(func() { d.probe(ctx) })
}

// probe runs ProbeLoop for as long as the monitor is paused. Neither Pause
// nor ErrPaused says which Call paused, and a new pause can land just after
// ProbeLoop has resumed, while probing is still set (so ensureProber declined
// to start another prober). Hence probe re-checks after clearing the flag and
// carries on unless another prober has taken over: a paused monitor is never
// left without a prober, and there is never more than one.
func (d *Daemon) probe(ctx context.Context) {
	for {
		for d.paused() && ctx.Err() == nil {
			d.deps.Monitor.ProbeLoop(ctx, d.deps.Sleep, d.deps.Ping)
		}
		d.mu.Lock()
		d.probing = false
		d.mu.Unlock()

		if ctx.Err() != nil || !d.paused() {
			return
		}
		d.mu.Lock()
		if d.probing {
			d.mu.Unlock()
			return
		}
		d.probing = true
		d.mu.Unlock()
	}
}

// maintain runs the periodic refreshes and prunes until ctx is done.
func (d *Daemon) maintain(ctx context.Context) {
	tickers := []*time.Ticker{
		time.NewTicker(d.sessionsEvery),
		time.NewTicker(d.localEvery),
		time.NewTicker(d.trackerPruneEvery),
		time.NewTicker(d.storePruneEvery),
		time.NewTicker(d.firewallCheckEvery),
	}
	defer func() {
		for _, t := range tickers {
			t.Stop()
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tickers[0].C:
			d.refreshSessions()
		case <-tickers[1].C:
			d.refreshLocal()
		case <-tickers[2].C:
			d.tracker.Prune(d.deps.Now())
		case <-tickers[3].C:
			if err := d.deps.Store.Prune(d.deps.Now()); err != nil {
				d.log.Warn("cannot prune the state file", "err", err)
			}
		case <-tickers[4].C:
			d.checkFirewall(ctx)
		}
	}
}

// refreshSessions and refreshLocal keep the previous list when reading fails
// (a container has no utmp, for example): dropping it could expose the
// administrator.
func (d *Daemon) refreshSessions() {
	if d.deps.Sessions == nil {
		return
	}
	addrs, err := d.deps.Sessions()
	if err != nil {
		d.log.Debug("cannot read login sessions; keeping the previous list", "err", err)
		return
	}
	d.deps.Allow.SetSessions(addrs)
}

func (d *Daemon) refreshLocal() {
	if d.deps.Local == nil {
		return
	}
	addrs, err := d.deps.Local()
	if err != nil {
		d.log.Debug("cannot read local addresses; keeping the previous list", "err", err)
		return
	}
	d.deps.Allow.SetLocal(addrs)
}

// syncAllow pushes the stored allowlist into Allow.
func (d *Daemon) syncAllow() {
	d.allowMu.Lock()
	defer d.allowMu.Unlock()
	d.deps.Allow.SetUser(d.deps.Store.AllowList())
}

// Status reports the daemon's current state.
func (d *Daemon) Status() Status {
	paused, reason, since := d.deps.Monitor.Paused()
	st := Status{
		Paused:      paused,
		PauseReason: reason,
		PausedSince: since,
		DryRun:      d.deps.DryRun,
		Sources:     append([]string{}, d.sources...),
		BanCount:    len(d.deps.Store.ActiveBans(d.deps.Now())),
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	st.LastDecision = d.lastDecision
	st.LastJev = d.lastJev
	st.JevFailures = d.jevFailures
	st.Degraded = d.degraded
	st.Firewall = d.firewallErr
	return st
}

// Bans returns the active bans, soonest-expiring first.
func (d *Daemon) Bans() []state.Ban {
	return d.deps.Store.ActiveBans(d.deps.Now())
}

// Unban lifts the ban on ip in the firewall, then in the state file, and
// forgets what the tracker had seen from it.
func (d *Daemon) Unban(ctx context.Context, ip netip.Addr) error {
	ip = netutil.NormAddr(ip)
	if !ip.IsValid() {
		return errors.New("invalid IP address")
	}
	if err := d.deps.Firewall.Unban(ctx, ip); err != nil {
		return err
	}
	if _, err := d.deps.Store.RemoveBan(ip); err != nil {
		return fmt.Errorf("unbanned, but the state file was not updated (the ban would return after a restart): %w", err)
	}
	d.tracker.Forget(ip)
	d.log.Info("unbanned", "ip", ip)
	return nil
}

// Allow adds p to the administrator's allowlist (saved in the state file).
func (d *Daemon) Allow(p netip.Prefix) error {
	d.allowMu.Lock()
	defer d.allowMu.Unlock()
	if err := d.deps.Store.Allow(p); err != nil {
		return err
	}
	d.deps.Allow.SetUser(d.deps.Store.AllowList())
	return nil
}

// Disallow removes p from the administrator's allowlist. Removing a prefix
// that is not there is not an error.
func (d *Daemon) Disallow(p netip.Prefix) error {
	d.allowMu.Lock()
	defer d.allowMu.Unlock()
	if _, err := d.deps.Store.Disallow(p); err != nil {
		return err
	}
	d.deps.Allow.SetUser(d.deps.Store.AllowList())
	return nil
}
