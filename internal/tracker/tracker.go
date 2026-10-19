// Package tracker keeps a sliding window of events per source IP and decides
// when an IP has been active enough to be worth asking Jev about. All
// thresholds are constants: the only judgment is the model's.
package tracker

import (
	"container/list"
	"net/netip"
	"slices"
	"sync"
	"time"

	"ostrakon/internal/event"
)

// Event sources, as set by the extractors.
const (
	sourceSSHD  = "sshd"
	sourceNginx = "nginx-access"
)

// Trigger thresholds, counted over the events inside the window.
const (
	sshdRelevantTrigger  = 3   // failed / invalid / pre-auth-closed sshd attempts
	nginxRelevantTrigger = 10  // nginx requests answered with a 4xx
	nginxVolumeTrigger   = 300 // nginx requests of any status
)

// Config sizes the tracker. DefaultConfig holds the production values; New
// replaces any non-positive field with its default.
type Config struct {
	Window    time.Duration // how far back events count
	BenignTTL time.Duration // how long a "benign" verdict is remembered
	MaxEvents int           // events per Batch (the newest ones)
	PerIPCap  int           // events kept per IP
	MaxIPs    int           // tracked IPs; least recently active is evicted
}

// DefaultConfig returns the production configuration.
func DefaultConfig() Config {
	return Config{
		Window:    10 * time.Minute,
		BenignTTL: time.Hour,
		MaxEvents: 50,
		PerIPCap:  400,
		MaxIPs:    100000,
	}
}

// Batch is what to ask Jev about: the newest events of one IP, across all
// sources, in ascending time order. Events is a private copy.
type Batch struct {
	IP     netip.Addr
	Events []event.Event
}

// Tracker is safe for concurrent use.
type Tracker struct {
	cfg Config

	mu  sync.Mutex
	ips map[netip.Addr]*list.Element // element value is *ipState
	lru *list.List                   // front = most recently active
}

// ipState is everything remembered about one IP.
type ipState struct {
	ip netip.Addr
	// events is sorted ascending by Time and every entry is less than Window
	// older than the last one.
	events   []event.Event
	inFlight bool // a Batch was handed out and neither Done nor Forget has followed

	benign      bool      // a benign verdict is cached
	benignBase  counts    // the window's tallies when it was cached
	benignUntil time.Time // last event time at caching + BenignTTL
}

// counts are the per-source tallies the trigger rules look at.
type counts struct {
	sshdRelevant  int
	nginxRelevant int
	nginxTotal    int
}

// triggersAbove reports whether some trigger condition holds and, for that
// same condition, the count is at least double what base recorded. With a zero
// base this is the plain trigger rule.
func (c counts) triggersAbove(base counts) bool {
	return (c.sshdRelevant >= sshdRelevantTrigger && c.sshdRelevant >= 2*base.sshdRelevant) ||
		(c.nginxRelevant >= nginxRelevantTrigger && c.nginxRelevant >= 2*base.nginxRelevant) ||
		(c.nginxTotal >= nginxVolumeTrigger && c.nginxTotal >= 2*base.nginxTotal)
}

// New returns an empty Tracker.
func New(cfg Config) *Tracker {
	def := DefaultConfig()
	if cfg.Window <= 0 {
		cfg.Window = def.Window
	}
	if cfg.BenignTTL <= 0 {
		cfg.BenignTTL = def.BenignTTL
	}
	if cfg.MaxEvents <= 0 {
		cfg.MaxEvents = def.MaxEvents
	}
	if cfg.PerIPCap <= 0 {
		cfg.PerIPCap = def.PerIPCap
	}
	if cfg.MaxIPs <= 0 {
		cfg.MaxIPs = def.MaxIPs
	}
	return &Tracker{cfg: cfg, ips: make(map[netip.Addr]*list.Element), lru: list.New()}
}

// Add records ev and reports whether its IP now deserves a decision. The
// current moment is ev.Time (or, for an out-of-order event, the newest time
// seen), and only events less than Window old count. auth_success events are
// neither stored nor counted.
//
// A true result marks the IP in flight: further events are stored but do not
// trigger until Done or Forget.
func (t *Tracker) Add(ev event.Event) (Batch, bool) {
	if ev.Kind == event.KindAuthSuccess || !ev.IP.IsValid() {
		return Batch{}, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	var st *ipState
	if el, ok := t.ips[ev.IP]; ok {
		st = el.Value.(*ipState)
		t.lru.MoveToFront(el)
	} else {
		for len(t.ips) >= t.cfg.MaxIPs {
			t.evictOldest()
		}
		st = &ipState{ip: ev.IP}
		t.ips[ev.IP] = t.lru.PushFront(st)
	}

	st.insert(ev)
	st.expire(st.newest(), t.cfg.Window)
	st.capTo(t.cfg.PerIPCap)

	if st.inFlight {
		return Batch{}, false
	}
	now := st.newest()
	if st.benign && !now.Before(st.benignUntil) {
		st.benign = false
	}
	var base counts
	if st.benign {
		base = st.benignBase
	}
	if !st.count().triggersAbove(base) {
		return Batch{}, false
	}
	st.inFlight = true
	return Batch{IP: ev.IP, Events: st.latest(t.cfg.MaxEvents)}, true
}

// Done ends the decision started by Add. With benign=true the verdict is
// cached: until BenignTTL after its last event, a trigger condition only fires
// again once its own count (sshd relevant, nginx 4xx or nginx total) has at
// least doubled since now, so web traffic cannot buy an SSH attacker a free
// pass or the other way round. With benign=false (a ban is followed by Forget;
// an error means retry) any earlier cache is left as it was. Unknown IPs and
// IPs with an empty window cache nothing.
func (t *Tracker) Done(ip netip.Addr, benign bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	el, ok := t.ips[ip]
	if !ok {
		return
	}
	st := el.Value.(*ipState)
	st.inFlight = false
	if benign && len(st.events) > 0 {
		st.benign = true
		st.benignBase = st.count()
		st.benignUntil = st.newest().Add(t.cfg.BenignTTL)
	}
	t.dropIfIdle(el)
}

// Forget discards everything about ip, typically after banning it.
func (t *Tracker) Forget(ip netip.Addr) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if el, ok := t.ips[ip]; ok {
		t.remove(el)
	}
}

// Prune drops events at least Window older than now and expired benign
// caches, then forgets every IP left with no events, no decision in flight
// and no live cache.
func (t *Tracker) Prune(now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for el := t.lru.Front(); el != nil; {
		next := el.Next()
		st := el.Value.(*ipState)
		st.expire(now, t.cfg.Window)
		if st.benign && !now.Before(st.benignUntil) {
			st.benign = false
		}
		t.dropIfIdle(el)
		el = next
	}
}

// Len is the number of IPs currently tracked.
func (t *Tracker) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.ips)
}

func (t *Tracker) evictOldest() {
	if el := t.lru.Back(); el != nil {
		t.remove(el)
	}
}

func (t *Tracker) remove(el *list.Element) {
	delete(t.ips, el.Value.(*ipState).ip)
	t.lru.Remove(el)
}

// dropIfIdle forgets the IP when nothing about it is worth remembering.
func (t *Tracker) dropIfIdle(el *list.Element) {
	if st := el.Value.(*ipState); len(st.events) == 0 && !st.inFlight && !st.benign {
		t.remove(el)
	}
}

// newest is the time of the latest event. The window must not be empty.
func (s *ipState) newest() time.Time { return s.events[len(s.events)-1].Time }

// insert places ev in time order, after any events with an equal time.
func (s *ipState) insert(ev event.Event) {
	i := len(s.events)
	for i > 0 && s.events[i-1].Time.After(ev.Time) {
		i--
	}
	s.events = slices.Insert(s.events, i, ev)
}

// expire drops events that are Window or more older than ref.
func (s *ipState) expire(ref time.Time, window time.Duration) {
	keep := slices.IndexFunc(s.events, func(e event.Event) bool { return ref.Sub(e.Time) < window })
	if keep < 0 {
		keep = len(s.events)
	}
	if keep == 0 {
		return
	}
	s.events = slices.Delete(s.events, 0, keep)
	if len(s.events) == 0 {
		s.events = nil // let a quiet IP's buffer go
	}
}

// capTo drops the oldest events beyond limit.
func (s *ipState) capTo(limit int) {
	if extra := len(s.events) - limit; extra > 0 {
		s.events = slices.Delete(s.events, 0, extra)
	}
}

// count tallies the stored events by the trigger rules.
func (s *ipState) count() counts {
	var c counts
	for i := range s.events {
		e := &s.events[i]
		switch e.Source {
		case sourceSSHD:
			switch e.Kind {
			case event.KindAuthFail, event.KindInvalidUser, event.KindPreauthClose:
				c.sshdRelevant++
			}
		case sourceNginx:
			c.nginxTotal++
			if e.Status >= 400 && e.Status <= 499 {
				c.nginxRelevant++
			}
		}
	}
	return c
}

// latest copies the newest n events.
func (s *ipState) latest(n int) []event.Event {
	return slices.Clone(s.events[max(0, len(s.events)-n):])
}
