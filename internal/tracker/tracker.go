// Package tracker keeps a sliding window of events per source IP and decides
// when an IP has been active enough to be worth asking Jev about. All
// thresholds are constants: the only judgment is the model's.
package tracker

import (
	"container/list"
	"net/netip"
	"slices"
	"strings"
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
	MaxEvents int           // events per Batch
	PerIPCap  int           // events kept per IP and source
	MaxIPs    int           // tracked IPs; least recently active is evicted

	// MaxTotalEvents bounds the events held across all IPs; least recently
	// active IPs are evicted to stay within it.
	MaxTotalEvents int
}

// DefaultConfig returns the production configuration.
func DefaultConfig() Config {
	return Config{
		Window:    10 * time.Minute,
		BenignTTL: time.Hour,
		MaxEvents: 50,
		PerIPCap:  400,
		MaxIPs:    100000,

		MaxTotalEvents: 200000,
	}
}

// Batch is what to ask Jev about: at most MaxEvents events of one IP, in
// ascending time order. The newest trigger-relevant events (sshd failures,
// nginx 4xx) of every source come first; the newest other events fill the
// remaining room, so ordinary traffic cannot crowd out the evidence. Events is
// a private copy.
type Batch struct {
	IP     netip.Addr
	Events []event.Event
}

// Tracker is safe for concurrent use.
type Tracker struct {
	cfg Config

	mu    sync.Mutex
	ips   map[netip.Addr]*list.Element // element value is *ipState
	lru   *list.List                   // front = most recently active
	total int                          // events held across all IPs
}

// ipState is everything remembered about one IP.
type ipState struct {
	ip netip.Addr
	// bufs holds one buffer per source, so that heavy traffic from one
	// source cannot push another's events out. Every event is less than
	// Window older than the newest event of any buffer.
	bufs     []buffer
	inFlight bool // a Batch was handed out and neither Done nor Forget has followed

	benign      bool      // a benign verdict is cached
	benignBase  counts    // the window's tallies when it was cached
	benignUntil time.Time // last event time at caching + BenignTTL
}

// buffer is one source's events for an IP, sorted ascending by Time and at
// most PerIPCap long.
type buffer struct {
	source string
	events []event.Event
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
	if cfg.MaxTotalEvents <= 0 {
		cfg.MaxTotalEvents = def.MaxTotalEvents
	}
	return &Tracker{cfg: cfg, ips: make(map[netip.Addr]*list.Element), lru: list.New()}
}

// Add records ev and reports whether its IP now deserves a decision. The
// current moment is ev.Time (or, for an out-of-order event, the newest time
// seen), and only events less than Window old count. auth_success events are
// neither stored nor counted. What is stored is a compact copy of ev (see
// compact), and when the events held across all IPs exceed MaxTotalEvents the
// least recently active IPs are forgotten.
//
// A true result marks the IP in flight: further events are stored but do not
// trigger until Done or Forget.
func (t *Tracker) Add(ev event.Event) (Batch, bool) {
	if ev.Kind == event.KindAuthSuccess || !ev.IP.IsValid() {
		return Batch{}, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	el, ok := t.ips[ev.IP]
	if ok {
		t.lru.MoveToFront(el)
	} else {
		for len(t.ips) >= t.cfg.MaxIPs {
			t.evictOldest()
		}
		el = t.lru.PushFront(&ipState{ip: ev.IP})
		t.ips[ev.IP] = el
	}
	st := el.Value.(*ipState)

	before := st.size()
	st.insert(compact(ev), t.cfg.PerIPCap)
	st.expire(st.newest(), t.cfg.Window)
	t.total += st.size() - before
	t.enforceBudget(el)

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
	return Batch{IP: ev.IP, Events: st.batch(t.cfg.MaxEvents)}, true
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
	if benign && st.size() > 0 {
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
		before := st.size()
		st.expire(now, t.cfg.Window)
		t.total += st.size() - before
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

// enforceBudget forgets least recently active IPs until the events held fit
// in MaxTotalEvents. cur, the IP just added to and the most recently active,
// is never evicted; if it alone is over budget its oldest events go instead.
func (t *Tracker) enforceBudget(cur *list.Element) {
	for t.total > t.cfg.MaxTotalEvents {
		back := t.lru.Back()
		if back == cur {
			st := cur.Value.(*ipState)
			excess := t.total - t.cfg.MaxTotalEvents
			st.dropOldest(excess)
			t.total -= excess
			return
		}
		t.remove(back)
	}
}

func (t *Tracker) evictOldest() {
	if el := t.lru.Back(); el != nil {
		t.remove(el)
	}
}

func (t *Tracker) remove(el *list.Element) {
	st := el.Value.(*ipState)
	t.total -= st.size()
	delete(t.ips, st.ip)
	t.lru.Remove(el)
}

// dropIfIdle forgets the IP when nothing about it is worth remembering.
func (t *Tracker) dropIfIdle(el *list.Element) {
	if st := el.Value.(*ipState); st.size() == 0 && !st.inFlight && !st.benign {
		t.remove(el)
	}
}

// size is the number of events held.
func (s *ipState) size() int {
	n := 0
	for i := range s.bufs {
		n += len(s.bufs[i].events)
	}
	return n
}

// all returns a fresh slice of every event held, oldest first. Events with
// equal times keep the order of their buffers.
func (s *ipState) all() []event.Event {
	out := make([]event.Event, 0, s.size())
	for i := range s.bufs {
		out = append(out, s.bufs[i].events...)
	}
	slices.SortStableFunc(out, func(a, b event.Event) int { return a.Time.Compare(b.Time) })
	return out
}

// compact returns ev with every string field cut to event.MaxField runes and
// copied into its own memory. Extractors hand out substrings of the log line,
// which may be 16 KiB long; storing those would keep every line alive.
func compact(ev event.Event) event.Event {
	switch ev.Source {
	case sourceSSHD:
		ev.Source = sourceSSHD
	case sourceNginx:
		ev.Source = sourceNginx
	default:
		ev.Source = cut(ev.Source)
	}
	ev.User = cut(ev.User)
	ev.Method = cut(ev.Method)
	ev.Path = cut(ev.Path)
	ev.UserAgent = cut(ev.UserAgent)
	return ev
}

// cut returns a private copy of the first event.MaxField runes of s.
func cut(s string) string {
	n := 0
	for i := range s {
		if n == event.MaxField {
			s = s[:i]
			break
		}
		n++
	}
	return strings.Clone(s)
}

// newest is the time of the latest event of any source. The window must not
// be empty.
func (s *ipState) newest() time.Time {
	var t time.Time
	for i := range s.bufs {
		if evs := s.bufs[i].events; len(evs) > 0 {
			if last := evs[len(evs)-1].Time; t.IsZero() || last.After(t) {
				t = last
			}
		}
	}
	return t
}

// insert places ev in its source's buffer in time order, after any events
// with an equal time, then drops that buffer's oldest events beyond limit.
func (s *ipState) insert(ev event.Event, limit int) {
	i := slices.IndexFunc(s.bufs, func(b buffer) bool { return b.source == ev.Source })
	if i < 0 {
		s.bufs = append(s.bufs, buffer{source: ev.Source})
		i = len(s.bufs) - 1
	}
	b := &s.bufs[i]
	j := len(b.events)
	for j > 0 && b.events[j-1].Time.After(ev.Time) {
		j--
	}
	b.events = slices.Insert(b.events, j, ev)
	if extra := len(b.events) - limit; extra > 0 {
		b.events = slices.Delete(b.events, 0, extra)
	}
}

// expire drops events that are Window or more older than ref, and buffers
// left empty.
func (s *ipState) expire(ref time.Time, window time.Duration) {
	for i := range s.bufs {
		b := &s.bufs[i]
		keep := slices.IndexFunc(b.events, func(e event.Event) bool { return ref.Sub(e.Time) < window })
		if keep < 0 {
			keep = len(b.events)
		}
		b.events = slices.Delete(b.events, 0, keep)
	}
	s.bufs = slices.DeleteFunc(s.bufs, func(b buffer) bool { return len(b.events) == 0 })
	if len(s.bufs) == 0 {
		s.bufs = nil // let a quiet IP's buffers go
	}
}

// dropOldest removes the n oldest events across all sources.
func (s *ipState) dropOldest(n int) {
	for ; n > 0; n-- {
		oldest := -1
		for i := range s.bufs {
			if len(s.bufs[i].events) == 0 {
				continue
			}
			if oldest < 0 || s.bufs[i].events[0].Time.Before(s.bufs[oldest].events[0].Time) {
				oldest = i
			}
		}
		if oldest < 0 {
			return
		}
		s.bufs[oldest].events = slices.Delete(s.bufs[oldest].events, 0, 1)
	}
	s.bufs = slices.DeleteFunc(s.bufs, func(b buffer) bool { return len(b.events) == 0 })
}

// relevant reports whether e counts towards the sshd or the nginx 4xx
// trigger.
func relevant(e *event.Event) bool {
	switch e.Source {
	case sourceSSHD:
		switch e.Kind {
		case event.KindAuthFail, event.KindInvalidUser, event.KindPreauthClose:
			return true
		}
	case sourceNginx:
		return e.Status >= 400 && e.Status <= 499
	}
	return false
}

// count tallies the stored events by the trigger rules.
func (s *ipState) count() counts {
	var c counts
	for i := range s.bufs {
		for j := range s.bufs[i].events {
			e := &s.bufs[i].events[j]
			switch e.Source {
			case sourceSSHD:
				if relevant(e) {
					c.sshdRelevant++
				}
			case sourceNginx:
				c.nginxTotal++
				if relevant(e) {
					c.nginxRelevant++
				}
			}
		}
	}
	return c
}

// batch picks at most n events: the newest relevant ones first, then the
// newest of the rest, returned oldest first.
func (s *ipState) batch(n int) []event.Event {
	evs := s.all()
	if len(evs) <= n {
		return evs
	}
	keep := make([]bool, len(evs))
	k := 0
	for i := len(evs) - 1; i >= 0 && k < n; i-- {
		if relevant(&evs[i]) {
			keep[i] = true
			k++
		}
	}
	for i := len(evs) - 1; i >= 0 && k < n; i-- {
		if !keep[i] {
			keep[i] = true
			k++
		}
	}
	out := make([]event.Event, 0, k)
	for i := range evs {
		if keep[i] {
			out = append(out, evs[i])
		}
	}
	return out
}
