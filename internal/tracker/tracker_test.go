package tracker

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"ostrakon/internal/event"
)

var (
	t0   = time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	ipA  = netip.MustParseAddr("203.0.113.1")
	ipB  = netip.MustParseAddr("203.0.113.2")
	ipC  = netip.MustParseAddr("203.0.113.3")
	ipV6 = netip.MustParseAddr("2001:db8::1")
)

// sshFail is a relevant sshd event for ip at t0+off.
func sshFail(ip netip.Addr, off time.Duration) event.Event {
	return event.Event{Time: t0.Add(off), Source: "sshd", IP: ip, Kind: event.KindAuthFail, User: "root"}
}

// web is an nginx-access request for ip at t0+off with the given status.
func web(ip netip.Addr, off time.Duration, status int) event.Event {
	return event.Event{Time: t0.Add(off), Source: "nginx-access", IP: ip, Kind: event.KindHTTPRequest, Method: "GET", Path: "/", Status: status}
}

func sec(n int) time.Duration { return time.Duration(n) * time.Second }

// mustNotTrigger adds ev and fails if it triggered.
func mustNotTrigger(t *testing.T, tr *Tracker, ev event.Event) {
	t.Helper()
	if b, ok := tr.Add(ev); ok {
		t.Fatalf("Add(%v %v at %v) triggered unexpectedly with %d events", ev.Source, ev.Kind, ev.Time.Sub(t0), len(b.Events))
	}
}

// mustTrigger adds ev and returns the batch, failing if it did not trigger.
func mustTrigger(t *testing.T, tr *Tracker, ev event.Event) Batch {
	t.Helper()
	b, ok := tr.Add(ev)
	if !ok {
		t.Fatalf("Add(%v %v at %v) did not trigger", ev.Source, ev.Kind, ev.Time.Sub(t0))
	}
	return b
}

func TestDefaultConfig(t *testing.T) {
	want := Config{Window: 10 * time.Minute, BenignTTL: time.Hour, MaxEvents: 50, PerIPCap: 400, MaxIPs: 100000}
	if got := DefaultConfig(); got != want {
		t.Fatalf("DefaultConfig() = %+v, want %+v", got, want)
	}
}

func TestSSHDTriggerAtThree(t *testing.T) {
	tr := New(DefaultConfig())
	mustNotTrigger(t, tr, sshFail(ipA, 0))
	mustNotTrigger(t, tr, sshFail(ipA, sec(1)))
	b := mustTrigger(t, tr, sshFail(ipA, sec(2)))
	if b.IP != ipA {
		t.Errorf("Batch.IP = %v, want %v", b.IP, ipA)
	}
	if len(b.Events) != 3 {
		t.Fatalf("len(Events) = %d, want 3", len(b.Events))
	}
	for i := 1; i < len(b.Events); i++ {
		if b.Events[i].Time.Before(b.Events[i-1].Time) {
			t.Errorf("Events not in ascending time order: %v", b.Events)
		}
	}
}

func TestSSHDKindsAllRelevant(t *testing.T) {
	tr := New(DefaultConfig())
	kinds := []event.Kind{event.KindAuthFail, event.KindInvalidUser, event.KindPreauthClose}
	for i, k := range kinds {
		ev := sshFail(ipA, sec(i))
		ev.Kind = k
		if i < 2 {
			mustNotTrigger(t, tr, ev)
		} else {
			mustTrigger(t, tr, ev)
		}
	}
}

func TestSSHDWindowExpiry(t *testing.T) {
	tr := New(DefaultConfig())
	mustNotTrigger(t, tr, sshFail(ipA, 0))
	mustNotTrigger(t, tr, sshFail(ipA, time.Minute))
	mustNotTrigger(t, tr, sshFail(ipA, 11*time.Minute))
}

func TestWindowBoundaryIsExclusive(t *testing.T) {
	cfg := DefaultConfig()
	t.Run("exactly Window old is out", func(t *testing.T) {
		tr := New(cfg)
		mustNotTrigger(t, tr, sshFail(ipA, 0))
		mustNotTrigger(t, tr, sshFail(ipA, sec(1)))
		mustNotTrigger(t, tr, sshFail(ipA, cfg.Window))
	})
	t.Run("just under Window old is in", func(t *testing.T) {
		tr := New(cfg)
		mustNotTrigger(t, tr, sshFail(ipA, 0))
		mustNotTrigger(t, tr, sshFail(ipA, sec(1)))
		mustTrigger(t, tr, sshFail(ipA, cfg.Window-time.Nanosecond))
	})
}

func TestAuthSuccessIgnored(t *testing.T) {
	tr := New(DefaultConfig())
	for i := 0; i < 3; i++ {
		ev := sshFail(ipA, sec(i))
		ev.Kind = event.KindAuthSuccess
		mustNotTrigger(t, tr, ev)
	}
	if n := tr.Len(); n != 0 {
		t.Fatalf("Len() = %d, want 0", n)
	}
}

func TestAuthSuccessNotCounted(t *testing.T) {
	tr := New(DefaultConfig())
	mustNotTrigger(t, tr, sshFail(ipA, 0))
	mustNotTrigger(t, tr, sshFail(ipA, sec(1)))
	ok := sshFail(ipA, sec(2))
	ok.Kind = event.KindAuthSuccess
	mustNotTrigger(t, tr, ok)
	// The success was not stored, so the next failure is only the third relevant event.
	b := mustTrigger(t, tr, sshFail(ipA, sec(3)))
	if len(b.Events) != 3 {
		t.Fatalf("len(Events) = %d, want 3 (auth_success must not be stored)", len(b.Events))
	}
}

func TestNginx4xxTrigger(t *testing.T) {
	tr := New(DefaultConfig())
	for i := 0; i < 100; i++ {
		mustNotTrigger(t, tr, web(ipA, sec(i), 200))
	}
	for i := 0; i < 9; i++ {
		mustNotTrigger(t, tr, web(ipA, sec(100+i), 404))
	}
	b := mustTrigger(t, tr, web(ipA, sec(109), 404))
	if len(b.Events) != 50 {
		t.Errorf("len(Events) = %d, want 50 (MaxEvents)", len(b.Events))
	}
}

func TestNginxStatusRelevance(t *testing.T) {
	// 3xx and 5xx are not relevant: ten of them must not trigger.
	for _, status := range []int{399, 500, 503} {
		tr := New(DefaultConfig())
		for i := 0; i < 10; i++ {
			mustNotTrigger(t, tr, web(ipA, sec(i), status))
		}
	}
	// 400 and 499 are the inclusive bounds.
	for _, status := range []int{400, 499} {
		tr := New(DefaultConfig())
		for i := 0; i < 9; i++ {
			mustNotTrigger(t, tr, web(ipA, sec(i), status))
		}
		mustTrigger(t, tr, web(ipA, sec(9), status))
	}
}

func TestNginxVolumeTrigger(t *testing.T) {
	tr := New(DefaultConfig())
	for i := 1; i <= 299; i++ {
		mustNotTrigger(t, tr, web(ipA, sec(i), 200))
	}
	last := web(ipA, sec(300), 200)
	b := mustTrigger(t, tr, last)
	if len(b.Events) != 50 {
		t.Fatalf("len(Events) = %d, want 50", len(b.Events))
	}
	if got := b.Events[len(b.Events)-1]; !got.Time.Equal(last.Time) {
		t.Errorf("last batch event at %v, want the 300th at %v", got.Time, last.Time)
	}
	if !b.Events[0].Time.Equal(t0.Add(sec(251))) {
		t.Errorf("first batch event at %v, want the 251st", b.Events[0].Time.Sub(t0))
	}
}

func TestBatchIncludesAllSources(t *testing.T) {
	tr := New(DefaultConfig())
	mustNotTrigger(t, tr, web(ipA, 0, 200))
	mustNotTrigger(t, tr, sshFail(ipA, sec(1)))
	mustNotTrigger(t, tr, sshFail(ipA, sec(2)))
	b := mustTrigger(t, tr, sshFail(ipA, sec(3)))
	if len(b.Events) != 4 {
		t.Fatalf("len(Events) = %d, want 4 (the nginx 200 rides along)", len(b.Events))
	}
	if b.Events[0].Source != "nginx-access" {
		t.Errorf("first event source = %q, want nginx-access", b.Events[0].Source)
	}
}

func TestSourcesCountedIndependently(t *testing.T) {
	// 2 sshd + 9 nginx 4xx is below every individual threshold.
	tr := New(DefaultConfig())
	mustNotTrigger(t, tr, sshFail(ipA, 0))
	mustNotTrigger(t, tr, sshFail(ipA, sec(1)))
	for i := 0; i < 9; i++ {
		mustNotTrigger(t, tr, web(ipA, sec(2+i), 404))
	}
}

func TestInFlight(t *testing.T) {
	tr := New(DefaultConfig())
	for i := 0; i < 2; i++ {
		mustNotTrigger(t, tr, sshFail(ipA, sec(i)))
	}
	mustTrigger(t, tr, sshFail(ipA, sec(2)))
	mustNotTrigger(t, tr, sshFail(ipA, sec(3)))
	tr.Done(ipA, false)
	b := mustTrigger(t, tr, sshFail(ipA, sec(4)))
	if len(b.Events) != 5 {
		t.Errorf("len(Events) = %d, want 5 (events stored while in flight are kept)", len(b.Events))
	}
}

func TestBenignCache(t *testing.T) {
	t.Run("ssh trigger cached: needs a doubled ssh count", func(t *testing.T) {
		tr := New(DefaultConfig())
		mustNotTrigger(t, tr, sshFail(ipA, 0))
		mustNotTrigger(t, tr, sshFail(ipA, sec(1)))
		mustTrigger(t, tr, sshFail(ipA, sec(2)))
		tr.Done(ipA, true)
		mustNotTrigger(t, tr, sshFail(ipA, sec(3)))
		mustNotTrigger(t, tr, sshFail(ipA, sec(4)))
		b := mustTrigger(t, tr, sshFail(ipA, sec(5)))
		if len(b.Events) != 6 {
			t.Errorf("len(Events) = %d, want 6", len(b.Events))
		}
	})

	t.Run("expires BenignTTL after the last event", func(t *testing.T) {
		tr := New(DefaultConfig())
		mustNotTrigger(t, tr, sshFail(ipA, 0))
		mustNotTrigger(t, tr, sshFail(ipA, sec(1)))
		mustTrigger(t, tr, sshFail(ipA, sec(2)))
		tr.Done(ipA, true)
		base := 61 * time.Minute
		mustNotTrigger(t, tr, sshFail(ipA, base))
		mustNotTrigger(t, tr, sshFail(ipA, base+sec(1)))
		b := mustTrigger(t, tr, sshFail(ipA, base+sec(2)))
		if len(b.Events) != 3 {
			t.Errorf("len(Events) = %d, want 3 (old events left the window)", len(b.Events))
		}
	})

	t.Run("still active just before expiry", func(t *testing.T) {
		tr := New(DefaultConfig())
		mustNotTrigger(t, tr, sshFail(ipA, 0))
		mustNotTrigger(t, tr, sshFail(ipA, sec(1)))
		mustTrigger(t, tr, sshFail(ipA, sec(2)))
		tr.Done(ipA, true)
		// Cache runs until t0+2s+1h; these land just inside it.
		base := time.Hour
		mustNotTrigger(t, tr, sshFail(ipA, base))
		mustNotTrigger(t, tr, sshFail(ipA, base+sec(1)))
		mustNotTrigger(t, tr, sshFail(ipA, base+sec(1)+time.Millisecond))
	})

	t.Run("a cached IP below every trigger condition stays quiet", func(t *testing.T) {
		tr := New(DefaultConfig())
		mustNotTrigger(t, tr, sshFail(ipA, 0))
		mustNotTrigger(t, tr, sshFail(ipA, sec(1)))
		tr.Done(ipA, true) // cache N=2 without ever triggering
		// Neither sshd (2) nor nginx 4xx (2) crosses its threshold.
		mustNotTrigger(t, tr, web(ipA, sec(2), 404))
		mustNotTrigger(t, tr, web(ipA, sec(3), 404))
	})

	t.Run("a later Done replaces the cached counts", func(t *testing.T) {
		tr := New(DefaultConfig())
		for i := 0; i < 2; i++ {
			mustNotTrigger(t, tr, sshFail(ipA, sec(i)))
		}
		mustTrigger(t, tr, sshFail(ipA, sec(2)))
		tr.Done(ipA, true) // N=3
		for i := 3; i < 5; i++ {
			mustNotTrigger(t, tr, sshFail(ipA, sec(i)))
		}
		mustTrigger(t, tr, sshFail(ipA, sec(5)))
		tr.Done(ipA, true) // N=6
		for i := 6; i < 11; i++ {
			mustNotTrigger(t, tr, sshFail(ipA, sec(i)))
		}
		mustTrigger(t, tr, sshFail(ipA, sec(11))) // 12 = 2*6
	})

	t.Run("volume trigger cached: more of the same stays quiet", func(t *testing.T) {
		tr := New(DefaultConfig())
		for i := 1; i < 300; i++ {
			mustNotTrigger(t, tr, web(ipA, sec(i), 200))
		}
		mustTrigger(t, tr, web(ipA, sec(300), 200))
		tr.Done(ipA, true) // T=300, S=0, F=0
		for i := 301; i <= 400; i++ {
			mustNotTrigger(t, tr, web(ipA, sec(i), 200))
		}
	})

	t.Run("volume trigger cached: ssh failures still trigger", func(t *testing.T) {
		tr := New(DefaultConfig())
		for i := 1; i < 300; i++ {
			mustNotTrigger(t, tr, web(ipA, sec(i), 200))
		}
		mustTrigger(t, tr, web(ipA, sec(300), 200))
		tr.Done(ipA, true)
		mustNotTrigger(t, tr, sshFail(ipA, sec(301)))
		mustNotTrigger(t, tr, sshFail(ipA, sec(302)))
		b := mustTrigger(t, tr, sshFail(ipA, sec(303)))
		if len(b.Events) != 50 || b.Events[len(b.Events)-1].Source != "sshd" {
			t.Errorf("batch has %d events ending in %q, want 50 ending in sshd", len(b.Events), b.Events[len(b.Events)-1].Source)
		}
	})

	t.Run("volume trigger cached: 4xx burst still triggers", func(t *testing.T) {
		tr := New(DefaultConfig())
		for i := 1; i < 300; i++ {
			mustNotTrigger(t, tr, web(ipA, sec(i), 200))
		}
		mustTrigger(t, tr, web(ipA, sec(300), 200))
		tr.Done(ipA, true)
		for i := 301; i < 310; i++ {
			mustNotTrigger(t, tr, web(ipA, sec(i), 404))
		}
		mustTrigger(t, tr, web(ipA, sec(310), 404))
	})

	t.Run("4xx trigger cached: needs a doubled 4xx count", func(t *testing.T) {
		tr := New(DefaultConfig())
		for i := 0; i < 9; i++ {
			mustNotTrigger(t, tr, web(ipA, sec(i), 404))
		}
		mustTrigger(t, tr, web(ipA, sec(9), 404))
		tr.Done(ipA, true) // F=10
		for i := 10; i < 19; i++ {
			mustNotTrigger(t, tr, web(ipA, sec(i), 404)) // F up to 19: not yet 2F
		}
		mustTrigger(t, tr, web(ipA, sec(19), 404)) // F=20
	})

	t.Run("Done false keeps the cache", func(t *testing.T) {
		tr := New(DefaultConfig())
		for i := 0; i < 2; i++ {
			mustNotTrigger(t, tr, sshFail(ipA, sec(i)))
		}
		mustTrigger(t, tr, sshFail(ipA, sec(2)))
		tr.Done(ipA, true) // N=3
		for i := 3; i < 5; i++ {
			mustNotTrigger(t, tr, sshFail(ipA, sec(i)))
		}
		mustTrigger(t, tr, sshFail(ipA, sec(5)))
		tr.Done(ipA, false) // e.g. Jev unavailable: retry on the next event, cache untouched
		mustTrigger(t, tr, sshFail(ipA, sec(6)))
	})
}

func TestForget(t *testing.T) {
	tr := New(DefaultConfig())
	for i := 0; i < 2; i++ {
		mustNotTrigger(t, tr, sshFail(ipA, sec(i)))
	}
	mustTrigger(t, tr, sshFail(ipA, sec(2)))
	if n := tr.Len(); n != 1 {
		t.Fatalf("Len() = %d, want 1", n)
	}
	tr.Forget(ipA)
	if n := tr.Len(); n != 0 {
		t.Fatalf("Len() after Forget = %d, want 0", n)
	}
	mustNotTrigger(t, tr, sshFail(ipA, sec(3)))
	mustNotTrigger(t, tr, sshFail(ipA, sec(4)))
}

func TestForgetClearsBenignCache(t *testing.T) {
	tr := New(DefaultConfig())
	for i := 0; i < 2; i++ {
		mustNotTrigger(t, tr, sshFail(ipA, sec(i)))
	}
	mustTrigger(t, tr, sshFail(ipA, sec(2)))
	tr.Done(ipA, true)
	tr.Forget(ipA)
	mustNotTrigger(t, tr, sshFail(ipA, sec(3)))
	mustNotTrigger(t, tr, sshFail(ipA, sec(4)))
	mustTrigger(t, tr, sshFail(ipA, sec(5))) // normal threshold again, not 2N
}

func TestUnknownIPNoOps(t *testing.T) {
	tr := New(DefaultConfig())
	tr.Done(ipA, false)
	tr.Done(ipA, true)
	tr.Forget(ipA)
	if n := tr.Len(); n != 0 {
		t.Fatalf("Len() = %d, want 0", n)
	}
	// And they must not have left state behind that changes later behavior.
	mustNotTrigger(t, tr, sshFail(ipA, 0))
	mustNotTrigger(t, tr, sshFail(ipA, sec(1)))
	mustTrigger(t, tr, sshFail(ipA, sec(2)))
}

func TestPrune(t *testing.T) {
	tr := New(DefaultConfig())
	mustNotTrigger(t, tr, sshFail(ipA, 0))
	tr.Prune(t0.Add(11 * time.Minute))
	if n := tr.Len(); n != 0 {
		t.Fatalf("Len() = %d, want 0", n)
	}
}

func TestPruneKeepsRecentEvents(t *testing.T) {
	tr := New(DefaultConfig())
	mustNotTrigger(t, tr, sshFail(ipA, 0))
	mustNotTrigger(t, tr, sshFail(ipA, 8*time.Minute))
	tr.Prune(t0.Add(11 * time.Minute)) // drops the first, keeps the second
	if n := tr.Len(); n != 1 {
		t.Fatalf("Len() = %d, want 1", n)
	}
	mustNotTrigger(t, tr, sshFail(ipA, 11*time.Minute))
	// 8m, 11m and this one are three relevant events inside the window.
	mustTrigger(t, tr, sshFail(ipA, 11*time.Minute+sec(1)))
}

func TestPruneKeepsInFlight(t *testing.T) {
	tr := New(DefaultConfig())
	for i := 0; i < 2; i++ {
		mustNotTrigger(t, tr, sshFail(ipA, sec(i)))
	}
	mustTrigger(t, tr, sshFail(ipA, sec(2)))
	tr.Prune(t0.Add(time.Hour))
	if n := tr.Len(); n != 1 {
		t.Fatalf("Len() = %d, want 1 (in-flight IP must survive Prune)", n)
	}
	// Still in flight after Prune: new events are stored but do not trigger.
	later := time.Hour
	for i := 0; i < 3; i++ {
		mustNotTrigger(t, tr, sshFail(ipA, later+sec(i)))
	}
	tr.Done(ipA, false)
	mustTrigger(t, tr, sshFail(ipA, later+sec(3)))
}

func TestPruneBenignCache(t *testing.T) {
	tr := New(DefaultConfig())
	for i := 0; i < 2; i++ {
		mustNotTrigger(t, tr, sshFail(ipA, sec(i)))
	}
	mustTrigger(t, tr, sshFail(ipA, sec(2)))
	tr.Done(ipA, true) // cached until t0+2s+1h

	tr.Prune(t0.Add(30 * time.Minute))
	if n := tr.Len(); n != 1 {
		t.Fatalf("Len() = %d, want 1 (benign cache still live)", n)
	}
	tr.Prune(t0.Add(time.Hour + sec(2)))
	if n := tr.Len(); n != 0 {
		t.Fatalf("Len() = %d, want 0 (cache expired, no events)", n)
	}
}

func TestDoneBenignAfterPruneEmptiedWindow(t *testing.T) {
	tr := New(DefaultConfig())
	for i := 0; i < 2; i++ {
		mustNotTrigger(t, tr, sshFail(ipA, sec(i)))
	}
	mustTrigger(t, tr, sshFail(ipA, sec(2)))
	tr.Prune(t0.Add(time.Hour)) // window now empty, IP kept only because it is in flight
	tr.Done(ipA, true)          // no window: nothing to cache
	if n := tr.Len(); n != 0 {
		t.Fatalf("Len() = %d, want 0", n)
	}
	for i := 0; i < 2; i++ {
		mustNotTrigger(t, tr, sshFail(ipA, time.Hour+sec(i)))
	}
	mustTrigger(t, tr, sshFail(ipA, time.Hour+sec(2))) // normal threshold, no 2N
}

func TestMaxIPs(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxIPs = 2
	tr := New(cfg)
	mustNotTrigger(t, tr, sshFail(ipA, 0))
	mustNotTrigger(t, tr, sshFail(ipB, sec(1)))
	mustNotTrigger(t, tr, sshFail(ipC, sec(2)))
	if n := tr.Len(); n != 2 {
		t.Fatalf("Len() = %d, want 2", n)
	}
	// ipA was evicted: two more events start from scratch and do not reach three.
	mustNotTrigger(t, tr, sshFail(ipA, sec(3)))
	mustNotTrigger(t, tr, sshFail(ipA, sec(4)))
	if n := tr.Len(); n != 2 {
		t.Fatalf("Len() = %d, want 2", n)
	}
}

func TestMaxIPsEvictsLeastRecentlyActive(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxIPs = 2
	tr := New(cfg)
	mustNotTrigger(t, tr, sshFail(ipA, 0))
	mustNotTrigger(t, tr, sshFail(ipB, sec(1)))
	mustNotTrigger(t, tr, sshFail(ipA, sec(2))) // A is now more recent than B
	mustNotTrigger(t, tr, sshFail(ipC, sec(3))) // evicts B
	mustTrigger(t, tr, sshFail(ipA, sec(4)))    // A kept all three events
}

func TestPerIPCap(t *testing.T) {
	cfg := DefaultConfig()
	cfg.PerIPCap = 4
	tr := New(cfg)
	for i := 0; i < 2; i++ {
		mustNotTrigger(t, tr, sshFail(ipA, sec(i)))
	}
	mustTrigger(t, tr, sshFail(ipA, sec(2)))
	for i := 3; i < 6; i++ { // in flight: stored, oldest dropped past the cap
		mustNotTrigger(t, tr, sshFail(ipA, sec(i)))
	}
	tr.Done(ipA, false)
	b := mustTrigger(t, tr, sshFail(ipA, sec(6)))
	if len(b.Events) != 4 {
		t.Fatalf("len(Events) = %d, want 4 (PerIPCap)", len(b.Events))
	}
	if !b.Events[0].Time.Equal(t0.Add(sec(3))) || !b.Events[3].Time.Equal(t0.Add(sec(6))) {
		t.Errorf("kept events %v..%v, want the newest four (3s..6s)", b.Events[0].Time.Sub(t0), b.Events[3].Time.Sub(t0))
	}
}

func TestOutOfOrderEventsAreStoredSorted(t *testing.T) {
	tr := New(DefaultConfig())
	mustNotTrigger(t, tr, sshFail(ipA, 5*time.Minute))
	mustNotTrigger(t, tr, sshFail(ipA, time.Minute)) // older than the newest, still in window
	b := mustTrigger(t, tr, sshFail(ipA, 3*time.Minute))
	want := []time.Duration{time.Minute, 3 * time.Minute, 5 * time.Minute}
	if len(b.Events) != len(want) {
		t.Fatalf("len(Events) = %d, want %d", len(b.Events), len(want))
	}
	for i, w := range want {
		if got := b.Events[i].Time.Sub(t0); got != w {
			t.Errorf("Events[%d] at %v, want %v", i, got, w)
		}
	}
}

func TestStaleEventIgnored(t *testing.T) {
	tr := New(DefaultConfig())
	mustNotTrigger(t, tr, sshFail(ipA, 11*time.Minute))
	mustNotTrigger(t, tr, sshFail(ipA, 0)) // 11m behind the newest: outside the window, dropped
	// Had the stale event been stored this would be the third.
	mustNotTrigger(t, tr, sshFail(ipA, 11*time.Minute+sec(1)))
}

func TestBatchEventsAreACopy(t *testing.T) {
	tr := New(DefaultConfig())
	for i := 0; i < 2; i++ {
		mustNotTrigger(t, tr, sshFail(ipA, sec(i)))
	}
	b := mustTrigger(t, tr, sshFail(ipA, sec(2)))
	want := append([]event.Event(nil), b.Events...)

	// A far-later event trims the window (shifting internal storage); others append.
	mustNotTrigger(t, tr, sshFail(ipA, 30*time.Minute))
	mustNotTrigger(t, tr, sshFail(ipA, 30*time.Minute+sec(1)))

	for i := range want {
		if !b.Events[i].Time.Equal(want[i].Time) {
			t.Fatalf("Batch.Events[%d] changed from %v to %v after later Adds", i, want[i].Time.Sub(t0), b.Events[i].Time.Sub(t0))
		}
	}
	// Writing to the batch must not reach the tracker either.
	b.Events[0].User = "tampered"
	tr.Done(ipA, false)
	b2 := mustTrigger(t, tr, sshFail(ipA, 30*time.Minute+sec(2)))
	for _, e := range b2.Events {
		if e.User == "tampered" {
			t.Fatalf("mutation of an earlier Batch leaked into the tracker")
		}
	}
}

func TestIPv6(t *testing.T) {
	tr := New(DefaultConfig())
	mustNotTrigger(t, tr, sshFail(ipV6, 0))
	mustNotTrigger(t, tr, sshFail(ipA, sec(1))) // other IPs have separate windows
	mustNotTrigger(t, tr, sshFail(ipV6, sec(2)))
	b := mustTrigger(t, tr, sshFail(ipV6, sec(3)))
	if b.IP != ipV6 || len(b.Events) != 3 {
		t.Fatalf("batch = %v with %d events, want %v with 3", b.IP, len(b.Events), ipV6)
	}
}

func TestInvalidIPIgnored(t *testing.T) {
	tr := New(DefaultConfig())
	for i := 0; i < 5; i++ {
		mustNotTrigger(t, tr, sshFail(netip.Addr{}, sec(i)))
	}
	if n := tr.Len(); n != 0 {
		t.Fatalf("Len() = %d, want 0", n)
	}
}

func TestConcurrentUse(t *testing.T) {
	tr := New(DefaultConfig())
	const workers = 8
	var wg sync.WaitGroup
	stop := make(chan struct{})
	pruneDone := make(chan struct{})
	go func() { // the daemon's ticker
		defer close(pruneDone)
		for {
			select {
			case <-stop:
				return
			default:
				tr.Prune(t0.Add(time.Hour))
				tr.Len()
			}
		}
	}()
	for w := 0; w < workers; w++ {
		ip := netip.AddrFrom4([4]byte{198, 51, 100, byte(w)})
		wg.Add(1)
		go func() {
			defer wg.Done()
			for round := 0; round < 50; round++ {
				for i := 0; i < 3; i++ {
					if b, ok := tr.Add(sshFail(ip, time.Duration(round*3+i)*time.Millisecond)); ok {
						if b.IP != ip || len(b.Events) == 0 {
							t.Errorf("bad batch %v with %d events", b.IP, len(b.Events))
						}
						wg.Add(1)
						go func() { // workers finish concurrently with the Add loop
							defer wg.Done()
							tr.Done(ip, round%2 == 0)
						}()
					}
				}
				if round%10 == 9 {
					tr.Forget(ip)
				}
			}
		}()
	}
	wg.Wait()
	close(stop)
	<-pruneDone
}
