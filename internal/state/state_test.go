package state

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)

func addr(s string) netip.Addr     { return netip.MustParseAddr(s) }
func prefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }

func statePath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "state.json")
}

func mustOpen(t *testing.T, path string, now time.Time) *Store {
	t.Helper()
	s, err := Open(path, now)
	if err != nil {
		t.Fatalf("Open(%s): %v", path, err)
	}
	return s
}

func mustAddBan(t *testing.T, s *Store, b Ban) {
	t.Helper()
	if err := s.AddBan(b); err != nil {
		t.Fatalf("AddBan(%v): %v", b.IP, err)
	}
}

func ban(ip string, since time.Time, ttl time.Duration, category string) Ban {
	return Ban{IP: addr(ip), Since: since, Until: since.Add(ttl), Category: category}
}

func TestRoundTrip(t *testing.T) {
	path := statePath(t)
	s := mustOpen(t, path, t0)

	first := ban("203.0.113.7", t0, time.Hour, "ssh")
	mustAddBan(t, s, first)

	s = mustOpen(t, path, t0.Add(time.Minute))
	got := s.ActiveBans(t0.Add(time.Minute))
	if len(got) != 1 {
		t.Fatalf("ActiveBans = %v, want 1 ban", got)
	}
	if got[0].IP != first.IP || got[0].Category != "ssh" ||
		!got[0].Since.Equal(first.Since) || !got[0].Until.Equal(first.Until) {
		t.Fatalf("ban = %+v, want %+v", got[0], first)
	}
	h := s.History(first.IP)
	if h.Count != 1 || !h.Last.Equal(first.Since) {
		t.Fatalf("History = %+v, want count 1 last %v", h, first.Since)
	}

	later := ban("203.0.113.7", t0.Add(2*time.Minute), 4*time.Hour, "ssh")
	mustAddBan(t, s, later)
	h = s.History(first.IP)
	if h.Count != 2 || !h.Last.Equal(later.Since) {
		t.Fatalf("History = %+v, want count 2 last %v", h, later.Since)
	}

	s = mustOpen(t, path, t0.Add(3*time.Minute))
	h = s.History(first.IP)
	if h.Count != 2 || !h.Last.Equal(later.Since) {
		t.Fatalf("reloaded History = %+v, want count 2 last %v", h, later.Since)
	}
}

func TestFileFormat(t *testing.T) {
	path := statePath(t)
	s := mustOpen(t, path, t0)
	mustAddBan(t, s, ban("203.0.113.7", t0, time.Hour, "web"))
	if err := s.Allow(prefix("198.51.100.0/24")); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Version int                        `json:"version"`
		Bans    map[string]json.RawMessage `json:"bans"`
		History map[string]json.RawMessage `json:"history"`
		Allow   []string                   `json:"allow"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("file is not valid JSON: %v\n%s", err, raw)
	}
	if doc.Version != 1 {
		t.Errorf("version = %d, want 1", doc.Version)
	}
	if _, ok := doc.Bans["203.0.113.7"]; !ok {
		t.Errorf("bans keys = %v, want 203.0.113.7", doc.Bans)
	}
	if _, ok := doc.History["203.0.113.7"]; !ok {
		t.Errorf("history keys = %v, want 203.0.113.7", doc.History)
	}
	if len(doc.Allow) != 1 || doc.Allow[0] != "198.51.100.0/24" {
		t.Errorf("allow = %v, want [198.51.100.0/24]", doc.Allow)
	}
	var b map[string]any
	if err := json.Unmarshal(doc.Bans["203.0.113.7"], &b); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"ip", "since", "until", "category"} {
		if _, ok := b[k]; !ok {
			t.Errorf("ban is missing field %q: %v", k, b)
		}
	}
}

func TestLoadsDocumentedFormat(t *testing.T) {
	// Hand-written in the documented layout, independent of this package's
	// own writer. The allow entries are unmasked, mapped and duplicated.
	const doc = `{
  "version": 1,
  "bans": {
    "203.0.113.7": {"ip": "203.0.113.7", "since": "2026-10-18T11:00:00Z", "until": "2026-10-18T15:00:00Z", "category": "ssh"},
    "2001:db8::5": {"ip": "2001:db8::5", "since": "2026-10-18T11:30:00Z", "until": "2026-10-18T13:00:00Z", "category": "web"}
  },
  "history": {
    "203.0.113.7": {"count": 3, "last": "2026-10-18T11:00:00Z"}
  },
  "allow": ["10.0.0.5/8", "10.0.0.0/8", "::ffff:192.0.2.0/120", "2001:db8:1::/48"]
}`
	path := statePath(t)
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	s := mustOpen(t, path, t0)
	if s.Recovered() != "" {
		t.Fatalf("a valid file was quarantined to %s", s.Recovered())
	}
	got := s.ActiveBans(t0)
	if len(got) != 2 || got[0].IP != addr("2001:db8::5") || got[1].IP != addr("203.0.113.7") || got[1].Category != "ssh" {
		t.Fatalf("ActiveBans = %+v", got)
	}
	if h := s.History(addr("203.0.113.7")); h.Count != 3 || !h.Last.Equal(time.Date(2026, 10, 18, 11, 0, 0, 0, time.UTC)) {
		t.Fatalf("History = %+v, want count 3", h)
	}
	want := []netip.Prefix{prefix("10.0.0.0/8"), prefix("192.0.2.0/24"), prefix("2001:db8:1::/48")}
	al := s.AllowList()
	if len(al) != len(want) {
		t.Fatalf("AllowList = %v, want %v", al, want)
	}
	for i := range want {
		if al[i] != want[i] {
			t.Fatalf("AllowList = %v, want %v", al, want)
		}
	}
}

func TestActiveBansDropsExpired(t *testing.T) {
	path := statePath(t)
	s := mustOpen(t, path, t0)
	// Expiry order (.2, .3, .1) deliberately differs from address order.
	mustAddBan(t, s, ban("192.0.2.1", t0, 3*time.Hour, "c"))
	mustAddBan(t, s, ban("192.0.2.2", t0, time.Hour, "a"))
	mustAddBan(t, s, ban("192.0.2.3", t0, 2*time.Hour, "b"))
	mustAddBan(t, s, ban("192.0.2.9", t0.Add(-2*time.Hour), time.Hour, "expired"))

	ips := func(bans []Ban) string {
		var out []string
		for _, b := range bans {
			out = append(out, b.IP.String())
		}
		return strings.Join(out, " ")
	}
	if got, want := ips(s.ActiveBans(t0)), "192.0.2.2 192.0.2.3 192.0.2.1"; got != want {
		t.Fatalf("ActiveBans at t0 = %q, want %q (ascending Until, expired dropped)", got, want)
	}
	// Until == now is already expired.
	if got, want := ips(s.ActiveBans(t0.Add(time.Hour))), "192.0.2.3 192.0.2.1"; got != want {
		t.Fatalf("ActiveBans at t0+1h = %q, want %q", got, want)
	}
	if got := s.ActiveBans(t0.Add(3 * time.Hour)); len(got) != 0 {
		t.Fatalf("ActiveBans after all expired = %v, want none", got)
	}
}

func TestActiveBansReturnsCopy(t *testing.T) {
	s := mustOpen(t, statePath(t), t0)
	mustAddBan(t, s, ban("192.0.2.1", t0, time.Hour, "a"))
	s.ActiveBans(t0)[0].Category = "mutated"
	if got := s.ActiveBans(t0)[0].Category; got != "a" {
		t.Fatalf("Category = %q, caller mutation leaked into the store", got)
	}
}

func TestOpenDropsExpiredBans(t *testing.T) {
	path := statePath(t)
	s := mustOpen(t, path, t0)
	mustAddBan(t, s, ban("192.0.2.1", t0, time.Hour, "gone"))
	mustAddBan(t, s, ban("192.0.2.2", t0, 2*time.Hour, "kept"))

	// 192.0.2.1 expires exactly at the Open time and must be dropped.
	s = mustOpen(t, path, t0.Add(time.Hour))
	if got := s.ActiveBans(t0.Add(-100 * time.Hour)); len(got) != 1 || got[0].IP != addr("192.0.2.2") {
		t.Fatalf("bans after reopen = %v, want only 192.0.2.2 (expired ban must be discarded at Open)", got)
	}
}

func TestHistoryPruned(t *testing.T) {
	path := statePath(t)
	s := mustOpen(t, path, t0)
	stale, edge, fresh := addr("192.0.2.1"), addr("192.0.2.2"), addr("192.0.2.3")
	mustAddBan(t, s, ban("192.0.2.1", t0.Add(-31*24*time.Hour), 24*time.Hour*60, "x"))
	mustAddBan(t, s, ban("192.0.2.2", t0.Add(-HistoryTTL), 24*time.Hour*60, "x"))
	mustAddBan(t, s, ban("192.0.2.3", t0.Add(-29*24*time.Hour), 24*time.Hour*60, "x"))

	s = mustOpen(t, path, t0)
	if got := s.History(stale).Count; got != 0 {
		t.Errorf("31-day-old history Count = %d, want 0", got)
	}
	if got := s.History(edge).Count; got != 1 {
		t.Errorf("exactly-HistoryTTL-old history Count = %d, want 1 (only older is dropped)", got)
	}
	if got := s.History(fresh).Count; got != 1 {
		t.Errorf("29-day-old history Count = %d, want 1", got)
	}
}

// longBefore is an Open time early enough that Open itself prunes nothing, so
// a reopen shows exactly what is on disk.
var longBefore = t0.Add(-365 * 24 * time.Hour)

func TestPruneDropsStaleAndPersists(t *testing.T) {
	path := statePath(t)
	s := mustOpen(t, path, t0)
	day := 24 * time.Hour
	// Expired ban, history too old: both go.
	mustAddBan(t, s, ban("192.0.2.1", t0.Add(-31*day), time.Hour, "old"))
	// Ban expires exactly now, history is recent: only the ban goes.
	mustAddBan(t, s, ban("192.0.2.2", t0.Add(-time.Hour), time.Hour, "just-expired"))
	// History exactly HistoryTTL old is kept (only older is stale); ban expired.
	mustAddBan(t, s, ban("192.0.2.3", t0.Add(-HistoryTTL), time.Hour, "edge"))
	// Active ban, recent history: untouched.
	mustAddBan(t, s, ban("192.0.2.4", t0, time.Hour, "live"))
	if err := s.Allow(prefix("198.51.100.0/24")); err != nil {
		t.Fatal(err)
	}

	if err := s.Prune(t0); err != nil {
		t.Fatalf("Prune: %v", err)
	}

	check := func(label string, st *Store) {
		t.Helper()
		bans := st.ActiveBans(longBefore) // every ban still held, expired or not
		if len(bans) != 1 || bans[0].IP != addr("192.0.2.4") {
			t.Errorf("%s: bans = %v, want only 192.0.2.4", label, bans)
		}
		for ip, want := range map[string]int{"192.0.2.1": 0, "192.0.2.2": 1, "192.0.2.3": 1, "192.0.2.4": 1} {
			if got := st.History(addr(ip)).Count; got != want {
				t.Errorf("%s: History(%s).Count = %d, want %d", label, ip, got, want)
			}
		}
		if al := st.AllowList(); len(al) != 1 || al[0] != prefix("198.51.100.0/24") {
			t.Errorf("%s: AllowList = %v, Prune must not touch it", label, al)
		}
	}
	check("in memory", s)
	// Opened "in the past", so any pruning seen here was persisted by Prune.
	check("after reopen", mustOpen(t, path, longBefore))
}

func TestPruneAtRuntimeEnforcesHistoryTTL(t *testing.T) {
	// The scenario Prune exists for: History(ip) has no clock, so a daemon
	// that stays up past HistoryTTL needs Prune to stop reporting old counts.
	s := mustOpen(t, statePath(t), t0)
	mustAddBan(t, s, ban("192.0.2.1", t0, time.Hour, "ssh"))
	later := t0.Add(HistoryTTL + time.Minute)
	if got := s.History(addr("192.0.2.1")).Count; got != 1 {
		t.Fatalf("History.Count before Prune = %d, want 1", got)
	}
	if err := s.Prune(later); err != nil {
		t.Fatal(err)
	}
	if got := s.History(addr("192.0.2.1")).Count; got != 0 {
		t.Fatalf("History.Count after Prune = %d, want 0", got)
	}
}

func TestPruneWithNothingStaleDoesNotWrite(t *testing.T) {
	path := statePath(t)
	s := mustOpen(t, path, t0)
	mustAddBan(t, s, ban("192.0.2.1", t0, time.Hour, "ssh"))

	// With the file gone, any save would bring it back.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	// And a blocked temp path would turn any save into an error.
	if err := os.Mkdir(path+".tmp", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := s.Prune(t0); err != nil {
		t.Fatalf("Prune with nothing stale = %v, want nil (no save attempted)", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("Prune with nothing stale rewrote the state file (stat err = %v)", err)
	}
}

func TestPruneSaveFailureRollsBack(t *testing.T) {
	path := statePath(t)
	s := mustOpen(t, path, t0)
	mustAddBan(t, s, ban("192.0.2.1", t0.Add(-31*24*time.Hour), time.Hour, "old"))
	mustAddBan(t, s, ban("192.0.2.2", t0, time.Hour, "live"))
	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path+".tmp", 0o700); err != nil {
		t.Fatal(err)
	}

	if err := s.Prune(t0); err == nil {
		t.Fatal("Prune succeeded although the save failed")
	}
	bans := s.ActiveBans(longBefore)
	if len(bans) != 2 {
		t.Errorf("bans = %v, want both restored after the failed Prune", bans)
	}
	if got := s.History(addr("192.0.2.1")); got.Count != 1 {
		t.Errorf("History(stale) = %+v, want it restored", got)
	}
	if cur, err := os.ReadFile(path); err != nil || string(cur) != string(onDisk) {
		t.Errorf("state file changed after a failed Prune: %q, %v", cur, err)
	}

	// Once saving works again, the same Prune goes through.
	if err := os.Remove(path + ".tmp"); err != nil {
		t.Fatal(err)
	}
	if err := s.Prune(t0); err != nil {
		t.Fatalf("Prune after the fault cleared: %v", err)
	}
	if got := s.History(addr("192.0.2.1")).Count; got != 0 {
		t.Errorf("History(stale).Count = %d after a successful retry, want 0", got)
	}
}

func TestHistoryUnknownIP(t *testing.T) {
	s := mustOpen(t, statePath(t), t0)
	if h := s.History(addr("192.0.2.1")); h.Count != 0 || !h.Last.IsZero() {
		t.Fatalf("History of unknown ip = %+v, want zero value", h)
	}
}

func TestCorruptFile(t *testing.T) {
	path := statePath(t)
	if err := os.WriteFile(path, []byte("{bad"), 0o600); err != nil {
		t.Fatal(err)
	}

	s, err := Open(path, t0)
	if err != nil {
		t.Fatalf("Open on a corrupt file must not fail: %v", err)
	}
	if got := s.ActiveBans(t0); len(got) != 0 {
		t.Fatalf("ActiveBans = %v, want none", got)
	}
	rec := s.Recovered()
	if want := fmt.Sprintf("%s.corrupt-%d", path, t0.Unix()); rec != want {
		t.Fatalf("Recovered() = %q, want %q", rec, want)
	}
	got, err := os.ReadFile(rec)
	if err != nil {
		t.Fatalf("renamed corrupt file is missing: %v", err)
	}
	if string(got) != "{bad" {
		t.Fatalf("corrupt file content = %q, want it preserved verbatim", got)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("original path still exists after quarantine (stat err = %v)", err)
	}

	// The store is usable and the next start is clean.
	mustAddBan(t, s, ban("192.0.2.1", t0, time.Hour, "ssh"))
	s = mustOpen(t, path, t0)
	if s.Recovered() != "" {
		t.Errorf("Recovered() = %q on a healthy file, want empty", s.Recovered())
	}
	if got := s.ActiveBans(t0); len(got) != 1 {
		t.Errorf("ActiveBans after recovery = %v, want the new ban", got)
	}
}

func TestCorruptVariants(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{"empty file", ""},
		{"truncated mid-write", `{"version":1,"bans":{"192.0.2.1":{"ip":"192.0.2.1","since":"2026-10-18T1`},
		{"trailing garbage", `{"version":1,"bans":{},"history":{},"allow":[]}xyz`},
		{"json null", `null`},
		{"json array", `[]`},
		{"unsupported version", `{"version":2,"bans":{},"history":{},"allow":[]}`},
		{"missing version", `{"bans":{},"history":{},"allow":[]}`},
		{"bad ban ip", `{"version":1,"bans":{"192.0.2.1":{"ip":"nope","since":"2026-10-18T12:00:00Z","until":"2026-10-18T13:00:00Z","category":"x"}}}`},
		{"bad bans key", `{"version":1,"bans":{"nope":{"ip":"192.0.2.1","since":"2026-10-18T12:00:00Z","until":"2026-10-18T13:00:00Z","category":"x"}}}`},
		{"empty bans key", `{"version":1,"bans":{"":{"ip":"192.0.2.1","since":"2026-10-18T12:00:00Z","until":"2026-10-18T13:00:00Z","category":"x"}}}`},
		{"mapped bans key", `{"version":1,"bans":{"::ffff:192.0.2.1":{"ip":"192.0.2.1","since":"2026-10-18T12:00:00Z","until":"2026-10-18T13:00:00Z","category":"x"}}}`},
		{"bad history key", `{"version":1,"history":{"nope":{"count":1,"last":"2026-10-18T12:00:00Z"}}}`},
		{"bad bans time", `{"version":1,"bans":{"192.0.2.1":{"ip":"192.0.2.1","since":"yesterday","until":"2026-10-18T13:00:00Z","category":"x"}}}`},
		{"bad allow entry", `{"version":1,"allow":["not-a-cidr"]}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := statePath(t)
			if err := os.WriteFile(path, []byte(tt.content), 0o600); err != nil {
				t.Fatal(err)
			}
			s, err := Open(path, t0)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if s.Recovered() == "" {
				t.Fatal("Recovered() is empty, want the quarantine path")
			}
			got, err := os.ReadFile(s.Recovered())
			if err != nil || string(got) != tt.content {
				t.Fatalf("quarantined file = %q, %v; want original content preserved", got, err)
			}
			if len(s.ActiveBans(t0.Add(-1000*time.Hour))) != 0 || len(s.AllowList()) != 0 {
				t.Fatal("store is not empty after recovery")
			}
		})
	}
}

func TestCorruptNameCollisionKeepsBoth(t *testing.T) {
	path := statePath(t)
	var recovered []string
	for _, content := range []string{"{first", "{second"} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		recovered = append(recovered, mustOpen(t, path, t0).Recovered())
	}
	if recovered[0] == recovered[1] {
		t.Fatalf("both quarantines used %q; the first corrupt file was overwritten", recovered[0])
	}
	for i, want := range []string{"{first", "{second"} {
		if got, err := os.ReadFile(recovered[i]); err != nil || string(got) != want {
			t.Errorf("%s = %q, %v; want %q", recovered[i], got, err, want)
		}
	}
}

func TestOpenMissingFile(t *testing.T) {
	path := statePath(t)
	s := mustOpen(t, path, t0)
	if s.Recovered() != "" {
		t.Errorf("Recovered() = %q, want empty", s.Recovered())
	}
	if len(s.ActiveBans(t0)) != 0 || len(s.AllowList()) != 0 {
		t.Error("fresh store is not empty")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("Open created the state file (stat err = %v); only a change should", err)
	}
}

func TestOpenReadErrorIsReturned(t *testing.T) {
	// A directory at the state path makes the read fail with something other
	// than "not exist"; that is a real error, not corruption.
	path := statePath(t)
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if s, err := Open(path, t0); err == nil {
		t.Fatalf("Open = %v, nil; want an error", s)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("a non-corruption read error must leave the path alone: %v", err)
	}
}

func TestAllowDisallow(t *testing.T) {
	path := statePath(t)
	s := mustOpen(t, path, t0)
	p := prefix("198.51.100.0/24")

	for range 2 {
		if err := s.Allow(p); err != nil {
			t.Fatal(err)
		}
	}
	if got := s.AllowList(); len(got) != 1 || got[0] != p {
		t.Fatalf("AllowList = %v, want [%v]", got, p)
	}

	s = mustOpen(t, path, t0)
	if got := s.AllowList(); len(got) != 1 || got[0] != p {
		t.Fatalf("AllowList after reopen = %v, want [%v]", got, p)
	}

	if ok, err := s.Disallow(p); err != nil || !ok {
		t.Fatalf("Disallow = %v, %v; want true, nil", ok, err)
	}
	if ok, err := s.Disallow(p); err != nil || ok {
		t.Fatalf("second Disallow = %v, %v; want false, nil", ok, err)
	}
	if got := s.AllowList(); len(got) != 0 {
		t.Fatalf("AllowList = %v, want empty", got)
	}
	s = mustOpen(t, path, t0)
	if got := s.AllowList(); len(got) != 0 {
		t.Fatalf("AllowList after reopen = %v, want empty (Disallow must persist)", got)
	}
}

func TestAllowListReturnsCopy(t *testing.T) {
	s := mustOpen(t, statePath(t), t0)
	if err := s.Allow(prefix("198.51.100.0/24")); err != nil {
		t.Fatal(err)
	}
	s.AllowList()[0] = prefix("0.0.0.0/0")
	if got := s.AllowList()[0]; got != prefix("198.51.100.0/24") {
		t.Fatalf("AllowList()[0] = %v, caller mutation leaked into the store", got)
	}
}

func TestRemoveBan(t *testing.T) {
	path := statePath(t)
	s := mustOpen(t, path, t0)
	ip := addr("192.0.2.1")
	mustAddBan(t, s, ban("192.0.2.1", t0, time.Hour, "ssh"))
	mustAddBan(t, s, ban("192.0.2.2", t0, time.Hour, "ssh"))

	if ok, err := s.RemoveBan(ip); err != nil || !ok {
		t.Fatalf("RemoveBan = %v, %v; want true, nil", ok, err)
	}
	if ok, err := s.RemoveBan(ip); err != nil || ok {
		t.Fatalf("second RemoveBan = %v, %v; want false, nil", ok, err)
	}
	if ok, err := s.RemoveBan(addr("192.0.2.77")); err != nil || ok {
		t.Fatalf("RemoveBan of unknown ip = %v, %v; want false, nil", ok, err)
	}

	s = mustOpen(t, path, t0)
	got := s.ActiveBans(t0)
	if len(got) != 1 || got[0].IP != addr("192.0.2.2") {
		t.Fatalf("bans after reopen = %v, want only 192.0.2.2", got)
	}
	if s.History(ip).Count != 1 {
		t.Errorf("History.Count = %d, want 1: removing a ban must keep the history", s.History(ip).Count)
	}
}

func TestAddBanReplacesExisting(t *testing.T) {
	path := statePath(t)
	s := mustOpen(t, path, t0)
	mustAddBan(t, s, ban("192.0.2.1", t0, 24*time.Hour, "ssh"))
	replacement := ban("192.0.2.1", t0.Add(time.Minute), time.Hour, "web")
	mustAddBan(t, s, replacement)

	for _, st := range []*Store{s, mustOpen(t, path, t0)} {
		got := st.ActiveBans(t0)
		if len(got) != 1 {
			t.Fatalf("ActiveBans = %v, want exactly one ban for the ip", got)
		}
		if got[0].Category != "web" || !got[0].Until.Equal(replacement.Until) || !got[0].Since.Equal(replacement.Since) {
			t.Fatalf("ban = %+v, want the replacement %+v taken as given", got[0], replacement)
		}
		if h := st.History(addr("192.0.2.1")); h.Count != 2 {
			t.Fatalf("History.Count = %d, want 2", h.Count)
		}
	}
}

func TestNormalizesAddresses(t *testing.T) {
	path := statePath(t)
	s := mustOpen(t, path, t0)
	mustAddBan(t, s, Ban{IP: addr("::ffff:203.0.113.9"), Since: t0, Until: t0.Add(time.Hour), Category: "ssh"})

	if h := s.History(addr("203.0.113.9")); h.Count != 1 {
		t.Errorf("History(v4) Count = %d, want 1", h.Count)
	}
	if h := s.History(addr("::ffff:203.0.113.9")); h.Count != 1 {
		t.Errorf("History(mapped) Count = %d, want 1", h.Count)
	}
	got := s.ActiveBans(t0)
	if len(got) != 1 || got[0].IP != addr("203.0.113.9") || got[0].IP.Is4In6() {
		t.Fatalf("ActiveBans = %v, want the unmapped 203.0.113.9", got)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "ffff") {
		t.Errorf("file keeps the mapped form: %s", raw)
	}

	if ok, err := s.RemoveBan(addr("::ffff:203.0.113.9")); err != nil || !ok {
		t.Fatalf("RemoveBan(mapped) = %v, %v; want true, nil", ok, err)
	}

	if err := s.Allow(prefix("::ffff:198.51.100.77/120")); err != nil {
		t.Fatal(err)
	}
	if err := s.Allow(prefix("192.0.2.77/24")); err != nil {
		t.Fatal(err)
	}
	if err := s.Allow(prefix("192.0.2.0/24")); err != nil { // same prefix, already present
		t.Fatal(err)
	}
	want := []netip.Prefix{prefix("198.51.100.0/24"), prefix("192.0.2.0/24")}
	got2 := s.AllowList()
	if len(got2) != len(want) || got2[0] != want[0] || got2[1] != want[1] {
		t.Fatalf("AllowList = %v, want %v (unmapped and masked, no duplicates)", got2, want)
	}
	if ok, err := s.Disallow(prefix("::ffff:192.0.2.5/120")); err != nil || !ok {
		t.Fatalf("Disallow(mapped, unmasked) = %v, %v; want true, nil", ok, err)
	}
}

func TestInvalidInputs(t *testing.T) {
	s := mustOpen(t, statePath(t), t0)
	if err := s.AddBan(Ban{Since: t0, Until: t0.Add(time.Hour)}); err == nil {
		t.Error("AddBan with an invalid IP succeeded, want an error")
	}
	if err := s.Allow(netip.Prefix{}); err == nil {
		t.Error("Allow with an invalid prefix succeeded, want an error")
	}
	if ok, err := s.RemoveBan(netip.Addr{}); ok || err != nil {
		t.Errorf("RemoveBan(invalid) = %v, %v; want false, nil", ok, err)
	}
	if ok, err := s.Disallow(netip.Prefix{}); ok || err != nil {
		t.Errorf("Disallow(invalid) = %v, %v; want false, nil", ok, err)
	}
	if h := s.History(netip.Addr{}); h.Count != 0 {
		t.Errorf("History(invalid) = %+v, want zero", h)
	}
	if len(s.ActiveBans(t0.Add(-time.Hour))) != 0 || len(s.AllowList()) != 0 {
		t.Error("rejected input changed the store")
	}
}

func TestNoTempLeft(t *testing.T) {
	path := statePath(t)
	s := mustOpen(t, path, t0)
	mustAddBan(t, s, ban("192.0.2.1", t0, time.Hour, "ssh"))
	if err := s.Allow(prefix("198.51.100.0/24")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RemoveBan(addr("192.0.2.1")); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("leftover temp file %s", e.Name())
		}
	}
	if len(entries) != 1 || entries[0].Name() != "state.json" {
		t.Errorf("directory holds %v, want only state.json", entries)
	}
}

func TestCreatesParentDirAndFileModes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "var", "lib", "ostrakon", "state.json")
	s := mustOpen(t, path, t0)

	dir := filepath.Dir(path)
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("Open did not create the parent directory: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Errorf("parent dir mode = %o, want 700", got)
	}

	// A stale temp file with loose permissions must not leak its mode into
	// the state file.
	if err := os.WriteFile(path+".tmp", []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	mustAddBan(t, s, ban("192.0.2.1", t0, time.Hour, "ssh"))
	info, err = os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("state file mode = %o, want 600", got)
	}
}

func TestOpenKeepsExistingParentDirMode(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	mustOpen(t, filepath.Join(dir, "state.json"), t0)
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o755 {
		t.Errorf("existing dir mode = %o, want it untouched (755)", got)
	}
}

func TestSaveFailureRollsBack(t *testing.T) {
	// breakers make the next save fail at a different step.
	breakers := map[string]func(t *testing.T, path string){
		"cannot create temp file": func(t *testing.T, path string) {
			if err := os.Mkdir(path+".tmp", 0o700); err != nil {
				t.Fatal(err)
			}
		},
		"cannot rename over target": func(t *testing.T, path string) {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(path, "keep"), 0o700); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, breakIt := range breakers {
		t.Run(name, func(t *testing.T) {
			path := statePath(t)
			s := mustOpen(t, path, t0)
			existing := ban("192.0.2.1", t0, time.Hour, "ssh")
			mustAddBan(t, s, existing)
			if err := s.Allow(prefix("198.51.100.0/24")); err != nil {
				t.Fatal(err)
			}
			onDisk, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			breakIt(t, path)

			// AddBan of a new ip.
			if err := s.AddBan(ban("192.0.2.2", t0, time.Hour, "web")); err == nil {
				t.Fatal("AddBan succeeded although the save failed")
			}
			if h := s.History(addr("192.0.2.2")); h.Count != 0 {
				t.Errorf("History after failed AddBan = %+v, want rolled back", h)
			}
			// AddBan over an existing ban.
			if err := s.AddBan(ban("192.0.2.1", t0.Add(time.Minute), 9*time.Hour, "web")); err == nil {
				t.Fatal("AddBan (replace) succeeded although the save failed")
			}
			if got := s.History(addr("192.0.2.1")); got.Count != 1 || !got.Last.Equal(existing.Since) {
				t.Errorf("History after failed replace = %+v, want count 1 last %v", got, existing.Since)
			}
			// RemoveBan.
			if ok, err := s.RemoveBan(addr("192.0.2.1")); err == nil || ok {
				t.Fatalf("RemoveBan = %v, %v; want false and an error", ok, err)
			}
			// Allow / Disallow.
			if err := s.Allow(prefix("203.0.113.0/24")); err == nil {
				t.Fatal("Allow succeeded although the save failed")
			}
			if ok, err := s.Disallow(prefix("198.51.100.0/24")); err == nil || ok {
				t.Fatalf("Disallow = %v, %v; want false and an error", ok, err)
			}

			got := s.ActiveBans(t0)
			if len(got) != 1 || got[0].IP != existing.IP || got[0].Category != "ssh" || !got[0].Until.Equal(existing.Until) {
				t.Errorf("bans = %v, want only the original %+v", got, existing)
			}
			if al := s.AllowList(); len(al) != 1 || al[0] != prefix("198.51.100.0/24") {
				t.Errorf("AllowList = %v, want the original single entry", al)
			}

			// The temp file created by a failed rename must be cleaned up.
			if name == "cannot rename over target" {
				if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
					t.Errorf("temp file left behind after failed rename (stat err = %v)", err)
				}
			}
			if name == "cannot create temp file" {
				if cur, err := os.ReadFile(path); err != nil || string(cur) != string(onDisk) {
					t.Errorf("state file changed on disk after failed saves: %q, %v", cur, err)
				}
			}
		})
	}
}

func TestSaveRecoversAfterFailure(t *testing.T) {
	path := statePath(t)
	s := mustOpen(t, path, t0)
	if err := os.Mkdir(path+".tmp", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := s.AddBan(ban("192.0.2.1", t0, time.Hour, "ssh")); err == nil {
		t.Fatal("AddBan succeeded although the save failed")
	}
	if err := os.Remove(path + ".tmp"); err != nil {
		t.Fatal(err)
	}
	mustAddBan(t, s, ban("192.0.2.1", t0, time.Hour, "ssh"))
	s = mustOpen(t, path, t0)
	if h := s.History(addr("192.0.2.1")); h.Count != 1 {
		t.Fatalf("History.Count = %d, want 1 (the failed attempt must not be counted)", h.Count)
	}
}

func TestConcurrentUse(t *testing.T) {
	path := statePath(t)
	s := mustOpen(t, path, t0)

	const workers, perWorker = 8, 10
	var wg sync.WaitGroup
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range perWorker {
				// Every worker hits its own ip and one shared ip.
				own := fmt.Sprintf("198.51.100.%d", w+1)
				since := t0.Add(time.Duration(i) * time.Second)
				if err := s.AddBan(ban(own, since, time.Hour, "ssh")); err != nil {
					t.Errorf("AddBan(%s): %v", own, err)
				}
				if err := s.AddBan(ban("203.0.113.1", since, time.Hour, "web")); err != nil {
					t.Errorf("AddBan(shared): %v", err)
				}
				s.ActiveBans(t0)
				s.History(addr(own))
				s.AllowList()
				if err := s.Prune(t0); err != nil {
					t.Errorf("Prune: %v", err)
				}
				if i%5 == 0 {
					p := prefix(fmt.Sprintf("192.0.2.%d/32", w+1))
					if err := s.Allow(p); err != nil {
						t.Errorf("Allow: %v", err)
					}
					if _, err := s.Disallow(p); err != nil {
						t.Errorf("Disallow: %v", err)
					}
				}
			}
		}()
	}
	wg.Wait()

	for _, st := range []*Store{s, mustOpen(t, path, t0)} {
		if got := len(st.ActiveBans(t0)); got != workers+1 {
			t.Errorf("active bans = %d, want %d", got, workers+1)
		}
		if got := st.History(addr("203.0.113.1")).Count; got != workers*perWorker {
			t.Errorf("shared History.Count = %d, want %d", got, workers*perWorker)
		}
		for w := range workers {
			if got := st.History(addr(fmt.Sprintf("198.51.100.%d", w+1))).Count; got != perWorker {
				t.Errorf("worker %d History.Count = %d, want %d", w, got, perWorker)
			}
		}
		if got := len(st.AllowList()); got != 0 {
			t.Errorf("AllowList = %d entries, want 0", got)
		}
	}
}
