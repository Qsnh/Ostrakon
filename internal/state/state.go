// Package state is the daemon's persistent local memory: which addresses are
// banned (so bans survive a reboot), how often each address has been banned
// before (so Jev can be told), and which prefixes the administrator exempted.
//
// Every change is written to disk before it is reported as done, and rolled
// back in memory if the write fails, so memory and disk never diverge
// silently. A damaged state file never keeps the daemon from starting: it is
// renamed aside and the daemon starts empty.
package state

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"ostrakon/internal/netutil"
)

const (
	// DefaultPath is where the daemon keeps its state.
	DefaultPath = "/var/lib/ostrakon/state.json"
	// HistoryTTL is how long a ban history entry is kept after its last ban.
	HistoryTTL = 30 * 24 * time.Hour

	// version is the only file format version this code reads and writes.
	version = 1

	dirMode  = 0o700
	fileMode = 0o600
)

// Ban is an active (or recently active) ban of one address.
type Ban struct {
	IP       netip.Addr `json:"ip"`
	Since    time.Time  `json:"since"`
	Until    time.Time  `json:"until"`
	Category string     `json:"category"`
}

// History counts how often an address has been banned.
type History struct {
	Count int       `json:"count"`
	Last  time.Time `json:"last"`
}

// document is the on-disk representation. Map keys are the canonical
// (unmapped) netip.Addr text form.
type document struct {
	Version int                    `json:"version"`
	Bans    map[netip.Addr]Ban     `json:"bans"`
	History map[netip.Addr]History `json:"history"`
	Allow   []netip.Prefix         `json:"allow"`
}

// Store is the persistent state. It is safe for concurrent use.
type Store struct {
	path      string
	recovered string // set once by Open, read-only afterwards

	mu      sync.Mutex
	bans    map[netip.Addr]Ban
	history map[netip.Addr]History
	allow   []netip.Prefix
}

// Open loads the state at path, creating the parent directory (mode 0700) if
// it is missing. A missing file yields an empty store. A file that cannot be
// parsed, or that has an unsupported version, is renamed to
// path+".corrupt-<unix seconds of now>", the store starts empty and Recovered
// reports the new name. Any other failure to read the file is returned.
//
// Bans that have already expired at now, and history whose last ban is older
// than HistoryTTL, are dropped (see Prune for a long-running process).
func Open(path string, now time.Time) (*Store, error) {
	s := &Store{
		path:    path,
		bans:    map[netip.Addr]Ban{},
		history: map[netip.Addr]History{},
		allow:   []netip.Prefix{},
	}
	if err := os.MkdirAll(filepath.Dir(path), dirMode); err != nil {
		return nil, fmt.Errorf("state: creating directory: %w", err)
	}

	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return s, nil
	case err != nil:
		return nil, fmt.Errorf("state: reading %s: %w", path, err)
	}

	doc, err := decode(data)
	if err != nil {
		// Keep the damaged file for inspection; refusing to start would
		// leave the machine unprotected, and overwriting it would destroy it.
		dest, qerr := quarantine(path, now)
		if qerr != nil {
			return nil, fmt.Errorf("state: %s is corrupt (%v) and could not be set aside: %w", path, err, qerr)
		}
		s.recovered = dest
		return s, nil
	}

	s.bans, s.history, s.allow = doc.Bans, doc.History, doc.Allow
	s.dropStale(now)
	return s, nil
}

// Recovered returns the path a corrupt state file was renamed to when the
// store was opened, or "" if the file was healthy or absent.
func (s *Store) Recovered() string { return s.recovered }

// Prune drops the bans that have expired at now and the history whose last
// ban is older than HistoryTTL, the same rule Open applies at start-up. A
// long-running daemon must call it from time to time: History takes no clock,
// so without Prune counts older than HistoryTTL would live until the next
// restart. The file is rewritten only if something was dropped; if saving
// fails nothing is changed and the error is returned.
func (s *Store) Prune(now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	undo, changed := s.dropStale(now)
	if !changed {
		return nil
	}
	return s.commit(undo)
}

// dropStale deletes the bans with Until <= now and the history with Last
// before now-HistoryTTL. It reports whether it deleted anything and returns a
// function that puts the deleted entries back. Callers hold s.mu (Open, which
// has not shared the store yet, excepted).
func (s *Store) dropStale(now time.Time) (undo func(), changed bool) {
	cutoff := now.Add(-HistoryTTL)
	staleBans := map[netip.Addr]Ban{}
	for ip, b := range s.bans {
		if !b.Until.After(now) {
			staleBans[ip] = b
			delete(s.bans, ip)
		}
	}
	staleHistory := map[netip.Addr]History{}
	for ip, h := range s.history {
		if h.Last.Before(cutoff) {
			staleHistory[ip] = h
			delete(s.history, ip)
		}
	}
	undo = func() {
		maps.Copy(s.bans, staleBans)
		maps.Copy(s.history, staleHistory)
	}
	return undo, len(staleBans)+len(staleHistory) > 0
}

// AddBan records b, replacing any existing ban of the same address, counts it
// in the address's history (Count+1, Last=b.Since) and saves immediately. If
// saving fails nothing is changed and the error is returned.
func (s *Store) AddBan(b Ban) error {
	ip := netutil.NormAddr(b.IP)
	if !ip.IsValid() {
		return errors.New("state: cannot record a ban for an invalid IP address")
	}
	b.IP = ip

	s.mu.Lock()
	defer s.mu.Unlock()
	oldBan, hadBan := s.bans[ip]
	oldHist, hadHist := s.history[ip]
	s.bans[ip] = b
	s.history[ip] = History{Count: oldHist.Count + 1, Last: b.Since}
	return s.commit(func() {
		restore(s.bans, ip, oldBan, hadBan)
		restore(s.history, ip, oldHist, hadHist)
	})
}

// RemoveBan deletes the ban of ip, reporting whether there was one. The
// address's history is kept.
func (s *Store) RemoveBan(ip netip.Addr) (bool, error) {
	ip = netutil.NormAddr(ip)
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.bans[ip]
	if !ok {
		return false, nil
	}
	delete(s.bans, ip)
	if err := s.commit(func() { s.bans[ip] = old }); err != nil {
		return false, err
	}
	return true, nil
}

// ActiveBans returns the bans whose Until is after now, soonest-expiring
// first.
func (s *Store) ActiveBans(now time.Time) []Ban {
	s.mu.Lock()
	out := make([]Ban, 0, len(s.bans))
	for _, b := range s.bans {
		if b.Until.After(now) {
			out = append(out, b)
		}
	}
	s.mu.Unlock()
	slices.SortFunc(out, func(a, b Ban) int {
		return cmp.Or(a.Until.Compare(b.Until), a.IP.Compare(b.IP))
	})
	return out
}

// History returns the ban history of ip; the zero value if there is none.
func (s *Store) History(ip netip.Addr) History {
	ip = netutil.NormAddr(ip)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.history[ip]
}

// Allow adds p to the administrator's allowlist and saves immediately. It
// does nothing if p is already present.
func (s *Store) Allow(p netip.Prefix) error {
	p = netutil.NormPrefix(p)
	if !p.IsValid() {
		return errors.New("state: cannot allow an invalid prefix")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if slices.Contains(s.allow, p) {
		return nil
	}
	old := s.allow
	s.allow = append(slices.Clone(old), p)
	return s.commit(func() { s.allow = old })
}

// Disallow removes p from the allowlist, reporting whether it was present.
func (s *Store) Disallow(p netip.Prefix) (bool, error) {
	p = netutil.NormPrefix(p)
	s.mu.Lock()
	defer s.mu.Unlock()
	i := slices.Index(s.allow, p)
	if !p.IsValid() || i < 0 {
		return false, nil
	}
	old := s.allow
	s.allow = slices.Delete(slices.Clone(old), i, i+1)
	if err := s.commit(func() { s.allow = old }); err != nil {
		return false, err
	}
	return true, nil
}

// AllowList returns a copy of the administrator's allowlist.
func (s *Store) AllowList() []netip.Prefix {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.allow)
}

// commit saves the already-applied in-memory change. If that fails it calls
// undo, still under the caller's lock, so memory matches the disk again.
func (s *Store) commit(undo func()) error {
	if err := s.save(); err != nil {
		undo()
		return err
	}
	return nil
}

// restore puts key back to its previous value, or deletes it if it had none.
func restore[V any](m map[netip.Addr]V, key netip.Addr, old V, had bool) {
	if had {
		m[key] = old
	} else {
		delete(m, key)
	}
}

// save atomically replaces the state file: write path+".tmp", fsync it,
// rename it over path, then (best effort) fsync the directory so the rename
// itself survives a power cut. Callers hold s.mu.
func (s *Store) save() error {
	allow := s.allow
	if allow == nil {
		allow = []netip.Prefix{} // encode as [] rather than null
	}
	data, err := json.Marshal(document{Version: version, Bans: s.bans, History: s.history, Allow: allow})
	if err != nil {
		return fmt.Errorf("state: encoding: %w", err)
	}
	data = append(data, '\n')

	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return fmt.Errorf("state: creating directory: %w", err)
	}
	tmp := s.path + ".tmp"
	if err := writeSynced(tmp, data); err != nil {
		return fmt.Errorf("state: writing %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("state: replacing %s: %w", s.path, err)
	}
	syncDir(dir)
	return nil
}

// writeSynced creates name with mode 0600 (even if a leftover file with other
// permissions was there), writes data and fsyncs it. A partly written file is
// removed.
func writeSynced(name string, data []byte) error {
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, fileMode)
	if err != nil {
		return err
	}
	err = f.Chmod(fileMode)
	if err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(name)
	}
	return err
}

// syncDir fsyncs a directory so a rename inside it is durable. It is best
// effort: some platforms and filesystems refuse, and the data file itself has
// already been synced.
func syncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = d.Sync()
	_ = d.Close()
}

// quarantine renames the damaged file at path to path+".corrupt-<unix
// seconds>", appending -1, -2, ... if that name is taken so an earlier
// quarantined file is never overwritten, and returns the new name.
func quarantine(path string, now time.Time) (string, error) {
	base := fmt.Sprintf("%s.corrupt-%d", path, now.Unix())
	dest := base
	for i := 1; ; i++ {
		_, err := os.Lstat(dest)
		if errors.Is(err, fs.ErrNotExist) {
			break
		}
		if err != nil {
			return "", err
		}
		dest = fmt.Sprintf("%s-%d", base, i)
	}
	if err := os.Rename(path, dest); err != nil {
		return "", err
	}
	syncDir(filepath.Dir(path))
	return dest, nil
}

// decode parses and validates a state file. Everything this code writes
// passes; anything else (syntax errors, other versions, keys that are not
// canonical addresses) is reported as an error so the caller treats the file
// as corrupt.
func decode(data []byte) (document, error) {
	var doc document
	if err := json.Unmarshal(data, &doc); err != nil {
		return document{}, err
	}
	if doc.Version != version {
		return document{}, fmt.Errorf("unsupported version %d", doc.Version)
	}
	bans := make(map[netip.Addr]Ban, len(doc.Bans))
	for ip, b := range doc.Bans {
		if !canonical(ip) {
			return document{}, fmt.Errorf("bans: bad address %q", ip)
		}
		b.IP = ip // the key is authoritative
		bans[ip] = b
	}
	history := make(map[netip.Addr]History, len(doc.History))
	for ip, h := range doc.History {
		if !canonical(ip) {
			return document{}, fmt.Errorf("history: bad address %q", ip)
		}
		history[ip] = h
	}
	allow := make([]netip.Prefix, 0, len(doc.Allow))
	for _, p := range doc.Allow {
		if !p.IsValid() {
			return document{}, errors.New("allow: invalid prefix")
		}
		if p = netutil.NormPrefix(p); !slices.Contains(allow, p) {
			allow = append(allow, p)
		}
	}
	return document{Version: version, Bans: bans, History: history, Allow: allow}, nil
}

// canonical reports whether ip is valid and already in the form
// netutil.NormAddr produces, which is the only form the store writes as a map key.
func canonical(ip netip.Addr) bool {
	return ip.IsValid() && ip == netutil.NormAddr(ip)
}
