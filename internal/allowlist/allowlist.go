// Package allowlist decides which source addresses must never be banned.
// Locking the administrator out of their own server is the worst failure this
// daemon can cause, so anything that plausibly belongs to the owner, to the
// local network, or to a recently successful login is exempt.
package allowlist

import (
	"net/netip"
	"sync"
	"time"

	"ostrakon/internal/netutil"
)

// SuccessTTL is how long an address stays exempt after a successful login.
const SuccessTTL = 24 * time.Hour

// sweepEvery bounds how often NoteSuccess scans for expired success entries.
// Memory therefore stays proportional to the successes of the last
// SuccessTTL + sweepEvery.
const sweepEvery = time.Hour

// Builtin holds the loopback, unspecified, link-local and private ranges
// (RFC 1122, 1918, 3927, 4193, 4291, 6598) that are never banned.
var Builtin = mustPrefixes(
	"127.0.0.0/8", "::1/128", "0.0.0.0/8", "::/128",
	"169.254.0.0/16", "fe80::/10",
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7",
)

// List is the never-ban set. The Builtin and Cloudflare ranges are always
// part of it; the rest is supplied through the setters. It is safe for
// concurrent use.
type List struct {
	mu        sync.RWMutex
	local     map[netip.Addr]struct{}
	sessions  map[netip.Addr]struct{}
	success   map[netip.Addr]time.Time // address -> expiry
	user      []netip.Prefix
	lastSweep time.Time
}

// New returns a List holding only the Builtin and Cloudflare ranges.
func New() *List {
	return &List{
		local:    map[netip.Addr]struct{}{},
		sessions: map[netip.Addr]struct{}{},
		success:  map[netip.Addr]time.Time{},
	}
}

// Allowed reports whether ip must never be banned at time now. IPv4-mapped
// IPv6 addresses are treated as the IPv4 address they carry; an invalid
// address is not allowed.
func (l *List) Allowed(ip netip.Addr, now time.Time) bool {
	ip = netutil.NormAddr(ip)
	if !ip.IsValid() {
		return false
	}
	if containsAny(Builtin, ip) || containsAny(Cloudflare, ip) {
		return true
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	if _, ok := l.local[ip]; ok {
		return true
	}
	if _, ok := l.sessions[ip]; ok {
		return true
	}
	if exp, ok := l.success[ip]; ok && now.Before(exp) {
		return true
	}
	return containsAny(l.user, ip)
}

// SetLocal replaces the set of this machine's own interface addresses.
func (l *List) SetLocal(addrs []netip.Addr) {
	set := addrSet(addrs)
	l.mu.Lock()
	l.local = set
	l.mu.Unlock()
}

// SetSessions replaces the set of addresses with a live login session.
func (l *List) SetSessions(addrs []netip.Addr) {
	set := addrSet(addrs)
	l.mu.Lock()
	l.sessions = set
	l.mu.Unlock()
}

// NoteSuccess records a successful login from ip at now, exempting it until
// now+SuccessTTL. Every call refreshes the expiry (it is never shortened).
func (l *List) NoteSuccess(ip netip.Addr, now time.Time) {
	ip = netutil.NormAddr(ip)
	if !ip.IsValid() {
		return
	}
	exp := now.Add(SuccessTTL)
	l.mu.Lock()
	defer l.mu.Unlock()
	if old, ok := l.success[ip]; !ok || exp.After(old) {
		l.success[ip] = exp
	}
	if now.Sub(l.lastSweep) >= sweepEvery {
		for a, e := range l.success {
			if !now.Before(e) {
				delete(l.success, a)
			}
		}
		l.lastSweep = now
	}
}

// SetUser replaces the administrator-supplied prefixes.
func (l *List) SetUser(p []netip.Prefix) {
	norm := make([]netip.Prefix, 0, len(p))
	for _, pf := range p {
		if pf = netutil.NormPrefix(pf); pf.IsValid() {
			norm = append(norm, pf)
		}
	}
	l.mu.Lock()
	l.user = norm
	l.mu.Unlock()
}

func addrSet(addrs []netip.Addr) map[netip.Addr]struct{} {
	set := make(map[netip.Addr]struct{}, len(addrs))
	for _, a := range addrs {
		if a = netutil.NormAddr(a); a.IsValid() {
			set[a] = struct{}{}
		}
	}
	return set
}

func containsAny(ps []netip.Prefix, ip netip.Addr) bool {
	for _, p := range ps {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func mustPrefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}
