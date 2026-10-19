package firewall

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"ostrakon/internal/netutil"
)

// Fake is an in-memory Firewall for other packages' tests. Tests read Banned
// and EnsureCalls while holding Mu, and set Err to make every method fail.
// Addresses are normalised exactly as NFT does, so Banned is keyed by the
// canonical form (an IPv4-mapped address is stored as plain IPv4).
type Fake struct {
	Mu          sync.Mutex
	Banned      map[netip.Addr]time.Duration
	EnsureCalls int
	Err         error
}

// NewFake returns an empty Fake.
func NewFake() *Fake {
	return &Fake{Banned: make(map[netip.Addr]time.Duration)}
}

// Ensure implements Firewall. The call is counted even when Err is set.
func (f *Fake) Ensure(context.Context) error {
	f.Mu.Lock()
	defer f.Mu.Unlock()
	f.EnsureCalls++
	return f.Err
}

// Ban implements Firewall.
func (f *Fake) Ban(_ context.Context, ip netip.Addr, ttl time.Duration) error {
	f.Mu.Lock()
	defer f.Mu.Unlock()
	if f.Err != nil {
		return f.Err
	}
	f.Banned[netutil.NormAddr(ip)] = ttl
	return nil
}

// Unban implements Firewall.
func (f *Fake) Unban(_ context.Context, ip netip.Addr) error {
	f.Mu.Lock()
	defer f.Mu.Unlock()
	if f.Err != nil {
		return f.Err
	}
	delete(f.Banned, netutil.NormAddr(ip))
	return nil
}
