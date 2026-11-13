package firewall

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"time"

	"github.com/Qsnh/Ostrakon/internal/netutil"
)

// Fake is an in-memory Firewall for other packages' tests. Tests read Banned
// and EnsureCalls while holding Mu, and set Err to make every method fail.
// Setting Missing models the table having been removed: Present reports
// false and Ban and Unban fail, as nft would, until Ensure rebuilds it.
// Addresses are normalised exactly as NFT does, so Banned is keyed by the
// canonical form (an IPv4-mapped address is stored as plain IPv4).
type Fake struct {
	Mu          sync.Mutex
	Banned      map[netip.Addr]time.Duration
	EnsureCalls int
	Err         error
	Missing     bool
}

// errFakeMissing is what Ban and Unban return while Missing is set.
var errFakeMissing = errors.New("nft: Error: No such file or directory (fake table missing)")

// NewFake returns an empty Fake.
func NewFake() *Fake {
	return &Fake{Banned: make(map[netip.Addr]time.Duration)}
}

// Ensure implements Firewall. The call is counted even when Err is set.
func (f *Fake) Ensure(context.Context) error {
	f.Mu.Lock()
	defer f.Mu.Unlock()
	f.EnsureCalls++
	if f.Err != nil {
		return f.Err
	}
	f.Missing = false
	return nil
}

// Present implements Firewall.
func (f *Fake) Present(context.Context) (bool, error) {
	f.Mu.Lock()
	defer f.Mu.Unlock()
	if f.Err != nil {
		return false, f.Err
	}
	return !f.Missing, nil
}

// Ban implements Firewall.
func (f *Fake) Ban(_ context.Context, ip netip.Addr, ttl time.Duration) error {
	f.Mu.Lock()
	defer f.Mu.Unlock()
	if f.Err != nil {
		return f.Err
	}
	if f.Missing {
		return errFakeMissing
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
	if f.Missing {
		return errFakeMissing
	}
	delete(f.Banned, netutil.NormAddr(ip))
	return nil
}
