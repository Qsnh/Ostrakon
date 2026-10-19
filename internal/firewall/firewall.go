// Package firewall bans and unbans addresses through nftables.
//
// Bans live in two timeout sets (one per address family) that a single
// prerouting drop rule consults, so nftables itself expires a ban when its
// TTL runs out and the daemon never has to schedule unbans.
package firewall

import (
	"context"
	"net/netip"
	"os/exec"
	"time"
)

// Firewall is what the daemon needs from a packet filter.
type Firewall interface {
	// Ensure creates the table, sets and drop rules. It is idempotent and
	// leaves existing set contents (current bans) untouched.
	Ensure(ctx context.Context) error
	// Ban drops traffic from ip for ttl, rounded up to whole seconds. Banning
	// an already banned address restarts its timeout.
	Ban(ctx context.Context, ip netip.Addr, ttl time.Duration) error
	// Unban lifts the ban on ip. Unbanning an address that is not banned is
	// not an error.
	Unban(ctx context.Context, ip netip.Addr) error
}

// Available reports whether the nft binary is on PATH.
func Available() bool {
	_, err := exec.LookPath("nft")
	return err == nil
}
