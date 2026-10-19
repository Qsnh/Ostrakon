package firewall

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"ostrakon/internal/netutil"
)

// Runner executes an nft script (the input of `nft -f -`) as one atomic
// transaction. It exists so tests can inject a recorder instead of running
// the real binary.
type Runner func(ctx context.Context, script string) error

// ExecRunner runs script through `nft -f -`. On failure the returned error
// wraps the exec error and carries nft's own output, which is where nft
// explains what it rejected.
func ExecRunner(ctx context.Context, script string) error {
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	if msg := strings.TrimSpace(string(out)); msg != "" {
		return fmt.Errorf("nft: %w: %s", err, msg)
	}
	return fmt.Errorf("nft: %w", err)
}

// ensureScript builds the table, the two timeout sets and the drop rules.
// "add" is a no-op for objects that already exist, so existing bans survive;
// the chain is flushed first so repeated runs do not stack duplicate rules.
const ensureScript = `add table inet ostrakon
add set inet ostrakon banned_v4 { type ipv4_addr; flags timeout; }
add set inet ostrakon banned_v6 { type ipv6_addr; flags timeout; }
add chain inet ostrakon prerouting { type filter hook prerouting priority -200; policy accept; }
flush chain inet ostrakon prerouting
add rule inet ostrakon prerouting ip saddr @banned_v4 drop
add rule inet ostrakon prerouting ip6 saddr @banned_v6 drop
`

// NFT is a Firewall backed by nftables. Run must be set (normally to
// ExecRunner).
type NFT struct {
	Run Runner
}

// Ensure implements Firewall.
func (n *NFT) Ensure(ctx context.Context) error {
	if err := n.Run(ctx, ensureScript); err != nil {
		return fmt.Errorf("ensure nftables ruleset: %w", err)
	}
	return nil
}

// Ban implements Firewall.
func (n *NFT) Ban(ctx context.Context, ip netip.Addr, ttl time.Duration) error {
	ip = netutil.NormAddr(ip)
	if !ip.IsValid() {
		return errors.New("ban: invalid IP address")
	}
	if ttl < time.Second {
		return fmt.Errorf("ban %s: ttl %v is shorter than one second", ip, ttl)
	}
	// Round up without computing ttl+1s, which would overflow for huge ttls.
	secs := int64(ttl / time.Second)
	if ttl%time.Second != 0 {
		secs++
	}
	// Adding an element that already exists keeps its old timeout, so to
	// refresh the timeout remove the element and add it again. All of it
	// runs as one nft transaction.
	script := dropElement(ip) + "add element inet ostrakon " + setName(ip) +
		" { " + ip.String() + " timeout " + strconv.FormatInt(secs, 10) + "s }\n"
	if err := n.Run(ctx, script); err != nil {
		return fmt.Errorf("ban %s: %w", ip, err)
	}
	return nil
}

// Unban implements Firewall.
func (n *NFT) Unban(ctx context.Context, ip netip.Addr) error {
	ip = netutil.NormAddr(ip)
	if !ip.IsValid() {
		return errors.New("unban: invalid IP address")
	}
	if err := n.Run(ctx, dropElement(ip)); err != nil {
		return fmt.Errorf("unban %s: %w", ip, err)
	}
	return nil
}

// dropElement removes ip from its set. The preceding add makes the delete
// succeed whether or not the element is present, since nft errors on
// deleting a missing element.
func dropElement(ip netip.Addr) string {
	set := setName(ip)
	el := " { " + ip.String() + " }\n"
	return "add element inet ostrakon " + set + el +
		"delete element inet ostrakon " + set + el
}

// setName picks the set for a normalised address.
func setName(ip netip.Addr) string {
	if ip.Is4() {
		return "banned_v4"
	}
	return "banned_v6"
}
