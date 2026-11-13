// Package netutil holds the address normalisation shared by every package
// that stores or compares IPs. Keeping one copy matters: if two packages
// normalised differently, an allowlist entry written by one would silently
// stop matching in the other.
package netutil

import "net/netip"

// NormAddr unmaps IPv4-mapped IPv6 and drops any zone so that every
// representation of one host compares equal. The zero Addr stays the zero
// Addr.
func NormAddr(a netip.Addr) netip.Addr {
	return a.Unmap().WithZone("")
}

// NormPrefix returns p masked, with an IPv4-mapped IPv6 prefix of at least
// 96 bits converted to the equivalent IPv4 prefix. Invalid prefixes yield the
// zero Prefix.
func NormPrefix(p netip.Prefix) netip.Prefix {
	if !p.IsValid() {
		return netip.Prefix{}
	}
	a := p.Addr().WithZone("")
	bits := p.Bits()
	if a.Is4In6() && bits >= 96 {
		a, bits = a.Unmap(), bits-96
	}
	return netip.PrefixFrom(a, bits).Masked()
}
