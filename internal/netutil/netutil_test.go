package netutil

import (
	"net/netip"
	"testing"
)

func TestNormAddr(t *testing.T) {
	tests := []struct {
		name string
		in   netip.Addr
		want netip.Addr
	}{
		{"ipv4", netip.MustParseAddr("203.0.113.9"), netip.MustParseAddr("203.0.113.9")},
		{"ipv4-mapped", netip.MustParseAddr("::ffff:203.0.113.9"), netip.MustParseAddr("203.0.113.9")},
		{"ipv4-mapped with zone", netip.MustParseAddr("::ffff:203.0.113.9").WithZone("eth0"), netip.MustParseAddr("203.0.113.9")},
		{"ipv6", netip.MustParseAddr("2001:db8::5"), netip.MustParseAddr("2001:db8::5")},
		{"ipv6 with zone", netip.MustParseAddr("fe80::1%eth0"), netip.MustParseAddr("fe80::1")},
		{"zero stays zero", netip.Addr{}, netip.Addr{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NormAddr(tt.in); got != tt.want {
				t.Fatalf("NormAddr(%v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestNormPrefix(t *testing.T) {
	tests := []struct {
		name string
		in   netip.Prefix
		want netip.Prefix
	}{
		{"already canonical", netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("198.51.100.0/24")},
		{"masked", netip.MustParsePrefix("192.0.2.77/24"), netip.MustParsePrefix("192.0.2.0/24")},
		{"ipv6 masked", netip.MustParsePrefix("2001:db8:1:2::5/48"), netip.MustParsePrefix("2001:db8:1::/48")},
		{"mapped /120 becomes v4 /24", netip.MustParsePrefix("::ffff:198.51.100.77/120"), netip.MustParsePrefix("198.51.100.0/24")},
		{"mapped /128 becomes v4 /32", netip.MustParsePrefix("::ffff:198.51.100.77/128"), netip.MustParsePrefix("198.51.100.77/32")},
		{"mapped /96 becomes v4 /0", netip.MustParsePrefix("::ffff:0.0.0.0/96"), netip.MustParsePrefix("0.0.0.0/0")},
		{"mapped shorter than /96 stays ipv6", netip.MustParsePrefix("::ffff:0.0.0.0/80"), netip.MustParsePrefix("::/80")},
		{"zone dropped", netip.PrefixFrom(netip.MustParseAddr("fe80::1%eth0"), 64), netip.MustParsePrefix("fe80::/64")},
		{"invalid", netip.Prefix{}, netip.Prefix{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NormPrefix(tt.in); got != tt.want {
				t.Fatalf("NormPrefix(%v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}
