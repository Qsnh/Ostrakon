package allowlist

import (
	"net"
	"net/netip"

	"ostrakon/internal/netutil"
)

// LocalAddrs returns the unicast addresses assigned to this machine's
// network interfaces.
func LocalAddrs() ([]netip.Addr, error) {
	as, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	return addrsFromNet(as), nil
}

// addrsFromNet extracts the IP of each address, unmapped and without zone.
// Entries that carry no valid IP are skipped.
func addrsFromNet(as []net.Addr) []netip.Addr {
	out := make([]netip.Addr, 0, len(as))
	for _, a := range as {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if na, ok := netip.AddrFromSlice(ip); ok {
			out = append(out, netutil.NormAddr(na))
		}
	}
	return out
}
