package allowlist

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"os"

	"ostrakon/internal/netutil"
)

// UTMPPath is where glibc keeps the table of current login sessions.
const UTMPPath = "/var/run/utmp"

// glibc struct utmp layout (identical on x86_64 and aarch64, little endian).
const (
	utmpRecordSize = 384
	utmpTypeOff    = 0   // int16 ut_type
	utmpHostOff    = 76  // [256]byte ut_host
	utmpHostLen    = 256 //
	utmpAddrOff    = 348 // [16]byte ut_addr_v6
	utmpAddrLen    = 16  //
	utmpUserProc   = 7   // USER_PROCESS
)

// ReadUTMP reads the utmp file at path and returns the remote addresses of
// its logged-in sessions. The error is non-nil if the file cannot be read.
func ReadUTMP(path string) ([]netip.Addr, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseUTMP(data), nil
}

// ParseUTMP returns the remote address of every USER_PROCESS record in data,
// in file order and without deduplication. The address comes from ut_addr_v6
// (an IPv4 address occupies its first four bytes), or, when that is all zero,
// from ut_host if that holds an IP literal. Records that carry no usable
// address, and a trailing partial record, are ignored.
func ParseUTMP(data []byte) []netip.Addr {
	var out []netip.Addr
	for ; len(data) >= utmpRecordSize; data = data[utmpRecordSize:] {
		rec := data[:utmpRecordSize]
		if int16(binary.LittleEndian.Uint16(rec[utmpTypeOff:])) != utmpUserProc {
			continue
		}
		if a, ok := utmpAddr(rec); ok {
			out = append(out, a)
		}
	}
	return out
}

func utmpAddr(rec []byte) (netip.Addr, bool) {
	raw := rec[utmpAddrOff : utmpAddrOff+utmpAddrLen]
	switch {
	case allZero(raw[4:]) && !allZero(raw[:4]):
		return netip.AddrFrom4([4]byte(raw[:4])), true
	case !allZero(raw):
		return netutil.NormAddr(netip.AddrFrom16([16]byte(raw))), true
	}
	host := rec[utmpHostOff : utmpHostOff+utmpHostLen]
	if i := bytes.IndexByte(host, 0); i >= 0 {
		host = host[:i]
	}
	a, err := netip.ParseAddr(string(host))
	if err != nil {
		return netip.Addr{}, false
	}
	return netutil.NormAddr(a), true
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}
