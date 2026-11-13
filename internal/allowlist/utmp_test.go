package allowlist

import (
	"encoding/binary"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

const (
	utRecSize  = 384
	utHostOff  = 76
	utHostLen  = 256
	utAddrOff  = 348
	utUserProc = 7
)

// utRec builds one 384-byte glibc utmp record. addr is the raw 16-byte
// ut_addr_v6 field (nil = all zero).
func utRec(typ int16, host string, addr []byte) []byte {
	b := make([]byte, utRecSize)
	binary.LittleEndian.PutUint16(b[0:], uint16(typ))
	// Surround the fields under test with junk that must not influence parsing.
	copy(b[8:], "pts/0")
	copy(b[44:], "alice")
	copy(b[utHostOff:utHostOff+utHostLen], host)
	copy(b[utAddrOff:utAddrOff+16], addr)
	return b
}

func v4Field(ip string) []byte {
	a := addr(ip).As4()
	return a[:]
}

func v6Field(ip string) []byte {
	a := addr(ip).As16()
	return a[:]
}

func concat(recs ...[]byte) []byte {
	var out []byte
	for _, r := range recs {
		out = append(out, r...)
	}
	return out
}

func addrs(ss ...string) []netip.Addr {
	var out []netip.Addr
	for _, s := range ss {
		out = append(out, addr(s))
	}
	return out
}

func TestParseUTMP(t *testing.T) {
	data := concat(
		utRec(utUserProc, "", v4Field("198.51.100.4")),
		utRec(utUserProc, "2001:db8::9", nil),
		utRec(8, "203.0.113.1", nil), // DEAD_PROCESS: ignored
		utRec(utUserProc, ":0", nil), // local display: not an IP
	)
	got := ParseUTMP(data)
	want := addrs("198.51.100.4", "2001:db8::9")
	if !slices.Equal(got, want) {
		t.Fatalf("ParseUTMP = %v, want %v", got, want)
	}
}

func TestParseUTMPAddrForms(t *testing.T) {
	tests := []struct {
		name string
		rec  []byte
		want []netip.Addr
	}{
		{"ipv4 in first four bytes", utRec(utUserProc, "", v4Field("203.0.113.5")), addrs("203.0.113.5")},
		{"ipv6", utRec(utUserProc, "", v6Field("2001:db8::1")), addrs("2001:db8::1")},
		{"ipv6 loopback is not mistaken for ipv4", utRec(utUserProc, "", v6Field("::1")), addrs("::1")},
		{"ipv4-mapped ipv6 is unmapped", utRec(utUserProc, "", v6Field("::ffff:203.0.113.6")), addrs("203.0.113.6")},
		{"nonzero addr wins over host", utRec(utUserProc, "192.0.2.1", v4Field("203.0.113.5")), addrs("203.0.113.5")},
		{"host ipv4 fallback", utRec(utUserProc, "203.0.113.7", nil), addrs("203.0.113.7")},
		{"host truncated at NUL", utRec(utUserProc, "203.0.113.8\x00garbage", nil), addrs("203.0.113.8")},
		{"host mapped is unmapped", utRec(utUserProc, "::ffff:203.0.113.9", nil), addrs("203.0.113.9")},
		{"host hostname ignored", utRec(utUserProc, "bastion.example.com", nil), nil},
		{"host empty and addr zero", utRec(utUserProc, "", nil), nil},
		{"type 0 empty", utRec(0, "203.0.113.1", v4Field("203.0.113.1")), nil},
		{"type 1 run level", utRec(1, "203.0.113.1", v4Field("203.0.113.1")), nil},
		{"type 6 login process", utRec(6, "203.0.113.1", v4Field("203.0.113.1")), nil},
		{"type 8 dead process", utRec(8, "203.0.113.1", v4Field("203.0.113.1")), nil},
		{"negative type", utRec(-7, "203.0.113.1", v4Field("203.0.113.1")), nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ParseUTMP(tc.rec); !slices.Equal(got, tc.want) {
				t.Errorf("ParseUTMP = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParseUTMPTypeIsLittleEndianInt16(t *testing.T) {
	rec := utRec(utUserProc, "", v4Field("203.0.113.5"))
	// High byte of ut_type set: the value is 0x0107, not 7.
	rec[1] = 1
	if got := ParseUTMP(rec); len(got) != 0 {
		t.Errorf("type 0x0107 accepted: %v", got)
	}
}

func TestParseUTMPTrailingPartialRecord(t *testing.T) {
	full := utRec(utUserProc, "", v4Field("198.51.100.4"))
	partial := utRec(utUserProc, "", v4Field("198.51.100.5"))[:utRecSize-1]
	got := ParseUTMP(concat(full, partial))
	if want := addrs("198.51.100.4"); !slices.Equal(got, want) {
		t.Errorf("ParseUTMP = %v, want %v", got, want)
	}
	// A partial record alone, even one that contains the address field, is ignored.
	if got := ParseUTMP(partial[:utAddrOff+16]); len(got) != 0 {
		t.Errorf("partial record parsed: %v", got)
	}
	if got := ParseUTMP(nil); len(got) != 0 {
		t.Errorf("ParseUTMP(nil) = %v", got)
	}
	if got := ParseUTMP([]byte{}); len(got) != 0 {
		t.Errorf("ParseUTMP(empty) = %v", got)
	}
}

func TestReadUTMP(t *testing.T) {
	path := filepath.Join(t.TempDir(), "utmp")
	data := concat(
		utRec(utUserProc, "", v4Field("198.51.100.4")),
		utRec(utUserProc, "2001:db8::9", nil),
	)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := ReadUTMP(path)
	if err != nil {
		t.Fatalf("ReadUTMP: %v", err)
	}
	if want := addrs("198.51.100.4", "2001:db8::9"); !slices.Equal(got, want) {
		t.Errorf("ReadUTMP = %v, want %v", got, want)
	}
}

func TestReadUTMPMissing(t *testing.T) {
	got, err := ReadUTMP(filepath.Join(t.TempDir(), "nope"))
	if err == nil {
		t.Fatal("ReadUTMP on a missing file returned nil error")
	}
	if len(got) != 0 {
		t.Errorf("ReadUTMP on a missing file returned %v", got)
	}
}
