// Package control is the local administration channel: the daemon listens on
// a unix socket and the ostrakon command line talks to it. Each connection
// carries one JSON request and one JSON response.
//
// The socket is mode 0600, so only root can use it. That is the access
// control; there is no further authentication.
package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"ostrakon/internal/daemon"
	"ostrakon/internal/netutil"
	"ostrakon/internal/state"
)

// SocketPath is where the daemon listens.
const SocketPath = "/run/ostrakon/ostrakon.sock"

const (
	dirMode  = 0o755
	sockMode = 0o600

	// readTimeout bounds how long a client may take to send its request, so
	// one that connects and says nothing cannot pin a goroutine.
	readTimeout = 5 * time.Second
	// writeTimeout bounds sending the response.
	writeTimeout = 5 * time.Second
	// opTimeout bounds one backend operation (unban and allow run nft).
	opTimeout = 10 * time.Second
	// callTimeout bounds a whole Call; it exceeds opTimeout so that the
	// server's own timeout is what the user sees.
	callTimeout = 15 * time.Second
	dialTimeout = 5 * time.Second
	// maxRequest is far more than any valid request needs.
	maxRequest = 4096
)

// Request is what the CLI sends. Cmd is status, bans, unban, allow or
// disallow; Arg is the IP or prefix for the last three.
type Request struct {
	Cmd string `json:"cmd"`
	Arg string `json:"arg,omitempty"`
}

// Response is the daemon's answer. When OK is false, Error says why.
type Response struct {
	OK     bool           `json:"ok"`
	Error  string         `json:"error,omitempty"`
	Status *daemon.Status `json:"status,omitempty"`
	Bans   []state.Ban    `json:"bans,omitempty"`
}

// Backend is what the server administers. *daemon.Daemon implements it.
type Backend interface {
	Status() daemon.Status
	Bans() []state.Ban
	Unban(ctx context.Context, ip netip.Addr) error
	Allow(ctx context.Context, p netip.Prefix) error
	Disallow(p netip.Prefix) error
}

var _ Backend = (*daemon.Daemon)(nil)

// Serve listens on path and answers requests with b until ctx is done, then
// closes the listener, waits for the requests in flight and removes the
// socket file; it returns nil in that case. The parent directory is created
// (0755) if missing, and the socket is 0600 from the moment it appears under
// its name. A stale socket file left by a crashed daemon is replaced; a
// socket someone is still listening on, or any file that is not a socket, is
// an error and is left alone.
func Serve(ctx context.Context, path string, b Backend) error {
	if err := prepare(path); err != nil {
		return err
	}

	// Bind under another name, restrict it, then rename it into place:
	// binding directly would leave the socket with umask-derived permissions
	// until a chmod could run.
	tmp := path + ".tmp"
	_ = os.Remove(tmp)
	ln, err := net.Listen("unix", tmp)
	if err != nil {
		return fmt.Errorf("control: listen: %w", err)
	}
	defer os.Remove(tmp) // Close unlinks only what it was bound to
	if err := os.Chmod(tmp, sockMode); err != nil {
		_ = ln.Close()
		return fmt.Errorf("control: chmod socket: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = ln.Close()
		return fmt.Errorf("control: install socket: %w", err)
	}
	defer os.Remove(path)

	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()

	var wg sync.WaitGroup
	defer wg.Wait() // runs before the removals above: no request outlives the socket
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			_ = ln.Close()
			return fmt.Errorf("control: accept: %w", err)
		}
		wg.Go(func() { handle(ctx, conn, b) })
	}
}

// prepare creates the parent directory and clears a stale socket at path.
func prepare(path string) error {
	dir := filepath.Dir(path)
	if _, err := os.Stat(dir); errors.Is(err, fs.ErrNotExist) {
		if err := os.MkdirAll(dir, dirMode); err != nil {
			return fmt.Errorf("control: creating %s: %w", dir, err)
		}
		// MkdirAll applies the umask.
		if err := os.Chmod(dir, dirMode); err != nil {
			return fmt.Errorf("control: creating %s: %w", dir, err)
		}
	}

	fi, err := os.Lstat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		return fmt.Errorf("control: %w", err)
	case fi.Mode()&fs.ModeSocket == 0:
		return fmt.Errorf("control: %s exists and is not a socket", path)
	}
	if c, err := net.DialTimeout("unix", path, dialTimeout); err == nil {
		_ = c.Close()
		return fmt.Errorf("control: another ostrakon is already listening on %s", path)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("control: removing stale socket: %w", err)
	}
	return nil
}

// handle answers one connection.
func handle(ctx context.Context, conn net.Conn, b Backend) {
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
	var req Request
	var resp Response
	if err := json.NewDecoder(io.LimitReader(conn, maxRequest)).Decode(&req); err != nil {
		resp = failure("bad request")
	} else {
		resp = dispatch(ctx, req, b)
	}

	_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	_ = json.NewEncoder(conn).Encode(resp)
}

func failure(msg string) Response { return Response{Error: msg} }

func dispatch(ctx context.Context, req Request, b Backend) Response {
	switch req.Cmd {
	case "status":
		st := b.Status()
		return Response{OK: true, Status: &st}
	case "bans":
		return Response{OK: true, Bans: b.Bans()}
	case "unban":
		ip, err := netip.ParseAddr(req.Arg)
		if err != nil {
			return failure(fmt.Sprintf("invalid IP address %q", req.Arg))
		}
		ctx, cancel := context.WithTimeout(ctx, opTimeout)
		defer cancel()
		return result(b.Unban(ctx, netutil.NormAddr(ip)))
	case "allow", "disallow":
		p, err := ParsePrefix(req.Arg)
		if err != nil {
			return failure(err.Error())
		}
		if req.Cmd == "allow" {
			// Allowing lifts the bans inside p, which runs nft.
			ctx, cancel := context.WithTimeout(ctx, opTimeout)
			defer cancel()
			return result(b.Allow(ctx, p))
		}
		return result(b.Disallow(p))
	}
	return failure("unknown command")
}

func result(err error) Response {
	if err != nil {
		return failure(err.Error())
	}
	return Response{OK: true}
}

// Call sends req to the daemon listening on path and returns its answer. A
// failure to reach the daemon is returned as is, so that NotRunning and
// errors.Is(err, fs.ErrPermission) can tell the reasons apart.
func Call(path string, req Request) (Response, error) {
	conn, err := net.DialTimeout("unix", path, dialTimeout)
	if err != nil {
		return Response{}, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(callTimeout))

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return Response{}, fmt.Errorf("control: sending request: %w", err)
	}
	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return Response{}, fmt.Errorf("control: reading response: %w", err)
	}
	return resp, nil
}

// NotRunning reports whether err, from Call or a dial, means that no daemon
// is listening: the socket is missing, or nothing accepts on it.
func NotRunning(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED)
}

// Running reports whether a daemon may be listening on path. It is false only
// when the socket is missing or refuses connections; any other failure, such
// as permission denied for a caller that is not root, counts as running so
// that the real error surfaces from Call.
func Running(path string) bool {
	c, err := net.DialTimeout("unix", path, dialTimeout)
	if err != nil {
		return !NotRunning(err)
	}
	_ = c.Close()
	return true
}

// ParsePrefix parses an IP address or a CIDR prefix. A single address becomes
// a host prefix (/32 or /128); zones are rejected. The result is normalised like every stored
// prefix (host bits cleared, IPv4-mapped IPv6 turned into IPv4). An IPv4-mapped
// IPv6 prefix shorter than /96 is rejected: IPv4 traffic is matched as IPv4,
// so such a prefix could never match anything.
func ParsePrefix(s string) (netip.Prefix, error) {
	var p netip.Prefix
	if a, err := netip.ParseAddr(s); err == nil {
		if a.Zone() != "" {
			// Also what "fe80::1%eth0/64" parses as: an address whose zone is "eth0/64".
			return netip.Prefix{}, fmt.Errorf("invalid IP address or prefix %q: zones are not supported", s)
		}
		p = netip.PrefixFrom(a, a.BitLen())
	} else {
		p, err = netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("invalid IP address or prefix %q", s)
		}
	}
	if p.Addr().Is4In6() && p.Bits() < 96 {
		return netip.Prefix{}, fmt.Errorf("%q is an IPv4-mapped IPv6 prefix shorter than /96; it could never match IPv4 traffic (use the IPv4 form)", s)
	}
	return netutil.NormPrefix(p), nil
}
