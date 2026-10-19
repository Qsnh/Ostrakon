// Command ostrakon bans attacking IP addresses, asking TypeSafe's Jev
// decision model whether a source is attacking. `ostrakon run` is the daemon;
// the other commands talk to it over its control socket.
package main

import (
	"io"
	"os"
	"time"

	"ostrakon/internal/control"
)

func main() {
	os.Exit(dispatch(os.Args[1:], os.Stdout, os.Stderr))
}

// dispatch picks the command: `run` starts the daemon, everything else is a
// control command (or a usage error) for runCLI.
func dispatch(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "run" {
		return runDaemon(args[1:], stderr)
	}
	return runCLI(args, stdout, stderr, cliDeps{
		Call:    func(req control.Request) (control.Response, error) { return control.Call(control.SocketPath, req) },
		Running: func() bool { return control.Running(control.SocketPath) },
		Now:     time.Now,
	})
}
