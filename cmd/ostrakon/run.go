package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/Qsnh/Ostrakon/internal/allowlist"
	"github.com/Qsnh/Ostrakon/internal/apikey"
	"github.com/Qsnh/Ostrakon/internal/control"
	"github.com/Qsnh/Ostrakon/internal/daemon"
	"github.com/Qsnh/Ostrakon/internal/firewall"
	"github.com/Qsnh/Ostrakon/internal/health"
	"github.com/Qsnh/Ostrakon/internal/jev"
	"github.com/Qsnh/Ostrakon/internal/judge"
	"github.com/Qsnh/Ostrakon/internal/logging"
	"github.com/Qsnh/Ostrakon/internal/notify"
	"github.com/Qsnh/Ostrakon/internal/source"
	"github.com/Qsnh/Ostrakon/internal/state"
)

// jevURLEnv overrides the Jev base URL. It exists for tests and is not
// documented to users.
const jevURLEnv = "OSTRAKON_JEV_URL"

// runDaemon is `ostrakon run [--dry-run]`: it builds the daemon from the real
// system and runs it, together with the control socket, until SIGINT or
// SIGTERM. It returns the process exit code. It is wiring only; everything
// with logic in it lives in the packages it assembles.
func runDaemon(args []string, stderr io.Writer) int {
	fl := flag.NewFlagSet("ostrakon run", flag.ContinueOnError)
	fl.SetOutput(stderr)
	dryRun := fl.Bool("dry-run", false, "log ban decisions instead of banning")
	if err := fl.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if fl.NArg() != 0 {
		fmt.Fprintln(stderr, "usage: ostrakon run [--dry-run]")
		return exitUsage
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(stderr, "ostrakon: run must be started as root (it manages the nftables firewall)")
		return exitError
	}

	// Under systemd, JOURNAL_STREAM is set and each line carries its
	// priority, so that `journalctl -p err` shows a pause.
	log := slog.New(logging.NewHandler(stderr, os.Getenv("JOURNAL_STREAM") != ""))
	slog.SetDefault(log)

	store, err := state.Open(state.DefaultPath, time.Now())
	if err != nil {
		log.Error("cannot open the state file", "err", err)
		return exitError
	}
	if kept := store.Recovered(); kept != "" {
		log.Error("the state file was damaged and has been reset: active bans, ban history AND allowlist entries are lost "+
			"(re-add yours with `ostrakon allow`); the damaged file was kept for inspection",
			"kept_at", kept)
	}

	keyLoader := apikey.Loader()
	base := os.Getenv(jevURLEnv)
	if base == "" {
		base = jev.DefaultBaseURL
	}
	client := jev.New(base, keyLoader)

	monitor := health.NewMonitor(time.Now, notify.Noop{}, log)
	if _, err := keyLoader(); err != nil {
		// Without a key every decision would fail. Start paused; the prober
		// re-reads the key and ends the pause once one is in place.
		monitor.Pause("no API key: " + err.Error())
	}

	specs := source.Discover(fileExists, haveJournalctl())

	d := daemon.New(daemon.Deps{
		Specs:    specs,
		Firewall: &firewall.NFT{Run: firewall.ExecRunner, Cmd: firewall.ExecCmd},
		Decider:  &judge.Judge{Client: client, Threshold: judge.DefaultThreshold},
		Ping: func(ctx context.Context) error {
			_, err := client.SystemOne(ctx, judge.PingRequest())
			return err
		},
		Store:    store,
		Allow:    allowlist.New(),
		Monitor:  monitor,
		Sleep:    health.RealSleep,
		Now:      time.Now,
		DryRun:   *dryRun,
		Log:      log,
		Sessions: func() ([]netip.Addr, error) { return allowlist.ReadUTMP(allowlist.UTMPPath) },
		Local:    allowlist.LocalAddrs,
	})

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	err = runTogether(ctx,
		func(ctx context.Context) error { return control.Serve(ctx, control.SocketPath, d) },
		d.Run,
	)
	if err != nil {
		log.Error("ostrakon stopped because of an error", "err", err)
		return exitError
	}
	return exitOK
}

// runTogether runs fns concurrently, each with a context that is cancelled
// when ctx is, or as soon as any of them returns (a daemon whose control
// socket or pipeline has died must not carry on half alive). It waits for all
// of them and returns their errors joined.
func runTogether(ctx context.Context, fns ...func(context.Context) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	errs := make([]error, len(fns))
	var wg sync.WaitGroup
	for i, fn := range fns {
		wg.Go(func() {
			errs[i] = fn(ctx)
			cancel()
		})
	}
	wg.Wait()
	return errors.Join(errs...)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func haveJournalctl() bool {
	_, err := exec.LookPath("journalctl")
	return err == nil
}
