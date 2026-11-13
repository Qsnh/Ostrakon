package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/Qsnh/Ostrakon/internal/firewall"
	"github.com/Qsnh/Ostrakon/internal/jev"
	"github.com/Qsnh/Ostrakon/internal/judge"
	"github.com/Qsnh/Ostrakon/internal/setup"
	"github.com/Qsnh/Ostrakon/internal/source"
)

// validateTimeout bounds the key check against Jev.
const validateTimeout = 15 * time.Second

// runSetup is `ostrakon setup`: it runs the one-shot setup against env and
// returns the process exit code. setup's own output goes to env.Out.
func runSetup(args []string, stderr io.Writer, env setup.Env) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "usage: ostrakon setup")
		return exitUsage
	}
	if err := setup.Run(context.Background(), env); err != nil {
		fmt.Fprintf(stderr, "ostrakon setup: %v\n", err)
		return exitError
	}
	return exitOK
}

// systemSetupEnv is the setup environment of the real machine. It is wiring
// only; it has no side effects until setup.Run calls its functions.
func systemSetupEnv(out io.Writer) setup.Env {
	return setup.Env{
		Out:    out,
		Getenv: os.Getenv,
		ReadSecret: func(prompt string) (string, error) {
			return readSecret(out, os.Stdin, prompt)
		},
		Validate: func(ctx context.Context, key string) error {
			// An empty override means the default Jev URL.
			return validateKey(ctx, os.Getenv(jevURLEnv), key)
		},
		IsRoot:        func() bool { return os.Geteuid() == 0 },
		HaveNFT:       firewall.Available,
		Discover:      func() []source.Spec { return source.Discover(fileExists, haveJournalctl()) },
		MkdirAll:      os.MkdirAll,
		WriteFile:     writeFileAtomic,
		InstallBinary: installBinary,
		Systemctl:     func(args ...string) error { return runCommand("systemctl", args...) },
	}
}

// validateKey checks key with a ping to the Jev server at baseURL (the default
// server when empty). Errors never contain the key.
func validateKey(ctx context.Context, baseURL, key string) error {
	ctx, cancel := context.WithTimeout(ctx, validateTimeout)
	defer cancel()
	client := jev.New(baseURL, func() (string, error) { return key, nil })
	_, err := client.SystemOne(ctx, judge.PingRequest())
	return err
}

// readSecret prints prompt to out and reads the key from in without echo. If
// in is not a terminal (`echo KEY | sudo ostrakon setup`) it reads one line.
func readSecret(out io.Writer, in *os.File, prompt string) (string, error) {
	fmt.Fprint(out, prompt)
	defer fmt.Fprintln(out)

	if fd := int(in.Fd()); term.IsTerminal(fd) {
		b, err := term.ReadPassword(fd)
		return string(b), err
	}
	return readLine(in)
}

// readLine returns the first line of r without its line terminator. Input
// that ends before a terminator yields what was read, and none yields "".
func readLine(r io.Reader) (string, error) {
	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// installBinary copies the running executable to dst.
func installBinary(dst string) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("find the running executable: %w", err)
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return fmt.Errorf("find the running executable: %w", err)
	}
	return copyBinary(exe, dst)
}

// copyBinary replaces dst with a copy of src, mode 0755, unless src and dst
// are the same file. The replacement is atomic, so it is safe while the old
// binary is running.
func copyBinary(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	srcInfo, err := in.Stat()
	if err != nil {
		return err
	}
	if dstInfo, err := os.Stat(dst); err == nil && os.SameFile(srcInfo, dstInfo) {
		return nil
	}
	return replaceFile(dst, 0o755, func(w io.Writer) error {
		_, err := io.Copy(w, in)
		return err
	})
}

// writeFileAtomic replaces the file at path with data and gives it mode perm,
// even if it existed with another mode. The new file is complete and has its
// final mode before it appears under path.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	return replaceFile(path, perm, func(w io.Writer) error {
		_, err := w.Write(data)
		return err
	})
}

// replaceFile has write fill a new file next to path, then renames it over
// path. The temporary file is created exclusively and never wider than perm.
func replaceFile(path string, perm os.FileMode, write func(io.Writer) error) (err error) {
	tmp := path + ".tmp"
	_ = os.Remove(tmp) // a leftover of an earlier failed attempt
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			f.Close()
			os.Remove(tmp)
		}
	}()

	if err = write(f); err != nil {
		return err
	}
	if err = f.Chmod(perm); err != nil { // the umask may have narrowed it
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// runCommand runs name with args and, on failure, returns an error that
// includes the command's output.
func runCommand(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err == nil {
		return nil
	}
	cmdline := strings.Join(append([]string{name}, args...), " ")
	if msg := strings.TrimSpace(string(out)); msg != "" {
		return fmt.Errorf("%s: %w: %s", cmdline, err, msg)
	}
	return fmt.Errorf("%s: %w", cmdline, err)
}
