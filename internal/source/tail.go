package source

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"time"
)

const (
	// maxLineBytes caps the length of an emitted line; the rest of a longer
	// line is discarded. It also bounds the buffer a partial line can use.
	maxLineBytes = 16 << 10
	// readChunk is the size of each read from a file or pipe.
	readChunk = 32 << 10
)

// lineSplitter turns a byte stream into lines. It keeps at most maxLineBytes
// of the line being assembled, so a pathological line cannot grow memory.
type lineSplitter struct {
	buf []byte
}

// feed consumes data and calls emit for every complete, non-empty line, with
// the "\n" and one trailing "\r" removed. It returns false as soon as emit
// does, leaving the rest of data unconsumed.
func (s *lineSplitter) feed(data []byte, emit func(string) bool) bool {
	for len(data) > 0 {
		i := bytes.IndexByte(data, '\n')
		if i < 0 {
			s.add(data)
			return true
		}
		s.add(data[:i])
		data = data[i+1:]
		if !s.flush(emit) {
			return false
		}
	}
	return true
}

// add appends part of a line to the buffer, dropping whatever exceeds the cap.
func (s *lineSplitter) add(b []byte) {
	if room := maxLineBytes - len(s.buf); room > 0 {
		s.buf = append(s.buf, b[:min(len(b), room)]...)
	}
}

// flush emits the buffered line, complete or not, and clears the buffer.
func (s *lineSplitter) flush(emit func(string) bool) bool {
	line := bytes.TrimSuffix(s.buf, []byte{'\r'})
	s.buf = s.buf[:0]
	if len(line) == 0 {
		return true
	}
	return emit(string(line))
}

// discard drops the buffered partial line without emitting it.
func (s *lineSplitter) discard() { s.buf = s.buf[:0] }

// errStopped is what a poll returns when emit gave up because ctx is done.
var errStopped = errors.New("source: stopped")

// TailFile follows the file at path and sends each new line to out, without
// its line terminator. It starts at the end of the file if it exists, and at
// the beginning of the file once it appears otherwise. It copes with log
// rotation: if path comes to name a different file (rename and recreate, or
// delete and recreate later) the old file is read to its end and the new one
// is read from the start; if the file shrinks (copytruncate) it is read again
// from the start. Lines are cut at 16 KiB.
//
// File errors never end the tail: a missing or unreadable file is retried
// every poll. TailFile logs nothing and returns ctx.Err() once ctx is done,
// which is the only way it returns.
func TailFile(ctx context.Context, path string, poll time.Duration, out chan<- string) error {
	return tailFile(ctx, path, poll, out, nil)
}

// tailFile is TailFile with a hook for problems. When onErr is non-nil it is
// called, on the tailing goroutine, as the file's health changes and not on
// every poll: with a non-nil error when a problem first appears or becomes a
// different one, and with nil once when the problem is gone. A file that does
// not exist yet is reported (as an error wrapping fs.ErrNotExist) like any
// other problem; the caller decides how loudly to say so.
func tailFile(ctx context.Context, path string, poll time.Duration, out chan<- string, onErr func(error)) error {
	if poll <= 0 {
		poll = filePoll
	}
	t := &tailer{path: path, seekEnd: true, onErr: onErr}
	emit := func(s string) bool {
		select {
		case out <- s:
			return true
		case <-ctx.Done():
			return false
		}
	}
	defer func() {
		if t.cur != nil {
			_ = t.cur.Close()
		}
	}()

	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	for {
		if err := t.poll(emit); !errors.Is(err, errStopped) {
			t.report(err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// tailer is the state of one tailFile: the open file, how far it has been
// read, the line being assembled, and the last problem reported.
type tailer struct {
	path string
	cur  *os.File // nil until the path can be opened
	off  int64    // bytes of cur consumed so far
	ls   lineSplitter

	// seekEnd is true until the first file is opened (or found missing): a
	// file that is there when the tail starts is followed from its end, even
	// if it only becomes readable later. One that shows up afterwards is
	// read from the start, so none of its lines are missed.
	seekEnd bool

	onErr   func(error)
	failed  bool
	lastErr string
}

// report tells onErr about a change in health: err is the outcome of the last
// poll, nil when it went fine.
func (t *tailer) report(err error) {
	if t.onErr == nil {
		return
	}
	switch {
	case err == nil && t.failed:
		t.failed, t.lastErr = false, ""
		t.onErr(nil)
	case err != nil && (!t.failed || t.lastErr != err.Error()):
		t.failed, t.lastErr = true, err.Error()
		t.onErr(err)
	}
}

// poll does one round: pick up rotation, then read what is new. It returns
// errStopped if emit gave up (ctx done), another error if the file could not
// be opened, statted or read, and nil otherwise. Errors are not fatal: the
// next poll tries again.
func (t *tailer) poll(emit func(string) bool) error {
	if t.cur == nil {
		return t.open(emit)
	}

	curInfo, err := t.cur.Stat()
	if err != nil {
		return err
	}
	// A path that cannot be statted is not a reason to leave the file we
	// have open; keep reading it. A path that is simply gone is the normal
	// gap in a delete-and-recreate rotation; any other failure is reported
	// once the open file has been read.
	pathInfo, pathErr := os.Stat(t.path)
	rotated := pathErr == nil && !os.SameFile(curInfo, pathInfo)
	if errors.Is(pathErr, fs.ErrNotExist) {
		pathErr = nil
	}

	if !rotated && curInfo.Size() < t.off {
		// Truncated in place. The old content is gone, and so is any
		// partial line of it.
		if _, err := t.cur.Seek(0, io.SeekStart); err != nil {
			return err
		}
		t.off = 0
		t.ls.discard()
	}
	if err := t.readToEOF(emit); err != nil {
		return err
	}
	if rotated {
		return t.open(emit)
	}
	return pathErr
}

// open opens the file now at t.path. The very first open follows it from its
// end (see seekEnd); a later one switches to it and reads it from the start,
// after emitting any partial last line of the file being left. If the path
// cannot be opened, nothing changes and the next poll tries again.
func (t *tailer) open(emit func(string) bool) error {
	f, err := os.Open(t.path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			t.seekEnd = false
		}
		return err
	}
	if t.seekEnd {
		off, err := f.Seek(0, io.SeekEnd)
		if err != nil {
			_ = f.Close()
			return err
		}
		t.seekEnd = false
		t.cur, t.off = f, off
		return nil
	}
	if t.cur != nil {
		_ = t.cur.Close()
		if !t.ls.flush(emit) {
			_ = f.Close()
			return errStopped
		}
	}
	t.cur, t.off = f, 0
	return t.readToEOF(emit)
}

// readToEOF emits every complete line from the current position to the end
// of t.cur. It returns errStopped if emit asked to stop, and any read error.
func (t *tailer) readToEOF(emit func(string) bool) error {
	chunk := make([]byte, readChunk)
	for {
		n, err := t.cur.Read(chunk)
		t.off += int64(n)
		if !t.ls.feed(chunk[:n], emit) {
			return errStopped
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}
