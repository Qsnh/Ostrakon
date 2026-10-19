package source

import (
	"bytes"
	"context"
	"io"
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
	if poll <= 0 {
		poll = filePoll
	}
	t := &tailer{path: path}
	emit := func(s string) bool {
		select {
		case out <- s:
			return true
		case <-ctx.Done():
			return false
		}
	}

	// A file that exists now is followed from its end; one that shows up
	// later is read from the start, so no line written to it is missed.
	if f, err := os.Open(path); err == nil {
		if off, err := f.Seek(0, io.SeekEnd); err == nil {
			t.cur, t.off = f, off
		} else {
			_ = f.Close()
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
		t.poll(emit)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// tailer is the state of one TailFile: the open file, how far it has been
// read, and the line being assembled.
type tailer struct {
	path string
	cur  *os.File // nil until the path can be opened
	off  int64    // bytes of cur consumed so far
	ls   lineSplitter
}

// poll does one round: pick up rotation, then read what is new. emit
// returning false (ctx done) just ends the round early.
func (t *tailer) poll(emit func(string) bool) {
	if t.cur == nil {
		t.open(emit)
		return
	}

	curInfo, err := t.cur.Stat()
	if err != nil {
		return
	}
	// A path that cannot be statted (removed, or permission denied) is not a
	// reason to leave the file we have open; keep reading it.
	pathInfo, err := os.Stat(t.path)
	rotated := err == nil && !os.SameFile(curInfo, pathInfo)

	if !rotated && curInfo.Size() < t.off {
		// Truncated in place. The old content is gone, and so is any
		// partial line of it.
		if _, err := t.cur.Seek(0, io.SeekStart); err != nil {
			return
		}
		t.off = 0
		t.ls.discard()
	}
	if !t.readToEOF(emit) {
		return
	}
	if rotated {
		t.open(emit)
	}
}

// open switches to the file now at t.path, reading it from the start. A
// partial last line of the file being left is emitted as-is first. If the
// path cannot be opened, nothing changes and the next poll tries again.
func (t *tailer) open(emit func(string) bool) {
	f, err := os.Open(t.path)
	if err != nil {
		return
	}
	if t.cur != nil {
		_ = t.cur.Close()
		if !t.ls.flush(emit) {
			_ = f.Close()
			return
		}
	}
	t.cur, t.off = f, 0
	t.readToEOF(emit)
}

// readToEOF emits every complete line from the current position to the end
// of t.cur. It returns false if emit asked to stop.
func (t *tailer) readToEOF(emit func(string) bool) bool {
	chunk := make([]byte, readChunk)
	for {
		n, err := t.cur.Read(chunk)
		t.off += int64(n)
		if !t.ls.feed(chunk[:n], emit) {
			return false
		}
		if err != nil {
			// io.EOF: caught up. Anything else is retried next poll.
			return true
		}
	}
}
