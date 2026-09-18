package logging

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// fileWriter is an append-only writer with optional size based rotation.
// Rotation renames path to path.1, path.1 to path.2 and so on, keeping
// maxFiles archives. Files are created with 0640 so that only the service
// user and its group can read logs, which may contain client data.
type fileWriter struct {
	mu       sync.Mutex
	path     string
	f        *os.File
	size     int64
	maxSize  int64
	maxFiles int
	// errs counts failed writes (disk full, revoked file); shared with the
	// Logs that owns the writer so the data plane can expose it.
	errs     *atomic.Uint64
	lastWarn time.Time
}

func newFileWriter(path string, maxSize int64, maxFiles int) (*fileWriter, error) {
	w := &fileWriter{path: path, maxSize: maxSize, maxFiles: maxFiles}
	if w.maxFiles <= 0 {
		w.maxFiles = 5
	}
	if err := w.open(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *fileWriter) open() error {
	f, err := os.OpenFile(w.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o640) //nolint:gosec // group-readable logs are intentional (see SECURITY.md)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	w.f = f
	w.size = st.Size()
	return nil
}

func (w *fileWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return 0, os.ErrClosed
	}
	if w.maxSize > 0 && w.size+int64(len(p)) > w.maxSize && w.size > 0 {
		if err := w.rotate(); err != nil {
			// Keep writing to the old file rather than losing events.
			fmt.Fprintf(os.Stderr, "xproxy: log rotation of %s failed: %v\n", w.path, err)
		}
	}
	n, err := w.f.Write(p)
	w.size += int64(n)
	if err != nil {
		if w.errs != nil {
			w.errs.Add(1)
		}
		// A full disk must never take the data plane down: the event is
		// dropped, counted, and reported to stderr at most once a minute.
		if now := time.Now(); now.Sub(w.lastWarn) > time.Minute {
			w.lastWarn = now
			fmt.Fprintf(os.Stderr, "xproxy: log write to %s failed: %v (events are being dropped)\n", w.path, err)
		}
	}
	return n, err
}

func (w *fileWriter) rotate() error {
	_ = w.f.Close()
	for i := w.maxFiles - 1; i >= 1; i-- {
		from := fmt.Sprintf("%s.%d", w.path, i)
		to := fmt.Sprintf("%s.%d", w.path, i+1)
		if _, err := os.Stat(from); err == nil {
			_ = os.Rename(from, to)
		}
	}
	if err := os.Rename(w.path, w.path+".1"); err != nil && !os.IsNotExist(err) {
		_ = w.open()
		return err
	}
	return w.open()
}

// Reopen closes and reopens the file (after external rotation).
func (w *fileWriter) Reopen() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f != nil {
		_ = w.f.Close()
	}
	return w.open()
}

func (w *fileWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return nil
	}
	err := w.f.Close()
	w.f = nil
	return err
}
