package tlsconf

import (
	"container/list"
	"sync"
)

// FingerprintTable remembers the fingerprint of open connections by
// remote address so the request handler can look it up. It is bounded;
// entries are removed when the connection closes and evicted in FIFO
// order under pressure. Every entry sits in one list element so a delete
// frees its place in the order too: the earlier slice of keys grew by one
// entry per handshake for the life of the process.
type FingerprintTable struct {
	mu    sync.Mutex
	by    map[string]*list.Element
	order *list.List // front is the oldest
	max   int
}

type fpEntry struct {
	remote string
	fp     Fingerprint
}

// NewFingerprintTable creates a table bounded to max entries.
func NewFingerprintTable(max int) *FingerprintTable {
	return &FingerprintTable{by: make(map[string]*list.Element, 1024), order: list.New(), max: max}
}

// Put records the fingerprint of a connection.
func (t *FingerprintTable) Put(remote string, fp Fingerprint) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if el, ok := t.by[remote]; ok {
		el.Value.(*fpEntry).fp = fp
		return
	}
	for len(t.by) >= t.max && t.order.Len() > 0 {
		oldest := t.order.Front()
		delete(t.by, oldest.Value.(*fpEntry).remote)
		t.order.Remove(oldest)
	}
	t.by[remote] = t.order.PushBack(&fpEntry{remote: remote, fp: fp})
}

// Get returns the fingerprint of a connection.
func (t *FingerprintTable) Get(remote string) (Fingerprint, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if el, ok := t.by[remote]; ok {
		return el.Value.(*fpEntry).fp, true
	}
	return Fingerprint{}, false
}

// Delete forgets a closed connection.
func (t *FingerprintTable) Delete(remote string) {
	t.mu.Lock()
	if el, ok := t.by[remote]; ok {
		delete(t.by, remote)
		t.order.Remove(el)
	}
	t.mu.Unlock()
}

// Len returns the number of tracked connections.
func (t *FingerprintTable) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.by)
}

// orderLen is the length of the eviction order (tests: it must equal Len).
func (t *FingerprintTable) orderLen() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.order.Len()
}
