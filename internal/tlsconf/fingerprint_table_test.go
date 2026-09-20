package tlsconf

import "testing"

// TestFingerprintTableNoLeak: deleting a closed connection frees its place
// in the eviction order too; the earlier key slice grew by one entry per
// handshake for the life of the process.
func TestFingerprintTableNoLeak(t *testing.T) {
	tab := NewFingerprintTable(8)
	for i := 0; i < 100000; i++ {
		tab.Put("c", Fingerprint{JA4: "x"})
		tab.Delete("c")
	}
	if tab.Len() != 0 || tab.orderLen() != 0 {
		t.Fatalf("leak: len %d order %d", tab.Len(), tab.orderLen())
	}
	// Without deletes (QUIC, DoT) the table stays at its bound and the
	// oldest goes first.
	for i := 0; i < 20; i++ {
		tab.Put(string(rune('a'+i)), Fingerprint{})
	}
	if tab.Len() != 8 || tab.orderLen() != 8 {
		t.Fatalf("bound: len %d order %d", tab.Len(), tab.orderLen())
	}
	if _, ok := tab.Get("a"); ok {
		t.Fatal("oldest kept")
	}
	if _, ok := tab.Get("t"); !ok {
		t.Fatal("newest evicted")
	}
	// Updating an entry keeps one slot.
	tab.Put("t", Fingerprint{JA4: "y"})
	if fp, _ := tab.Get("t"); fp.JA4 != "y" || tab.orderLen() != 8 {
		t.Fatal("update duplicated the entry")
	}
}
