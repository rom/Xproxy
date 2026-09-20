package dns

import (
	"encoding/binary"
	"testing"
)

// query builds a question with the labels given, exactly as they are, so
// a test can put a byte in a label that no encoder would produce.
func query(labels ...string) []byte {
	m := make([]byte, 0, 64)
	m = binary.BigEndian.AppendUint16(m, 0x1234)
	m = binary.BigEndian.AppendUint16(m, 0x0100)
	m = binary.BigEndian.AppendUint16(m, 1)
	m = binary.BigEndian.AppendUint16(m, 0)
	m = binary.BigEndian.AppendUint16(m, 0)
	m = binary.BigEndian.AppendUint16(m, 0)
	for _, l := range labels {
		m = append(m, byte(len(l))) //nolint:gosec // test labels are short
		m = append(m, l...)
	}
	m = append(m, 0)
	m = binary.BigEndian.AppendUint16(m, TypeA)
	m = binary.BigEndian.AppendUint16(m, ClassIN)
	return m
}

// A name becomes a string the moment it is parsed, and that string is
// the block list key, the cache key, the name DNSSEC compares and the
// value written to the security log. Labels are joined with ".", which
// is only reversible while no label contains one: [www.bank][test] and
// [www][bank][test] are different names that used to produce the same
// string, so one would be served from the other's cache entry and would
// satisfy the other's DNSSEC binding.
func TestLabelWithADotIsRefused(t *testing.T) {
	if _, _, err := ParseQuestion(query("www.bank", "test")); err == nil {
		t.Fatal("a label containing a dot was accepted, so two wire names share one key")
	}
	q, _, err := ParseQuestion(query("www", "bank", "test"))
	if err != nil || q.Name != "www.bank.test" {
		t.Fatalf("the ordinary spelling broke: %q %v", q.Name, err)
	}
}

// A control byte in a label reaches the security log, where a newline
// ends the record and lets an unauthenticated client write the line
// after it.
func TestControlBytesInALabelAreRefused(t *testing.T) {
	for _, label := range []string{"a\x00b", "a\nb", "a\rb", "a b", "a\x1bb", "a\\b", "a\x7fb"} {
		if _, _, err := ParseQuestion(query(label, "test")); err == nil {
			t.Errorf("label %q was accepted into a name", label)
		}
	}
	// Everything a real name uses still parses.
	for _, label := range []string{"www", "_dmarc", "xn--bcher-kva", "a-b", "A1"} {
		if _, _, err := ParseQuestion(query(label, "test")); err != nil {
			t.Errorf("ordinary label %q was refused: %v", label, err)
		}
	}
}
