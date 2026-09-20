package safe

import (
	"strings"
	"sync"
	"testing"
)

func TestGuardContainsAPanicAndReportsIt(t *testing.T) {
	before := Panics()
	var mu sync.Mutex
	var what string
	var value any
	var stack string
	Report = func(w string, v any, s []byte) {
		mu.Lock()
		defer mu.Unlock()
		what, value, stack = w, v, string(s)
	}
	defer func() { Report = nil }()

	done := make(chan struct{})
	go func() {
		defer close(done)
		defer Guard("test flow")
		var p *int
		_ = *p // nil dereference on a flow goroutine
	}()
	<-done

	if got := Panics() - before; got != 1 {
		t.Fatalf("contained panics: %d", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if what != "test flow" {
		t.Fatalf("what: %q", what)
	}
	if value == nil {
		t.Fatal("the recovered value was not reported")
	}
	if !strings.Contains(stack, "safe.TestGuardContainsAPanicAndReportsIt") {
		t.Fatalf("the stack does not name the panicking goroutine:\n%s", stack)
	}
}

// A goroutine that returns normally must cost nothing and report nothing.
func TestGuardIsSilentWithoutAPanic(t *testing.T) {
	before := Panics()
	Report = func(string, any, []byte) { t.Error("a clean return was reported as a panic") }
	defer func() { Report = nil }()
	func() { defer Guard("test flow") }()
	if Panics() != before {
		t.Fatal("a clean return was counted")
	}
}

// A nil Report must still contain the panic: the counter is the only
// thing lost.
func TestGuardWithoutAReporter(t *testing.T) {
	Report = nil
	before := Panics()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer Guard("test flow")
		panic("boom")
	}()
	<-done
	if Panics()-before != 1 {
		t.Fatal("the panic was not counted")
	}
}
