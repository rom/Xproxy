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
	SetReport(func(w string, v any, s []byte) {
		mu.Lock()
		defer mu.Unlock()
		what, value, stack = w, v, string(s)
	})
	defer SetReport(nil)

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
	SetReport(func(string, any, []byte) { t.Error("a clean return was reported as a panic") })
	defer SetReport(nil)
	func() { defer Guard("test flow") }()
	if Panics() != before {
		t.Fatal("a clean return was counted")
	}
}

// No reporter must still contain the panic: the detail is the only thing
// lost.
func TestGuardWithoutAReporter(t *testing.T) {
	SetReport(nil)
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

// The sink is installed while flow goroutines are running, because a
// reload builds a second Server while the first is still serving. Under
// the race detector this is what says the pointer is not torn: a plain
// package variable fails it, which is how the race was found -- by a test
// that started two listeners at once.
func TestSetReportDoesNotRaceAContainedPanic(t *testing.T) {
	defer SetReport(nil)
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			SetReport(func(string, any, []byte) {})
		}
	}()
	for i := 0; i < 200; i++ {
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer Guard("test flow")
			panic("boom")
		}()
		<-done
	}
	close(stop)
	wg.Wait()
}
