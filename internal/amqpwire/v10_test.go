package amqpwire

import (
	"reflect"
	"strings"
	"testing"
)

func TestTheTenPerformativesAreRead(t *testing.T) {
	// open: the container, the virtual host and the three bounds.
	p, err := ParsePerformative(perf10(uint8(PerfOpen), str10("client-1"), str10("/orders"),
		uint10(131072), []byte{0x60, 0x07, 0xff}, uint10(30000)))
	if err != nil {
		t.Fatal(err)
	}
	if p.Name() != "open" || !p.Known() {
		t.Fatalf("performative = %q", p.Name())
	}
	container, host, frame, channels, idle, ok := p.Open()
	if !ok || container != "client-1" || host != "/orders" || frame != 131072 || channels != 2047 || idle != 30000 {
		t.Errorf("open = %q, %q, %d, %d, %d, %v", container, host, frame, channels, idle, ok)
	}

	// attach: which way the link goes, and the address at each end.
	p, err = ParsePerformative(perf10(uint8(PerfAttach), str10("sender-link"), uint10(3),
		bool10(false), null10(), null10(), source10("", false), target10("/exchange/events/orders.created", false)))
	if err != nil {
		t.Fatal(err)
	}
	name, handle, role, source, target, ok := p.Attach()
	if !ok || name != "sender-link" || handle != 3 || role != RoleSender {
		t.Errorf("attach = %q, %d, %q, %v", name, handle, role, ok)
	}
	if source != "" || target != "/exchange/events/orders.created" {
		t.Errorf("addresses = %q, %q", source, target)
	}

	// A receiver attaches the other way round, and its address is the
	// source.
	p, _ = ParsePerformative(perf10(uint8(PerfAttach), str10("receiver-link"), uint10(4),
		bool10(true), null10(), null10(), source10("/queue/work", false), target10("", true)))
	_, _, role, source, _, _ = p.Attach()
	if role != RoleReceiver || source != "/queue/work" {
		t.Errorf("receiver attach = %q, %q", role, source)
	}
	// And a dynamic link asks the broker to make the node rather than
	// naming one, which is how a reply address is created on this version.
	if _, dynTarget := p.Dynamic(); !dynTarget {
		t.Error("a dynamic target was not read as dynamic")
	}

	// transfer: the link handle, and whether the message is finished.
	p, _ = ParsePerformative(perf10(uint8(PerfTransfer), uint10(3), uint10(9), bin10([]byte{1}),
		uint10(0), bool10(false), bool10(true)))
	handle, delivery, settled, more, aborted, ok := p.Transfer()
	if !ok || handle != 3 || delivery != 9 || settled || !more || aborted {
		t.Errorf("transfer = %d, %d, %v, %v, %v, %v", handle, delivery, settled, more, aborted, ok)
	}
	if h, ok := p.Handle(); !ok || h != 3 {
		t.Errorf("handle = %d, %v", h, ok)
	}

	// flow about the session names no link, and a relay must not read the
	// absence as handle zero.
	p, _ = ParsePerformative(perf10(uint8(PerfFlow), uint10(1), uint10(100), uint10(2), uint10(100)))
	if _, ok := p.Handle(); ok {
		t.Error("a session flow was read as naming a link")
	}
	p, _ = ParsePerformative(perf10(uint8(PerfFlow), uint10(1), uint10(100), uint10(2), uint10(100), uint10(7)))
	if h, ok := p.Handle(); !ok || h != 7 {
		t.Errorf("a link flow named %d, %v", h, ok)
	}

	// detach and close: the reason something ended.
	errored := described10(0x1d, list10(sym10("amqp:unauthorized-access"), str10("access to node denied")))
	p, _ = ParsePerformative(perf10(uint8(PerfDetach), uint10(3), bool10(true), errored))
	cond, desc, ok := p.CloseError()
	if !ok || cond != "amqp:unauthorized-access" || !strings.Contains(desc, "denied") {
		t.Errorf("detach error = %q, %q, %v", cond, desc, ok)
	}
	p, _ = ParsePerformative(perf10(uint8(PerfClose), errored))
	if cond, _, ok := p.CloseError(); !ok || cond != "amqp:unauthorized-access" {
		t.Errorf("close error = %q, %v", cond, ok)
	}
}

func TestTheSASLLayerIsRead(t *testing.T) {
	// The broker's offer, as an array of symbols and as a single one --
	// both forms are in use.
	p, err := ParsePerformative(perf10(uint8(PerfSASLMechanisms),
		array10(0xa3, join([]byte{4}, []byte("PLAIN")[:4]), join([]byte{8}, []byte("EXTERNAL")))))
	if err != nil {
		t.Fatal(err)
	}
	if !p.SASL() {
		t.Error("sasl-mechanisms was not read as a SASL performative")
	}
	got, ok := p.SASLMechanisms()
	if !ok || !reflect.DeepEqual(got, []string{"PLAI", "EXTERNAL"}) {
		t.Errorf("mechanisms = %v, %v", got, ok)
	}
	p, _ = ParsePerformative(perf10(uint8(PerfSASLMechanisms), sym10("ANONYMOUS")))
	if got, ok := p.SASLMechanisms(); !ok || !reflect.DeepEqual(got, []string{"ANONYMOUS"}) {
		t.Errorf("one mechanism = %v, %v", got, ok)
	}

	// The client's choice, and the identity in it -- never the password.
	p, _ = ParsePerformative(perf10(uint8(PerfSASLInit), sym10("PLAIN"),
		bin10([]byte("\x00orders\x00hunter2")), str10("/orders")))
	mech, user, host, ok := p.SASLInit()
	if !ok || mech != "PLAIN" || user != "orders" || host != "/orders" {
		t.Errorf("sasl-init = %q, %q, %q, %v", mech, user, host, ok)
	}

	// The broker's verdict, which is the only thing that says a connection
	// authenticated.
	p, _ = ParsePerformative(perf10(uint8(PerfSASLOutcome), smalluint(0)))
	if code, ok := p.SASLOutcome(); !ok || code != 0 {
		t.Errorf("outcome = %d, %v", code, ok)
	}
	p, _ = ParsePerformative(perf10(uint8(PerfSASLOutcome), smalluint(1), bin10([]byte("no"))))
	if code, ok := p.SASLOutcome(); !ok || code != 1 {
		t.Errorf("a refusal read as %d, %v", code, ok)
	}
	// An outcome with no code at all is not an outcome: a relay that read
	// it as zero would mark the connection authenticated on a frame that
	// said nothing.
	p, _ = ParsePerformative(perf10(uint8(PerfSASLOutcome), null10()))
	if _, ok := p.SASLOutcome(); ok {
		t.Error("an outcome with no code was read as one")
	}
}

// A descriptor may be written as a symbol instead of a code, and both mean
// the same performative.
func TestADescriptorWrittenAsASymbolIsTheSamePerformative(t *testing.T) {
	body := join([]byte{0x00}, sym10("amqp:open:list"),
		list10(str10("client-1"), str10("/orders")))
	p, err := ParsePerformative(body)
	if err != nil {
		t.Fatal(err)
	}
	if p.Code != PerfOpen || p.Name() != "open" {
		t.Errorf("performative = %#x %q", p.Code, p.Name())
	}
	if _, host, _, _, _, ok := p.Open(); !ok || host != "/orders" {
		t.Errorf("open = %q, %v", host, ok)
	}
}

func TestAFrameBodyThatIsNotAPerformativeIsRefused(t *testing.T) {
	for _, c := range []struct {
		name string
		b    []byte
		want string
	}{
		{"empty", nil, "empty frame body"},
		{"not described", list10(str10("x")), "not a described type"},
		{"fields that are not a list", described10(0x10, str10("x")), "not a list"},
		{"a truncated string", join([]byte{0x00, 0x53, 0x10}, []byte{0xa1, 40}, []byte("short")), "past the end"},
		{"a list longer than its frame", join([]byte{0x00, 0x53, 0x10}, []byte{0xc0, 40, 2}, []byte{0x40}), "past the end"},
	} {
		if _, err := ParsePerformative(c.b); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
	// A performative nobody has heard of is unknown rather than guessed at.
	p, err := ParsePerformative(perf10(0x77, str10("x")))
	if err != nil {
		t.Fatal(err)
	}
	if p.Known() {
		t.Error("descriptor 0x77 is in the catalogue")
	}
	if _, _, _, _, _, ok := p.Open(); ok {
		t.Error("an unknown performative answered as an open")
	}
}

// The type reader's bounds, which are the reason a hostile frame is a
// refusal rather than an outage.
func TestTheTypeReaderIsBounded(t *testing.T) {
	// Nesting: lists inside lists, past the depth bound.
	deep := list10(str10("leaf"))
	for i := 0; i < maxValueDepth+4; i++ {
		deep = list10(deep)
	}
	if _, err := ParsePerformative(described10(0x10, deep)); err == nil {
		t.Error("a value nested past the bound was read")
	}

	// A count that is not there. The count is four octets from the
	// network; a reader that allocated for it would take whatever a
	// twelve-octet frame asked for.
	body := join([]byte{0x00, 0x53, 0x10}, []byte{0xd0}, be32b(8), be32b(0xffffffff), []byte{0x40, 0x40, 0x40, 0x40})
	p, err := ParsePerformative(body)
	if err != nil {
		t.Fatalf("a list with an impossible count: %v", err)
	}
	if len(p.Fields) > 4 {
		t.Errorf("a count of four billion produced %d fields", len(p.Fields))
	}

	// And the value budget stops a frame that describes more values than
	// it has octets for.
	many := make([][][]byte, 0, maxValues+10)
	for i := 0; i < maxValues+10; i++ {
		many = append(many, [][]byte{null10()})
	}
	if _, err := ParsePerformative(described10(0x10, bigList10(many...))); err == nil {
		t.Error("a frame over the value budget was read")
	}
}

// Absent and zero are different answers, and a relay that confused them
// would report a bound nobody set.
func TestAnAbsentFieldIsNotZero(t *testing.T) {
	p, err := ParsePerformative(perf10(uint8(PerfOpen), str10("client-1")))
	if err != nil {
		t.Fatal(err)
	}
	if v, had := field(p.Fields, 2).Uint(); had {
		t.Errorf("an absent max-frame-size read as %d", v)
	}
	if field(p.Fields, 2).Present() {
		t.Error("an absent field reported itself present")
	}
	p, _ = ParsePerformative(perf10(uint8(PerfOpen), str10("c"), null10(), uint10(0)))
	if v, had := field(p.Fields, 2).Uint(); !had || v != 0 {
		t.Errorf("a max-frame-size of zero read as %d, %v", v, had)
	}
	if field(p.Fields, 1).Present() {
		t.Error("an explicit null reported itself present")
	}
}

// The address forms the brokers that serve both versions use, so one
// exchange and queue policy covers 0-9-1 and 1.0 rather than an operator
// writing the same boundary twice.
func TestALinkAddressIsReadIntoTheNounsAPolicyUses(t *testing.T) {
	for _, c := range []struct {
		addr string
		want []Target
	}{
		{"/exchange/events/orders.created", []Target{
			{KindAddress, "/exchange/events/orders.created"},
			{KindExchange, "events"},
			{KindRoutingKey, "orders.created"}}},
		{"/exchange/events", []Target{
			{KindAddress, "/exchange/events"}, {KindExchange, "events"}}},
		{"/queue/work", []Target{
			{KindAddress, "/queue/work"}, {KindQueue, "work"}}},
		{"/amq/queue/work", []Target{
			{KindAddress, "/amq/queue/work"}, {KindQueue, "work"}}},
		{"/topic/orders.created", []Target{
			{KindAddress, "/topic/orders.created"},
			{KindExchange, "amq.topic"}, {KindRoutingKey, "orders.created"}}},
		// A bare node name is what Azure Service Bus and Qpid use. It is
		// the address and nothing more, which is the honest reading:
		// inventing an exchange for it would put a policy on a name the
		// broker never sees.
		{"orders-queue", []Target{{KindAddress, "orders-queue"}}},
		{"$management", []Target{{KindAddress, "$management"}}},
		{"", []Target{{KindAddress, ""}}},
	} {
		got := SplitAddress(c.addr)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%q = %+v, want %+v", c.addr, got, c.want)
		}
	}
}

func TestThePerformativeCatalogueIsConsistent(t *testing.T) {
	for _, n := range Performatives() {
		c, ok := PerformativeCode(n)
		if !ok {
			t.Errorf("%q is listed and not found", n)
			continue
		}
		p := &Performative{Code: c}
		if p.Name() != n {
			t.Errorf("%#x is named %q and %q", c, n, p.Name())
		}
		if !p.Known() {
			t.Errorf("%q is listed and not known", n)
		}
		// The SASL performatives are the ones that travel in the SASL
		// frame type, and nothing else is.
		wantSASL := strings.HasPrefix(n, "sasl-")
		if p.SASL() != wantSASL {
			t.Errorf("%q: SASL = %v, want %v", n, p.SASL(), wantSASL)
		}
	}
	if _, ok := PerformativeCode("not-a-performative"); ok {
		t.Error("a name nobody defines has a code")
	}
}
