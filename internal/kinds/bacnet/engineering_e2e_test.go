package bacnet

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/access"

	wire "github.com/rom/xproxy/internal/bacnet"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
)

// bacnetWith starts a relay with its own top-level sections: the access
// ledger a grant is written in sits outside the listener.
func bacnetWith(t *testing.T, section, top, deviceAddr string) (*proxy.Server, string) {
	t.Helper()
	s := proxytest.Start(t, fmt.Sprintf(`
version: 1
%s
server:
  listeners:
    - name: plant
      address: "127.0.0.1:0"
      kind: bacnet
      bacnet:
%s
logging: {access: {enabled: false}}
upstreams:
  - {name: devices, endpoints: [{address: %q}]}
`, top, section, deviceAddr))
	return s, proxytest.Addr(t, s, "plant")
}

// reinitReq is ReinitializeDevice, a controller told to restart.
func reinitReq(invoke uint8) []byte {
	body := []byte{0x01, 0x04, 0x00, 0x05, invoke, wire.ReinitializeDevice, 0x09, 0x00}
	return bvlcWrap(wire.FuncOriginalUnicast, body)
}

// dccReq is DeviceCommunicationControl with DISABLE, a controller told to
// stop talking to the head end.
func dccReq(invoke uint8) []byte {
	body := []byte{0x01, 0x04, 0x00, 0x05, invoke, wire.DeviceCommunicationControl, 0x19, 0x01}
	return bvlcWrap(wire.FuncOriginalUnicast, body)
}

func awaitStats(t *testing.T, s *proxy.Server, what string, ok func(proxy.Snapshot) bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if ok(s.Stats()) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s: %+v", what, s.Stats().Refusals["bacnet"])
}

// The two BACnet services a building's own tooling and an intruder use
// for the same reason.
//
// A controller told to stop communicating is a controller the head end
// cannot see, and the operator finds out from the alarm that never
// arrives; a controller told to restart drops every schedule and
// override it was holding. Both are engineering rather than control, so
// both go through the ledger: with no grant open they are refused, and
// the operation is recorded either way because that is the record an
// audit asks for.
func TestTheTwoEngineeringServicesNeedAGrant(t *testing.T) {
	const section = `        upstream: devices
        allow_clients: [127.0.0.0/8]
        default_action: allow
        services: [readProperty, writeProperty, reinitializeDevice, deviceCommunicationControl]
        engineering:
          require_grant: true`
	for _, tc := range []struct {
		name  string
		raw   []byte
		class string
	}{
		{"a restart", reinitReq(1), "restart"},
		{"a controller told to stop talking", dccReq(2), "mode_change"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := startDevice(t, &device{})
			ledger := filepath.Join(t.TempDir(), "access.jsonl")
			top := fmt.Sprintf("access:\n  ledger: %q\n  approvals: 1\n  max_duration: 2h", ledger)
			s, addr := bacnetWith(t, section, top, d.addr())

			cl := dialClient(t, addr)
			cl.send(t, tc.raw)
			awaitStats(t, s, "the refusal and the engineering event", func(sn proxy.Snapshot) bool {
				return sn.Refusals["bacnet"]["engineering_no_grant"] >= 1 &&
					sn.EngineeringOps["bacnet/"+tc.class] >= 1
			})
			if got := d.seen(); len(got) != 0 {
				t.Errorf("%d messages reached the controller", len(got))
			}
		})
	}
}

// With the ledger not asked for, the same operation is carried and still
// recorded: the event class is what an estate reports on, and it is not
// a refusal.
func TestAnEngineeringOperationIsRecordedEvenWhenItIsCarried(t *testing.T) {
	d := startDevice(t, &device{})
	s, addr := bacnetWith(t, `        upstream: devices
        allow_clients: [127.0.0.0/8]
        default_action: allow
        services: [readProperty, reinitializeDevice]
        engineering: {}`, "", d.addr())

	cl := dialClient(t, addr)
	cl.send(t, reinitReq(3))
	awaitStats(t, s, "the engineering event", func(sn proxy.Snapshot) bool {
		return sn.EngineeringOps["bacnet/restart"] >= 1
	})
	if n := s.Stats().Refusals["bacnet"]["engineering_no_grant"]; n != 0 {
		t.Errorf("it was refused anyway: %d", n)
	}
	d.waitFor(t, 1, "the restart to reach the controller")
}

// The anomaly models, which notice a client doing what no rule named.
// On a building network the rules are written about objects and
// services; what they cannot say is "this client has never done this
// before", and that is the sentence an intruder's first message makes
// true.
func TestTheAnomalyModelsSeeTheServiceAndTheObject(t *testing.T) {
	d := startDevice(t, &device{})
	s, addr := bacnetWith(t, `        upstream: devices
        allow_clients: [127.0.0.0/8]
        default_action: allow
        services: [readProperty, writeProperty]
        anomaly:
          enabled: true
          settle: 0s`, "", d.addr())

	cl := dialClient(t, addr)
	cl.send(t, writeReq(4, wire.ObjectID{Type: wire.AnalogOutput, Instance: 3}, wire.PropPresentValue, 0))
	awaitStats(t, s, "the models to report something", func(sn proxy.Snapshot) bool {
		return len(sn.Refusals["bacnet"]) > 0
	})
}

// A grant somebody else approved carries the operation, and the record
// says which grant it was. That is the whole of just-in-time access on a
// building network: the engineer's restart is not refused, it is
// attributable.
func TestAnApprovedGrantCarriesTheRestartAndNamesItself(t *testing.T) {
	d := startDevice(t, &device{})
	ledger := filepath.Join(t.TempDir(), "access.jsonl")
	top := fmt.Sprintf("access:\n  ledger: %q\n  approvals: 1\n  max_duration: 2h", ledger)
	s, addr := bacnetWith(t, `        upstream: devices
        allow_clients: [127.0.0.0/8]
        default_action: allow
        services: [readProperty, reinitializeDevice, atomicWriteFile, createObject]
        engineering:
          require_grant: true`, top, d.addr())

	led := s.Access()
	if led == nil {
		t.Fatal("the daemon has no access ledger")
	}
	g, err := led.Request(access.Request{Subject: "127.0.0.1", Listener: "plant",
		Target: "devices", Reason: "change 812: restart the air handler controller",
		By: "engineer", Expires: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := led.Approve(g.ID, "supervisor", "agreed at the morning meeting"); err != nil {
		t.Fatal(err)
	}

	cl := dialClient(t, addr)
	cl.send(t, reinitReq(5))
	d.waitFor(t, 1, "the approved restart to reach the controller")
	awaitStats(t, s, "the engineering event", func(sn proxy.Snapshot) bool {
		return sn.EngineeringOps["bacnet/restart"] >= 1
	})
	if got := led.Stats().Engineering; got == 0 {
		t.Error("the carried operation was not written to the trail")
	}
}

// The other two engineering classes, which are about the device's own
// contents rather than its state: a file written into it, and the object
// model changed under the head end.
func TestTheFileAndObjectModelServicesAreEngineeringToo(t *testing.T) {
	writeFile := func(invoke uint8) []byte {
		// AtomicWriteFile naming a file object, which is the target the
		// record carries.
		body := []byte{0x01, 0x04, 0x00, 0x05, invoke, wire.AtomicWriteFile, 0xC4}
		body = append(body, wire.ObjectID{Type: wire.FileObject, Instance: 1}.Encode()...)
		return bvlcWrap(wire.FuncOriginalUnicast, body)
	}
	createObject := func(invoke uint8) []byte {
		body := []byte{0x01, 0x04, 0x00, 0x05, invoke, wire.CreateObject, 0x0E, 0x09, 0x02, 0x0F}
		return bvlcWrap(wire.FuncOriginalUnicast, body)
	}
	for _, tc := range []struct {
		name  string
		raw   []byte
		class string
	}{
		{"a file written into the controller", writeFile(6), "file_transfer"},
		{"an object created in it", createObject(7), "configuration"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := startDevice(t, &device{})
			ledger := filepath.Join(t.TempDir(), "access.jsonl")
			top := fmt.Sprintf("access:\n  ledger: %q\n  approvals: 1\n  max_duration: 2h", ledger)
			s, addr := bacnetWith(t, `        upstream: devices
        allow_clients: [127.0.0.0/8]
        default_action: allow
        services: [readProperty, atomicWriteFile, createObject, deleteObject]
        engineering:
          require_grant: true`, top, d.addr())
			dialClient(t, addr).send(t, tc.raw)
			awaitStats(t, s, "the engineering event", func(sn proxy.Snapshot) bool {
				return sn.EngineeringOps["bacnet/"+tc.class] >= 1
			})
		})
	}
}

// alert_on_deny off, which turns the security events down and nothing
// else: the refusal still happens, the counters still move, and the ban
// ladder is still told.
func TestTheRecordCanBeTurnedDownWithoutTurningTheRefusalOff(t *testing.T) {
	d := startDevice(t, &device{})
	ledger := filepath.Join(t.TempDir(), "access.jsonl")
	top := fmt.Sprintf(`access:
  ledger: %q
  approvals: 1
  max_duration: 2h
bans:
  triggers:
    - {name: plant, reasons: [bacnet_denied], threshold: 1, window: 1m, duration: 10m}`, ledger)
	s, addr := bacnetWith(t, `        upstream: devices
        allow_clients: [127.0.0.0/8]
        default_action: allow
        services: [readProperty, reinitializeDevice]
        alert_on_deny: false
        log_requests: false
        engineering:
          require_grant: true`, top, d.addr())

	cl := dialClient(t, addr)
	cl.send(t, reinitReq(8))
	awaitStats(t, s, "the refusal", func(sn proxy.Snapshot) bool {
		return sn.Refusals["bacnet"]["engineering_no_grant"] >= 1
	})
	// A write the service list does not carry, which is the other refusal
	// path and the one that feeds the ban ladder.
	cl.send(t, writeReq(9, wire.ObjectID{Type: wire.AnalogOutput, Instance: 3}, wire.PropPresentValue, 0))
	awaitStats(t, s, "the service refusal", func(sn proxy.Snapshot) bool {
		return sn.Refusals["bacnet"]["service_not_allowed"] >= 1
	})
}

// A network-layer message is logged as what it is rather than parsed as
// an application request: BACnet carries router messages on the same
// socket, and a relay that read one as a service would decide about a
// message that names none.
func TestANetworkLayerMessageIsLoggedAsOne(t *testing.T) {
	d := startDevice(t, &device{})
	s, addr := bacnetWith(t, `        upstream: devices
        allow_clients: [127.0.0.0/8]
        default_action: allow`, "", d.addr())
	// Version 1, control 0x80 (a network-layer message), Who-Is-Router-To-Network.
	dialClient(t, addr).send(t, bvlcWrap(wire.FuncOriginalUnicast, []byte{0x01, 0x80, 0x00}))
	// Nothing to assert in the counters: what matters is that it was read
	// as a network message and did not become a refusal.
	time.Sleep(200 * time.Millisecond)
	if n := s.Stats().Refusals["bacnet"]["service_not_allowed"]; n != 0 {
		t.Errorf("a network message was decided about as a service: %d", n)
	}
	_ = d
}
