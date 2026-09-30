package mgmt

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/logging"
	"github.com/rom/xproxy/internal/proxy"
)

// The three calls over the socket, and the two refusals that matter: a work
// order the ledger will not accept, and a daemon with no ledger to file it in.
func TestWorkOrdersOverTheSocket(t *testing.T) {
	dir := t.TempDir()
	yaml := `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
access:
  ledger: ` + filepath.Join(dir, "access.jsonl") + `
  approvals: 1
upstreams:
  - name: u
    endpoints: [{address: "127.0.0.1:1"}]
routes:
  - name: r
    upstream: u
`
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	p, err := proxy.New(cfg, logging.Discard())
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "m.sock")
	m := New(config.Management{Socket: sock, SocketMode: "0600"}, p, logging.Discard(), Actions{})
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Shutdown(context.Background()) }()
	c := NewClient(sock)

	rep, err := c.WorkOrders("", "")
	if err != nil || len(rep.Orders) != 0 || rep.Open != 0 {
		t.Fatalf("empty: %+v %v", rep, err)
	}

	v, err := c.FileWorkOrder("WO-7", "plc-line1", "", "drive replacement", "maintenance", "8h", "")
	if err != nil {
		t.Fatal(err)
	}
	if v.Reference != "WO-7" || v.Device != "plc-line1" || v.State != "open" {
		t.Fatalf("filed: %+v", v)
	}

	rep, err = c.WorkOrders("open", "plc-line1")
	if err != nil || len(rep.Orders) != 1 || rep.Open != 1 {
		t.Fatalf("listing: %+v %v", rep, err)
	}
	if rep, err := c.WorkOrders("", "somewhere-else"); err != nil || len(rep.Orders) != 0 {
		t.Errorf("the device filter matched the wrong device: %+v %v", rep, err)
	}
	if rep, err := c.WorkOrders("closed", ""); err != nil || len(rep.Orders) != 0 {
		t.Errorf("the state filter matched an open work order as closed: %+v %v", rep, err)
	}

	if _, err := c.CloseWorkOrder("WO-7", "supervisor", "finished"); err != nil {
		t.Fatal(err)
	}
	rep, err = c.WorkOrders("", "")
	if err != nil || rep.Open != 0 || rep.Orders[0].State != "closed" {
		t.Fatalf("after closing: %+v %v", rep, err)
	}

	// A window with no end, which is the one an operator most wants to file
	// and the one that must be refused.
	if _, err := c.FileWorkOrder("WO-8", "plc-line1", "", "", "op", "", ""); err == nil {
		t.Error("a work order with no duration was accepted")
	}
	if _, err := c.FileWorkOrder("", "plc-line1", "", "", "op", "1h", ""); err == nil ||
		!strings.Contains(err.Error(), "reference") {
		t.Errorf("a work order with no reference: %v", err)
	}
	if _, err := c.CloseWorkOrder("WO-nothing", "op", ""); err == nil {
		t.Error("closing a work order nobody filed succeeded")
	}
}

// A daemon with no access section has nowhere to file a work order and says
// which section is missing, rather than accepting one into nothing.
func TestFilingAWorkOrderWithoutALedger(t *testing.T) {
	cfg, err := config.Parse([]byte(`
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
upstreams:
  - name: u
    endpoints: [{address: "127.0.0.1:1"}]
routes:
  - name: r
    upstream: u
`))
	if err != nil {
		t.Fatal(err)
	}
	p, err := proxy.New(cfg, logging.Discard())
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(t.TempDir(), "m.sock")
	m := New(config.Management{Socket: sock, SocketMode: "0600"}, p, logging.Discard(), Actions{})
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Shutdown(context.Background()) }()
	c := NewClient(sock)
	if _, err := c.WorkOrders("", ""); err == nil || !strings.Contains(err.Error(), "access section") {
		t.Errorf("listing without a ledger: %v", err)
	}
	if _, err := c.FileWorkOrder("WO-1", "d", "", "", "op", "1h", ""); err == nil {
		t.Error("a work order was filed into a daemon with no ledger")
	}
}
