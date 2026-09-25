package tftp

import (
	"bytes"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
	wire "github.com/rom/xproxy/internal/tftp"
)

// fileServer is a fake TFTP server. It records every request that reached it,
// which is the assertion that matters on a security relay: not what the client
// was told, but what got through.
//
// It answers from a socket of its own, as RFC 1350 requires, so the tests
// exercise the part of this relay that has to follow a transfer onto an
// ephemeral port pair.
type fileServer struct {
	pc net.PacketConn

	mu  sync.Mutex
	got []*wire.Request
	// file is what a read transfer serves.
	file []byte
	// written is what a write transfer delivered.
	written []byte
	// grant is the block size and window an option acknowledgement offers.
	// Zero grants nothing, which is a server that ignores the options --
	// and then sends 512-octet blocks whatever the request asked for.
	grantBlock, grantWindow int
	// grantTSize puts a transfer size in the acknowledgement, which on a
	// read is the server declaring how large the file is.
	grantTSize int64
	// silent answers nothing at all.
	silent bool
	// errorCode answers with an error packet instead of the file.
	errorCode int
	// stray sends one datagram from a second socket once the transfer is
	// under way, which is the off-path injection this relay has to drop: the
	// server's transfer identifier is known by then, and a packet from any
	// other port has no part in the transfer.
	stray bool
}

func startFileServer(t *testing.T, s *fileServer) *fileServer {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.pc = pc
	t.Cleanup(func() { _ = pc.Close() })
	go s.accept(t)
	return s
}

func (s *fileServer) addr() string { return s.pc.LocalAddr().String() }

func (s *fileServer) accept(t *testing.T) {
	buf := make([]byte, wire.MaxPacket+1)
	for {
		n, from, err := s.pc.ReadFrom(buf)
		if err != nil {
			return
		}
		raw := make([]byte, n)
		copy(raw, buf[:n])
		p, err := wire.Parse(raw)
		if err != nil || p.Request == nil {
			continue
		}
		s.mu.Lock()
		s.got = append(s.got, p.Request)
		silent := s.silent
		s.mu.Unlock()
		if silent {
			continue
		}
		go s.transfer(t, p, from.(*net.UDPAddr))
	}
}

// transfer runs one transfer from a socket of its own, which is the server's
// transfer identifier.
func (s *fileServer) transfer(t *testing.T, p *wire.Packet, peer *net.UDPAddr) {
	tid, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return
	}
	defer func() { _ = tid.Close() }()
	s.mu.Lock()
	code, grantBlock, grantWindow, tsize, stray := s.errorCode, s.grantBlock, s.grantWindow, s.grantTSize, s.stray
	file := s.file
	s.mu.Unlock()
	if code != 0 {
		_, _ = tid.WriteTo(wire.EncodeError(uint16(code), "refused by the server"), peer)
		return
	}
	block := wire.DefaultBlockSize
	oacked := false
	if len(p.Request.Options) > 0 && (grantBlock > 0 || grantWindow > 0 || tsize > 0) {
		var opts []wire.Option
		if grantBlock > 0 {
			opts = append(opts, wire.Option{Name: wire.OptBlockSize, Value: itoa(grantBlock)})
			block = grantBlock
		}
		if grantWindow > 0 {
			opts = append(opts, wire.Option{Name: wire.OptWindowSize, Value: itoa(grantWindow)})
		}
		if tsize > 0 {
			opts = append(opts, wire.Option{Name: wire.OptTransferSize, Value: itoa64(tsize)})
		}
		oack, err := wire.EncodeOAck(opts)
		if err != nil {
			return
		}
		if _, err := tid.WriteTo(oack, peer); err != nil {
			return
		}
		oacked = true
	}
	if p.Op == wire.OpWrite {
		if !oacked {
			if _, err := tid.WriteTo(wire.EncodeAck(0), peer); err != nil {
				return
			}
		}
		s.receive(tid, peer, block)
		return
	}
	s.send(tid, peer, file, block, oacked, stray)
}

// send is the data half of a read transfer.
//
// The first block goes out unprompted unless an option acknowledgement was
// sent, because that acknowledgement is the one packet a client answers before
// any data has moved. This is RFC 1350 and RFC 2347 read literally, and it is
// where a relay that assumed its own options had been granted would go wrong.
func (s *fileServer) send(tid net.PacketConn, peer *net.UDPAddr, file []byte, block int, oacked, stray bool) {
	buf := make([]byte, wire.MaxPacket+1)
	if oacked {
		_ = tid.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, _, err := tid.ReadFrom(buf); err != nil {
			return
		}
	}
	for n := 1; ; n++ {
		lo := (n - 1) * block
		if lo > len(file) {
			return
		}
		hi := lo + block
		if hi > len(file) {
			hi = len(file)
		}
		out := append([]byte{0, 3, byte(n >> 8), byte(n)}, file[lo:hi]...)
		if _, err := tid.WriteTo(out, peer); err != nil {
			return
		}
		_ = tid.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, _, err := tid.ReadFrom(buf); err != nil {
			return
		}
		if stray && n == 1 {
			// A second socket on this host, once the transfer identifiers are
			// both settled: the relay knows which port speaks for the server
			// and this is not it.
			if other, err := net.ListenPacket("udp", "127.0.0.1:0"); err == nil {
				_, _ = other.WriteTo(wire.EncodeError(wire.ErrNotDefined, "injected"), peer)
				_ = other.Close()
			}
		}
		if hi-lo < block {
			return
		}
	}
}

// receive is the data half of a write transfer.
func (s *fileServer) receive(tid net.PacketConn, peer *net.UDPAddr, block int) {
	buf := make([]byte, wire.MaxPacket+1)
	var got []byte
	for {
		_ = tid.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, err := tid.ReadFrom(buf)
		if err != nil {
			return
		}
		p, err := wire.Parse(buf[:n])
		if err != nil || p.Op != wire.OpData {
			return
		}
		got = append(got, buf[4:n]...)
		if _, err := tid.WriteTo(wire.EncodeAck(p.Data.Block), peer); err != nil {
			return
		}
		if p.Data.Length < block {
			s.mu.Lock()
			s.written = got
			s.mu.Unlock()
			return
		}
	}
}

func (s *fileServer) seen() []*wire.Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*wire.Request, len(s.got))
	copy(out, s.got)
	return out
}

func (s *fileServer) delivered() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.written
}

const tftpYAML = `
version: 1
server:
  listeners:
    - name: boot
      address: "127.0.0.1:0"
      kind: tftp
      tftp:
%s
%s
logging: {access: {enabled: false}}
upstreams:
  - {name: servers, endpoints: [{address: %q}]}
`

func tftpRelay(t *testing.T, section, serverAddr string) (*proxy.Server, string) {
	t.Helper()
	return tftpRelayWith(t, section, "", serverAddr)
}

// tftpRelayWith starts a relay, with extra listener keys outside the tftp
// section (which is how shadow mode is set).
func tftpRelayWith(t *testing.T, section, extra, serverAddr string) (*proxy.Server, string) {
	t.Helper()
	s := proxytest.Start(t, fmt.Sprintf(tftpYAML, section, extra, serverAddr))
	return s, proxytest.Addr(t, s, "boot")
}

// client is a device: a socket, a request, and whatever comes back.
type client struct {
	t     *testing.T
	pc    net.PacketConn
	relay *net.UDPAddr
	// peer is the relay's transfer identifier, learned from its first answer.
	peer *net.UDPAddr
}

func dial(t *testing.T, addr string) *client {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	ra, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	return &client{t: t, pc: pc, relay: ra}
}

func (c *client) request(op wire.Op, name, mode string, opts ...wire.Option) {
	c.t.Helper()
	raw, err := wire.EncodeRequest(op, name, mode, opts)
	if err != nil {
		c.t.Fatal(err)
	}
	if _, err := c.pc.WriteTo(raw, c.relay); err != nil {
		c.t.Fatal(err)
	}
}

// send writes to the relay's transfer identifier once one is known.
func (c *client) send(raw []byte) {
	c.t.Helper()
	to := c.relay
	if c.peer != nil {
		to = c.peer
	}
	if _, err := c.pc.WriteTo(raw, to); err != nil {
		c.t.Fatal(err)
	}
}

// recv reads one packet, or reports that nothing came.
func (c *client) recv() (*wire.Packet, bool) {
	c.t.Helper()
	buf := make([]byte, wire.MaxPacket+1)
	_ = c.pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, from, err := c.pc.ReadFrom(buf)
	if err != nil {
		return nil, false
	}
	c.peer = from.(*net.UDPAddr)
	raw := make([]byte, n)
	copy(raw, buf[:n])
	p, err := wire.Parse(raw)
	if err != nil {
		c.t.Fatalf("the relay sent something unreadable: %v", err)
	}
	return p, true
}

// read runs a whole read transfer and returns the file, or the error packet
// that ended it.
func (c *client) read(name string, opts ...wire.Option) ([]byte, *wire.Packet) {
	c.t.Helper()
	c.request(wire.OpRead, name, wire.ModeOctet, opts...)
	var file []byte
	block := wire.DefaultBlockSize
	for {
		p, ok := c.recv()
		if !ok {
			return file, nil
		}
		switch p.Op {
		case wire.OpOAck:
			for _, o := range p.OAck {
				if o.Name == wire.OptBlockSize {
					var n int
					if _, err := fmt.Sscanf(o.Value, "%d", &n); err == nil {
						block = n
					}
				}
			}
			c.send(wire.EncodeAck(0))
		case wire.OpData:
			file = append(file, p.Raw[4:]...)
			c.send(wire.EncodeAck(p.Data.Block))
			if p.Data.Length < block {
				return file, nil
			}
		case wire.OpError:
			return file, p
		default:
			c.t.Fatalf("a read transfer received %v", p.Op)
		}
	}
}

// write runs a whole write transfer and returns the error packet that ended
// it, when one did.
func (c *client) write(name string, data []byte, opts ...wire.Option) *wire.Packet {
	c.t.Helper()
	c.request(wire.OpWrite, name, wire.ModeOctet, opts...)
	block := wire.DefaultBlockSize
	sent := 0
	for n := 0; ; {
		p, ok := c.recv()
		if !ok {
			return nil
		}
		switch p.Op {
		case wire.OpOAck:
			for _, o := range p.OAck {
				if o.Name == wire.OptBlockSize {
					var v int
					if _, err := fmt.Sscanf(o.Value, "%d", &v); err == nil {
						block = v
					}
				}
			}
		case wire.OpAck:
			if sent > 0 && sent >= len(data) {
				return nil
			}
		case wire.OpError:
			return p
		default:
			c.t.Fatalf("a write transfer received %v", p.Op)
		}
		n++
		hi := sent + block
		if hi > len(data) {
			hi = len(data)
		}
		out := append([]byte{0, 2 + 1, byte(n >> 8), byte(n)}, data[sent:hi]...)
		c.send(out)
		last := hi-sent < block
		sent = hi
		if last {
			// The acknowledgement of the short block ends the transfer.
			p, ok := c.recv()
			if !ok {
				return nil
			}
			if p.Op == wire.OpError {
				return p
			}
			return nil
		}
	}
}

func awaitCounter(t *testing.T, s *proxy.Server, ok func(proxy.Snapshot) bool, what string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if ok(s.Stats()) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s: the counters never said so: %+v", what, s.Stats().Refusals["tftp"])
}

func content(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte('a' + i%26)
	}
	return out
}

// TestAReadTransferGoesThroughAndTheServerSeesTheRequest is the base case:
// the relay follows the transfer onto the ephemeral port pair and the file
// arrives whole.
func TestAReadTransferGoesThroughAndTheServerSeesTheRequest(t *testing.T) {
	want := content(1500)
	fs := startFileServer(t, &fileServer{file: want})
	_, addr := tftpRelay(t, "        upstream: servers\n        directories: [firmware]\n        default_action: allow\n", fs.addr())
	c := dial(t, addr)
	got, errp := c.read("firmware/boot.bin")
	if errp != nil {
		t.Fatalf("the transfer was refused: %s", errp.ErrorMessage)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %d octets, want %d", len(got), len(want))
	}
	seen := fs.seen()
	if len(seen) != 1 || seen[0].Filename != "firmware/boot.bin" {
		t.Fatalf("the server saw %v", seen)
	}
}

// TestATraversalNeverReachesTheServer is the whole point of the kind.
func TestATraversalNeverReachesTheServer(t *testing.T) {
	fs := startFileServer(t, &fileServer{file: content(16)})
	_, addr := tftpRelay(t, "        upstream: servers\n        default_action: allow\n", fs.addr())
	for _, name := range []string{
		"../../etc/shadow",
		"firmware/../../etc/shadow",
		`..\..\etc\shadow`,
		"/etc/shadow",
		`c:\config.txt`,
	} {
		c := dial(t, addr)
		got, errp := c.read(name)
		if errp == nil {
			t.Errorf("%q was not refused", name)
		}
		if len(got) != 0 {
			t.Errorf("%q returned %d octets", name, len(got))
		}
	}
	if seen := fs.seen(); len(seen) != 0 {
		t.Fatalf("the server saw %v", seen)
	}
}

// TestAWriteIsRefusedByDefault holds the default that matters most: a write is
// how a configuration leaves an estate and how firmware arrives in it.
func TestAWriteIsRefusedByDefault(t *testing.T) {
	fs := startFileServer(t, &fileServer{})
	_, addr := tftpRelay(t, "        upstream: servers\n        default_action: allow\n", fs.addr())
	c := dial(t, addr)
	if errp := c.write("cfg.txt", content(64)); errp == nil {
		t.Fatal("a write was relayed with no operations list")
	}
	if seen := fs.seen(); len(seen) != 0 {
		t.Fatalf("the server saw %v", seen)
	}
	// And it goes through once somebody writes it down.
	fs2 := startFileServer(t, &fileServer{})
	_, addr2 := tftpRelayWith(t, "        upstream: servers\n        operations: [read, write]\n        default_action: allow\n", "", fs2.addr())
	c2 := dial(t, addr2)
	want := content(700)
	if errp := c2.write("cfg.txt", want); errp != nil {
		t.Fatalf("the write was refused: %s", errp.ErrorMessage)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && len(fs2.delivered()) < len(want) {
		time.Sleep(5 * time.Millisecond)
	}
	if !bytes.Equal(fs2.delivered(), want) {
		t.Fatalf("the server received %d octets, want %d", len(fs2.delivered()), len(want))
	}
}

// TestTheWindowIsLoweredRatherThanRefused is the design decision that keeps
// the amplification bound deployable: the poller asking for sixty-four still
// gets its file.
func TestTheWindowIsLoweredRatherThanRefused(t *testing.T) {
	want := content(600)
	fs := startFileServer(t, &fileServer{file: want, grantBlock: 512, grantWindow: 2})
	_, addr := tftpRelay(t, "        upstream: servers\n        default_action: allow\n        max_window_size: 2\n        max_block_size: 512\n", fs.addr())
	c := dial(t, addr)
	got, errp := c.read("boot.bin",
		wire.Option{Name: wire.OptBlockSize, Value: "8192"},
		wire.Option{Name: wire.OptWindowSize, Value: "64"})
	if errp != nil {
		t.Fatalf("the transfer was refused: %s", errp.ErrorMessage)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %d octets, want %d", len(got), len(want))
	}
	seen := fs.seen()
	if len(seen) != 1 {
		t.Fatalf("the server saw %d requests", len(seen))
	}
	if v, _ := seen[0].Get(wire.OptWindowSize); v != "2" {
		t.Errorf("the server was asked for a window of %q", v)
	}
	if v, _ := seen[0].Get(wire.OptBlockSize); v != "512" {
		t.Errorf("the server was asked for a block size of %q", v)
	}
}

// TestADeclaredTransferSizePastTheBoundIsRefusedBeforeAnOctetMoves is the one
// bound that cannot be lowered: the client has said in advance how much it
// intends to send.
func TestADeclaredTransferSizePastTheBoundIsRefusedBeforeAnOctetMoves(t *testing.T) {
	fs := startFileServer(t, &fileServer{})
	_, addr := tftpRelay(t, "        upstream: servers\n        operations: [read, write]\n        max_transfer_bytes: 1024\n        default_action: allow\n", fs.addr())
	c := dial(t, addr)
	c.request(wire.OpWrite, "big.bin", wire.ModeOctet,
		wire.Option{Name: wire.OptTransferSize, Value: "1048576"})
	p, ok := c.recv()
	if !ok || p.Op != wire.OpError {
		t.Fatalf("got %v, want an error packet", p)
	}
	if seen := fs.seen(); len(seen) != 0 {
		t.Fatalf("the server saw %v", seen)
	}
}

// TestATransferIsCutAtItsByteBound is the same bound on the data rather than
// on the declaration, which is what a client that declared nothing meets.
func TestATransferIsCutAtItsByteBound(t *testing.T) {
	fs := startFileServer(t, &fileServer{file: content(4096)})
	_, addr := tftpRelay(t, "        upstream: servers\n        default_action: allow\n        max_transfer_bytes: 1024\n", fs.addr())
	c := dial(t, addr)
	got, errp := c.read("boot.bin")
	if errp == nil {
		t.Fatal("an oversize transfer ran to the end")
	}
	if len(got) > 2048 {
		t.Fatalf("%d octets went through a 1024 octet bound", len(got))
	}
}

// TestAServerThatAcceptsMoreThanItWasOfferedEndsTheTransfer holds the other
// end of the amplification bound: the request was lowered, and a server that
// answers with a larger value than it was offered is not one to argue with
// mid-transfer.
func TestAServerThatAcceptsMoreThanItWasOfferedEndsTheTransfer(t *testing.T) {
	fs := startFileServer(t, &fileServer{file: content(4096), grantBlock: 8192})
	_, addr := tftpRelay(t, "        upstream: servers\n        default_action: allow\n        max_block_size: 512\n", fs.addr())
	c := dial(t, addr)
	_, errp := c.read("boot.bin", wire.Option{Name: wire.OptBlockSize, Value: "8192"})
	if errp == nil {
		t.Fatal("the transfer survived a server that overshot the block size")
	}
}

// TestADatagramFromAThirdAddressIsDropped is the injection this protocol has
// no defence against: a packet in the middle of a firmware transfer is
// firmware.
func TestADatagramFromAThirdAddressIsDropped(t *testing.T) {
	want := content(1200)
	fs := startFileServer(t, &fileServer{file: want, stray: true})
	_, addr := tftpRelay(t, "        upstream: servers\n        default_action: allow\n", fs.addr())
	c := dial(t, addr)
	got, errp := c.read("boot.bin")
	if errp != nil {
		t.Fatalf("the injected datagram ended the transfer: %s", errp.ErrorMessage)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %d octets, want %d", len(got), len(want))
	}
}

// TestAPacketThatIsNotARequestOnThePortIsRefused: the request port has one
// job.
func TestAPacketThatIsNotARequestOnThePortIsRefused(t *testing.T) {
	fs := startFileServer(t, &fileServer{})
	_, addr := tftpRelay(t, "        upstream: servers\n        default_action: allow\n", fs.addr())
	c := dial(t, addr)
	c.send(wire.EncodeAck(1))
	p, ok := c.recv()
	if !ok || p.Op != wire.OpError {
		t.Fatalf("got %v, want an error packet", p)
	}
	if seen := fs.seen(); len(seen) != 0 {
		t.Fatalf("the server saw %v", seen)
	}
}

// TestDropAnswersNothing is the other deny_response: a refused client hears
// nothing and retransmits until it gives up.
func TestDropAnswersNothing(t *testing.T) {
	fs := startFileServer(t, &fileServer{})
	_, addr := tftpRelay(t, "        upstream: servers\n        default_action: allow\n        deny_response: drop\n", fs.addr())
	c := dial(t, addr)
	c.request(wire.OpRead, "../../etc/shadow", wire.ModeOctet)
	if p, ok := c.recv(); ok {
		t.Fatalf("a dropped refusal answered with %v", p)
	}
}

// TestShadowModeForwardsPolicyAndStillRefusesTheHardShapes is the split every
// kind here draws: a policy is what shadow mode is for, and a bound is not.
func TestShadowModeForwardsPolicyAndStillRefusesTheHardShapes(t *testing.T) {
	want := content(64)
	fs := startFileServer(t, &fileServer{file: want})
	_, addr := tftpRelayWith(t, "        upstream: servers\n        directories: [firmware]\n        default_action: allow\n",
		"      policy: {mode: shadow}", fs.addr())
	c := dial(t, addr)
	// Outside the directories list, which is policy: in shadow mode it is
	// recorded and forwarded.
	got, errp := c.read("elsewhere/boot.bin")
	if errp != nil {
		t.Fatalf("shadow mode refused a policy decision: %s", errp.ErrorMessage)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %d octets, want %d", len(got), len(want))
	}
	// A control character in the filename is not policy: it goes into the
	// server's own log, and there is nothing for a policy to be evaluated
	// against.
	c2 := dial(t, addr)
	if _, errp := c2.read("firmware/boot\r\n.bin"); errp == nil {
		t.Fatal("shadow mode forwarded a filename with a control character in it")
	}
	if seen := fs.seen(); len(seen) != 1 {
		t.Fatalf("the server saw %d requests", len(seen))
	}
}

// TestAServerErrorReachesTheClient: a relay that swallowed the server's own
// answer would leave the device retransmitting.
func TestAServerErrorReachesTheClient(t *testing.T) {
	fs := startFileServer(t, &fileServer{errorCode: int(wire.ErrFileNotFound)})
	_, addr := tftpRelay(t, "        upstream: servers\n        default_action: allow\n", fs.addr())
	c := dial(t, addr)
	_, errp := c.read("missing.bin")
	if errp == nil || errp.ErrorCode != wire.ErrFileNotFound {
		t.Fatalf("got %v, want the server's fileNotFound", errp)
	}
}

// TestASilentServerEndsTheTransferOnTheIdleTimeout: a transfer that nothing
// is happening on is a socket this relay is holding.
func TestASilentServerEndsTheTransferOnTheIdleTimeout(t *testing.T) {
	fs := startFileServer(t, &fileServer{silent: true})
	s, addr := tftpRelay(t, "        upstream: servers\n        default_action: allow\n        idle_timeout: 1s\n", fs.addr())
	c := dial(t, addr)
	c.request(wire.OpRead, "boot.bin", wire.ModeOctet)
	if p, ok := c.recv(); ok {
		t.Fatalf("a silent server produced %v", p)
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.TFTPTransfersOpen == 0 && sn.TFTPTimedOut > 0
	}, "the idle transfer ended")
}

// TestTheTransferBoundRefusesTheSecondClient is the resource bound: each
// transfer holds a socket.
func TestTheTransferBoundRefusesTheSecondClient(t *testing.T) {
	fs := startFileServer(t, &fileServer{silent: true})
	_, addr := tftpRelay(t, "        upstream: servers\n        default_action: allow\n        max_transfers: 1\n        idle_timeout: 30s\n", fs.addr())
	c := dial(t, addr)
	c.request(wire.OpRead, "boot.bin", wire.ModeOctet)
	c2 := dial(t, addr)
	c2.request(wire.OpRead, "boot.bin", wire.ModeOctet)
	p, ok := c2.recv()
	if !ok || p.Op != wire.OpError {
		t.Fatalf("the second transfer got %v", p)
	}
}

// TestARuleNarrowsByDirectionDirectoryAndWindow: the rules are where an
// estate's own shape is written down.
func TestARuleNarrowsByDirectionDirectoryAndWindow(t *testing.T) {
	want := content(600)
	fs := startFileServer(t, &fileServer{file: want, grantBlock: 512})
	section := "        upstream: servers\n" +
		"        operations: [read, write]\n" +
		"        rules:\n" +
		"          - {name: firmware, action: allow, operations: [read], directories: [firmware], max_window_size: 1}\n" +
		"          - {name: configs, action: deny, directories: [configs]}\n"
	_, addr := tftpRelay(t, section, fs.addr())
	c := dial(t, addr)
	got, errp := c.read("firmware/boot.bin", wire.Option{Name: wire.OptWindowSize, Value: "16"})
	if errp != nil {
		t.Fatalf("the rule refused its own traffic: %s", errp.ErrorMessage)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %d octets", len(got))
	}
	if v, _ := fs.seen()[0].Get(wire.OptWindowSize); v != "1" {
		t.Errorf("the rule's window bound was not applied: %q", v)
	}
	// A write to the same directory matches no allowing rule.
	c2 := dial(t, addr)
	if errp := c2.write("firmware/boot.bin", content(8)); errp == nil {
		t.Fatal("a write matched a read-only rule")
	}
	// And the denying rule wins over the listener's own lists.
	c3 := dial(t, addr)
	if _, errp := c3.read("configs/router.cfg"); errp == nil {
		t.Fatal("a denied directory was relayed")
	}
}

// TestAClientOutsideTheListNeverReachesTheServer: the client list is the only
// identity this protocol has.
func TestAClientOutsideTheListNeverReachesTheServer(t *testing.T) {
	fs := startFileServer(t, &fileServer{file: content(16)})
	_, addr := tftpRelay(t, "        upstream: servers\n        allow_clients: [\"10.99.0.0/16\"]\n        default_action: allow\n", fs.addr())
	c := dial(t, addr)
	c.request(wire.OpRead, "boot.bin", wire.ModeOctet)
	if p, ok := c.recv(); ok {
		t.Fatalf("a refused client was answered with %v", p)
	}
	if seen := fs.seen(); len(seen) != 0 {
		t.Fatalf("the server saw %v", seen)
	}
}
