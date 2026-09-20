// Package ldaptest is an in-process fake LDAP server for tests. It speaks
// just enough of the protocol (simple bind, search with equality, presence
// and boolean filters) to exercise the ldap client and the ldap_auth
// filter. It is not a directory: entries and passwords are fixed tables.
package ldaptest

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
)

// User is one directory entry.
type User struct {
	DN       string
	Password string
	Attrs    map[string][]string
}

// Server is a running fake LDAP server.
type Server struct {
	Addr      string
	ln        net.Listener
	users     []User
	closeOnce sync.Once
}

// Start launches a fake server on a loopback port and stops it on cleanup.
func Start(t *testing.T, users []User) *Server {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{Addr: ln.Addr().String(), ln: ln, users: users}
	go s.serve()
	t.Cleanup(s.Close)
	return s
}

// URL returns the ldap:// URL of the server.
func (s *Server) URL() string { return "ldap://" + s.Addr }

// Close stops the server early, for a test that needs the directory to
// go away while the code under test is still running. It is safe to
// call more than once and before the cleanup that always runs.
func (s *Server) Close() { s.closeOnce.Do(func() { _ = s.ln.Close() }) }

func (s *Server) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *Server) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	for {
		raw, err := readTLV(conn)
		if err != nil {
			return
		}
		msg, _, err := parse(raw)
		if err != nil || len(msg.kids) < 2 {
			return
		}
		id := msg.kids[0].intValue()
		op := msg.kids[1]
		switch {
		case op.class == classApplication && op.tag == 0: // BindRequest
			_, _ = conn.Write(s.bind(id, op))
		case op.class == classApplication && op.tag == 3: // SearchRequest
			for _, b := range s.search(id, op) {
				_, _ = conn.Write(b)
			}
		default:
			return
		}
	}
}

func (s *Server) bind(id int, op *packet) []byte {
	code := 49 // invalidCredentials
	if len(op.kids) >= 3 {
		dn := string(op.kids[1].data)
		pass := string(op.kids[2].data)
		for _, u := range s.users {
			if strings.EqualFold(u.DN, dn) && pass != "" && u.Password == pass {
				code = 0
				break
			}
		}
	}
	resp := node(classUniversal, tagSequence,
		intPacket(id),
		node(classApplication, 1, enumPacket(code), strPacket(""), strPacket("")),
	)
	return resp.encode(nil)
}

func (s *Server) search(id int, op *packet) [][]byte {
	var out [][]byte
	if len(op.kids) >= 7 {
		filter := op.kids[6]
		for _, u := range s.users {
			if matchFilter(filter, u) {
				out = append(out, s.entry(id, u).encode(nil))
			}
		}
	}
	done := node(classUniversal, tagSequence, intPacket(id),
		node(classApplication, 5, enumPacket(0), strPacket(""), strPacket("")))
	return append(out, done.encode(nil))
}

func (s *Server) entry(id int, u User) *packet {
	attrList := node(classUniversal, tagSequence)
	for name, vals := range u.Attrs {
		valSet := node(classUniversal, tagSet)
		for _, v := range vals {
			valSet.add(strPacket(v))
		}
		attrList.add(node(classUniversal, tagSequence, strPacket(name), valSet))
	}
	return node(classUniversal, tagSequence, intPacket(id),
		node(classApplication, 4, strPacket(u.DN), attrList))
}

// matchFilter evaluates a filter packet against a user entry.
func matchFilter(f *packet, u User) bool {
	switch {
	case f.class == classContext && f.tag == 0: // and
		for _, k := range f.kids {
			if !matchFilter(k, u) {
				return false
			}
		}
		return true
	case f.class == classContext && f.tag == 1: // or
		for _, k := range f.kids {
			if matchFilter(k, u) {
				return true
			}
		}
		return false
	case f.class == classContext && f.tag == 2: // not
		return len(f.kids) == 1 && !matchFilter(f.kids[0], u)
	case f.class == classContext && f.tag == 3: // equalityMatch
		if len(f.kids) != 2 {
			return false
		}
		val := string(f.kids[1].data)
		for _, v := range u.Attrs[string(f.kids[0].data)] {
			if strings.EqualFold(v, val) {
				return true
			}
		}
		return false
	case f.class == classContext && f.tag == 7: // present
		return len(u.Attrs[string(f.data)]) > 0
	default:
		return false
	}
}

// --- minimal BER, server side only ---

const (
	classUniversal   = 0x00
	classApplication = 0x40
	classContext     = 0x80
	constructed      = 0x20
	tagInteger       = 0x02
	tagOctetStr      = 0x04
	tagEnum          = 0x0a
	tagSequence      = 0x10
	tagSet           = 0x11
)

type packet struct {
	class byte
	tag   byte
	cons  bool
	data  []byte
	kids  []*packet
}

func node(class, tag byte, kids ...*packet) *packet {
	return &packet{class: class, tag: tag, cons: true, kids: kids}
}
func (p *packet) add(k *packet) { p.kids = append(p.kids, k) }

func strPacket(s string) *packet {
	return &packet{class: classUniversal, tag: tagOctetStr, data: []byte(s)}
}

func intPacket(v int) *packet {
	if v == 0 {
		return &packet{class: classUniversal, tag: tagInteger, data: []byte{0}}
	}
	var b []byte
	for v > 0 {
		b = append([]byte{byte(v)}, b...)
		v >>= 8
	}
	if b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return &packet{class: classUniversal, tag: tagInteger, data: b}
}

func enumPacket(v int) *packet { p := intPacket(v); p.tag = tagEnum; return p }

func (p *packet) encode(out []byte) []byte {
	id := p.class | p.tag
	if p.cons {
		id |= constructed
	}
	out = append(out, id)
	var body []byte
	if p.cons {
		for _, k := range p.kids {
			body = k.encode(body)
		}
	} else {
		body = p.data
	}
	out = appendLength(out, len(body))
	return append(out, body...)
}

func appendLength(out []byte, n int) []byte {
	if n < 0x80 {
		return append(out, byte(n))
	}
	var buf [8]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte(n)
		n >>= 8
	}
	out = append(out, byte(0x80|(len(buf)-i)))
	return append(out, buf[i:]...)
}

func (p *packet) intValue() int {
	n := 0
	for _, c := range p.data {
		n = n<<8 | int(c)
	}
	return n
}

func parse(b []byte) (*packet, int, error) {
	if len(b) < 2 {
		return nil, 0, errors.New("short")
	}
	id := b[0]
	p := &packet{class: id & 0xc0, tag: id & 0x1f, cons: id&constructed != 0}
	n, hdr, err := readLength(b[1:])
	if err != nil {
		return nil, 0, err
	}
	start, end := 1+hdr, 1+hdr+n
	if end > len(b) {
		return nil, 0, errors.New("overflow")
	}
	body := b[start:end]
	if p.cons {
		for len(body) > 0 {
			kid, used, err := parse(body)
			if err != nil {
				return nil, 0, err
			}
			p.kids = append(p.kids, kid)
			body = body[used:]
		}
	} else {
		p.data = body
	}
	return p, end, nil
}

func readLength(b []byte) (int, int, error) {
	if len(b) == 0 {
		return 0, 0, errors.New("no length")
	}
	if b[0] < 0x80 {
		return int(b[0]), 1, nil
	}
	count := int(b[0] & 0x7f)
	if count == 0 || count > 4 || 1+count > len(b) {
		return 0, 0, errors.New("bad length")
	}
	n := 0
	for i := 0; i < count; i++ {
		n = n<<8 | int(b[1+i])
	}
	return n, 1 + count, nil
}

func readTLV(r io.Reader) ([]byte, error) {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	out := hdr
	var length int
	if hdr[1] < 0x80 {
		length = int(hdr[1])
	} else {
		count := int(hdr[1] & 0x7f)
		if count == 0 || count > 4 {
			return nil, errors.New("bad length")
		}
		lb := make([]byte, count)
		if _, err := io.ReadFull(r, lb); err != nil {
			return nil, err
		}
		for _, b := range lb {
			length = length<<8 | int(b)
		}
		out = append(out, lb...)
	}
	if length < 0 || length > 8<<20 {
		return nil, errors.New("length range")
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return append(out, body...), nil
}
