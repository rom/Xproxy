// Package sftp holds the SFTP packet layer an inspecting proxy needs:
// framing, the request types, and the path each one names.
//
// SFTP is not a protocol of its own on the wire. It is what runs inside
// an SSH subsystem channel, which is why a proxy that only decides
// "this session may use sftp" has decided almost nothing: the whole
// difference between reading a file and deleting a tree is inside the
// channel. This package makes that difference visible.
//
// Version 3 (draft-ietf-secsh-filexfer-02) is what every widely
// deployed client and server speaks, and is what is parsed here. A
// client that negotiates a higher version is a client whose packets
// this cannot be trusted to read, which the proxy treats as a refusal
// rather than a reason to guess.
package sftp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"unicode/utf8"
)

// Packet types of version 3.
const (
	INIT     = 1
	VERSION  = 2
	OPEN     = 3
	CLOSE    = 4
	READ     = 5
	WRITE    = 6
	LSTAT    = 7
	FSTAT    = 8
	SETSTAT  = 9
	FSETSTAT = 10
	OPENDIR  = 11
	READDIR  = 12
	REMOVE   = 13
	MKDIR    = 14
	RMDIR    = 15
	REALPATH = 16
	STAT     = 17
	RENAME   = 18
	READLINK = 19
	SYMLINK  = 20

	STATUS        = 101
	HANDLE        = 102
	DATA          = 103
	NAME          = 104
	ATTRS         = 105
	EXTENDED      = 200
	EXTENDEDREPLY = 201
)

// Status codes of version 3, as far as this proxy needs to answer with
// them.
const (
	StatusOK               = 0
	StatusFailure          = 4
	StatusPermissionDenied = 3
	StatusOpUnsupported    = 8
)

// Open flags (section 6.3 of the draft).
const (
	FlagRead   = 0x00000001
	FlagWrite  = 0x00000002
	FlagAppend = 0x00000004
	FlagCreat  = 0x00000008
	FlagTrunc  = 0x00000010
	FlagExcl   = 0x00000020
)

// Version is the protocol version this package reads.
const Version = 3

var (
	// ErrTooLarge is a packet over the configured bound.
	ErrTooLarge = errors.New("sftp: packet too large")
	// ErrMalformed is a packet whose fields do not fit its length.
	ErrMalformed = errors.New("sftp: malformed packet")
)

// Packet is one SFTP packet: its type and everything after the type
// octet.
type Packet struct {
	Type byte
	Body []byte
}

// Encode renders a packet with its length prefix.
func (p Packet) Encode() []byte {
	out := make([]byte, 4, 5+len(p.Body))
	binary.BigEndian.PutUint32(out, uint32(len(p.Body)+1)) //nolint:gosec // bounded by the caller
	out = append(out, p.Type)
	return append(out, p.Body...)
}

// Name is the packet type's name, for logs and for the deny list.
func (p Packet) Name() string { return TypeName(p.Type) }

// TypeName maps a packet type to the operation name an operator would
// write in a policy.
func TypeName(t byte) string {
	switch t {
	case INIT:
		return "init"
	case OPEN:
		return "open"
	case CLOSE:
		return "close"
	case READ:
		return "read"
	case WRITE:
		return "write"
	case LSTAT:
		return "lstat"
	case FSTAT:
		return "fstat"
	case SETSTAT:
		return "setstat"
	case FSETSTAT:
		return "fsetstat"
	case OPENDIR:
		return "opendir"
	case READDIR:
		return "readdir"
	case REMOVE:
		return "remove"
	case MKDIR:
		return "mkdir"
	case RMDIR:
		return "rmdir"
	case REALPATH:
		return "realpath"
	case STAT:
		return "stat"
	case RENAME:
		return "rename"
	case READLINK:
		return "readlink"
	case SYMLINK:
		return "symlink"
	default:
		return fmt.Sprintf("type %d", t)
	}
}

// Request is a parsed client request: what it asks for, and what it
// asks it of.
type Request struct {
	Type byte
	ID   uint32
	// Path is the name the request works on, empty for the ones that
	// work on an open handle.
	Path string
	// Target is the second name of rename and symlink.
	Target string
	// Flags are the open flags of an OPEN request.
	Flags uint32
	// Handle is the opaque name the server gave an open file, for the
	// requests that work on one. It is the server's bytes, not a path
	// and not text: the only thing to do with it is compare it with
	// what the HANDLE reply carried.
	Handle string
	// Offset and Data are a WRITE request's payload. Data aliases the
	// packet's own body, which is forwarded unchanged, so a reader
	// must not keep it past the packet.
	Offset uint64
	Data   []byte
	// Writes reports whether the request changes anything on the
	// server: the question a read-only policy asks.
	Writes bool
}

// ParseRequest reads a client request. Only the fields a policy decides
// on are read; the rest of the packet is forwarded untouched, because a
// proxy that re-encodes what it does not need only adds a way to
// change it.
func ParseRequest(p Packet) (Request, error) {
	r := Request{Type: p.Type}
	b := &reader{b: p.Body}
	if p.Type == INIT {
		v, err := b.uint32()
		if err != nil {
			return r, err
		}
		r.Flags = v // the offered version
		return r, nil
	}
	var err error
	if r.ID, err = b.uint32(); err != nil {
		return r, err
	}
	switch p.Type {
	case OPEN:
		if r.Path, err = b.str(); err != nil {
			return r, err
		}
		if r.Flags, err = b.uint32(); err != nil {
			return r, err
		}
		r.Writes = r.Flags&(FlagWrite|FlagAppend|FlagCreat|FlagTrunc) != 0
	case OPENDIR, LSTAT, STAT, REALPATH, READLINK:
		if r.Path, err = b.str(); err != nil {
			return r, err
		}
	case REMOVE, MKDIR, RMDIR, SETSTAT:
		if r.Path, err = b.str(); err != nil {
			return r, err
		}
		r.Writes = true
	case RENAME, SYMLINK:
		if r.Path, err = b.str(); err != nil {
			return r, err
		}
		if r.Target, err = b.str(); err != nil {
			return r, err
		}
		r.Writes = true
	case WRITE:
		// Named by handle, not by path. The handle came from an OPEN
		// the policy already decided on, which is where a write is
		// caught; this flag is what a read-only policy refuses even so,
		// because a handle opened for reading must not be written to.
		r.Writes = true
		if r.Handle, err = b.raw(); err != nil {
			return r, err
		}
		if r.Offset, err = b.uint64(); err != nil {
			return r, err
		}
		if r.Data, err = b.rawBytes(); err != nil {
			return r, err
		}
	case FSETSTAT:
		r.Writes = true
		if r.Handle, err = b.raw(); err != nil {
			return r, err
		}
	case CLOSE, READ, FSTAT, READDIR:
		if r.Handle, err = b.raw(); err != nil {
			return r, err
		}
	case EXTENDED:
		// An extension is a request whose meaning this proxy does not
		// know. It is named so a policy can refuse it by name.
		if r.Target, err = b.str(); err != nil {
			return r, err
		}
		r.Writes = true
	}
	return r, nil
}

// ParseHandleReply reads the server's answer to an OPEN or OPENDIR: the
// request it answers and the handle it gave. It is the one packet from
// the server a proxy has to read, because without it a WRITE names
// something the proxy cannot connect to the path it decided on.
func ParseHandleReply(p Packet) (id uint32, handle string, err error) {
	if p.Type != HANDLE {
		return 0, "", ErrMalformed
	}
	b := &reader{b: p.Body}
	if id, err = b.uint32(); err != nil {
		return 0, "", err
	}
	if handle, err = b.raw(); err != nil {
		return 0, "", err
	}
	return id, handle, nil
}

// StatusPacket builds a status reply, which is how a refusal is spelled
// to a client without ending the session.
func StatusPacket(id uint32, code uint32, message string) Packet {
	body := make([]byte, 0, 16+len(message))
	body = binary.BigEndian.AppendUint32(body, id)
	body = binary.BigEndian.AppendUint32(body, code)
	body = appendStr(body, message)
	body = appendStr(body, "") // language tag
	return Packet{Type: STATUS, Body: body}
}

func appendStr(b []byte, s string) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(s))) //nolint:gosec // a message this package wrote
	return append(b, s...)
}

type reader struct {
	b   []byte
	pos int
}

func (r *reader) uint32() (uint32, error) {
	if r.pos+4 > len(r.b) {
		return 0, ErrMalformed
	}
	v := binary.BigEndian.Uint32(r.b[r.pos:])
	r.pos += 4
	return v, nil
}

func (r *reader) uint64() (uint64, error) {
	if r.pos+8 > len(r.b) {
		return 0, ErrMalformed
	}
	v := binary.BigEndian.Uint64(r.b[r.pos:])
	r.pos += 8
	return v, nil
}

// rawBytes reads a length-prefixed field without reading anything into
// it: a handle is the server's opaque bytes and file data is the
// client's, and neither is text. It aliases the packet's body rather
// than copying, because the packet is forwarded unchanged and a copy
// per write would be the transfer's cost twice.
func (r *reader) rawBytes() ([]byte, error) {
	n, err := r.uint32()
	if err != nil {
		return nil, err
	}
	if int64(n) > int64(len(r.b)-r.pos) {
		return nil, ErrMalformed
	}
	b := r.b[r.pos : r.pos+int(n)]
	r.pos += int(n)
	return b, nil
}

// raw is rawBytes as a string, for a handle, which is compared and
// never read.
func (r *reader) raw() (string, error) {
	b, err := r.rawBytes()
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (r *reader) str() (string, error) {
	n, err := r.uint32()
	if err != nil {
		return "", err
	}
	if int(n) > len(r.b)-r.pos {
		return "", ErrMalformed
	}
	s := string(r.b[r.pos : r.pos+int(n)])
	r.pos += int(n)
	if !utf8.ValidString(s) || strings.ContainsRune(s, 0) {
		// Version 3 leaves the encoding unstated, which in practice
		// means UTF-8. A name that is not is one the proxy and the
		// server would compare differently, and a path comparison that
		// differs is a policy that does not hold. A NUL is the same
		// problem in its sharpest form: a server reading the name
		// through a C string stops where the proxy did not.
		return "", ErrMalformed
	}
	return s, nil
}

// CleanPath normalises a path for matching: slashes collapsed, "." and
// resolvable ".." removed. A path that still escapes upwards afterwards
// is reported, because its meaning depends on a working directory the
// proxy cannot see.
func CleanPath(p string) (string, bool) {
	if p == "" {
		return "", false
	}
	c := path.Clean(p)
	if c == ".." || strings.HasPrefix(c, "../") {
		return c, false
	}
	return c, true
}

// MatchPath reports whether a cleaned path is covered by a pattern.
// A pattern ending in "/" or "/**" covers a whole tree; otherwise it is
// a path.Match glob, in which "*" does not cross a slash.
func MatchPath(pattern, p string) bool {
	switch {
	case pattern == "" || p == "":
		return false
	case pattern == "/" || pattern == "**" || pattern == "/**":
		return true
	case strings.HasSuffix(pattern, "/**"):
		base := strings.TrimSuffix(pattern, "/**")
		return p == base || strings.HasPrefix(p, base+"/")
	case strings.HasSuffix(pattern, "/"):
		base := strings.TrimSuffix(pattern, "/")
		return p == base || strings.HasPrefix(p, base+"/")
	}
	ok, err := path.Match(pattern, p)
	return err == nil && ok
}

// ReadPacket reads one packet, refusing anything over max before its
// body is allocated.
func ReadPacket(r io.Reader, max int) (Packet, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Packet{}, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 {
		return Packet{}, ErrMalformed
	}
	if max > 0 && int64(n) > int64(max) {
		return Packet{}, ErrTooLarge
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return Packet{}, err
	}
	return Packet{Type: body[0], Body: body[1:]}, nil
}
