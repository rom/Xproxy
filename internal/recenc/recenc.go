// Package recenc encrypts a session recording at rest and reads one back.
//
// A recording holds everything a session showed. On an administrative
// session that is the most valuable file on the machine: keys printed,
// configuration read, tokens echoed, a password typed into a prompt that
// did not echo it. The proxy already writes them 0600 into a directory an
// operator names, which is protection against another user on the same
// host and against nothing else -- not against a backup that leaves the
// building, not against a stolen disk, and not against somebody who
// reaches the file system with the proxy user's rights.
//
// So the bytes on the disk can be ciphertext, under a key that lives in
// custody (see internal/keysource) rather than beside them. What this
// buys is specific: a recording taken away from the host is unreadable,
// and a recording read on the host is readable only by something that can
// resolve the key. It does not hide a session from the proxy itself,
// which is writing it.
//
// # The format
//
// A 32-octet header, then a sequence of AEAD frames:
//
//	"XPROXYREC1" suite reserved salt[16] chunk[4]      -- 32 octets
//	uint32 length, sealed chunk                        -- one per chunk
//	uint32 length, sealed empty plaintext              -- the end
//
// The file key is HKDF-SHA256 of the configured key with the header's
// random salt, so two recordings under one configured key never share a
// key stream, and the salt is in the file rather than derived from
// anything an attacker chooses.
//
// Each frame is sealed with AES-256-GCM under a nonce that is the frame's
// own counter, with the header as its additional data. Those two are what
// hold the file together, and each covers exactly one thing: the nonce
// binds a frame to its position, so a frame moved within the file does not
// open; the header binds every frame to this file's salt, suite and frame
// size, so a frame from another recording does not open and the header
// cannot be edited. The end is an empty frame, which only the key can
// produce, so a file cut short has no end and a reader says so rather than
// reporting a clean end.
//
// An earlier draft of this also put the counter in the additional data and
// a "last frame" octet beside it. Mutation testing showed both were dead:
// the nonce already binds the position, and the writer never seals an
// empty frame except as the end, so nothing could tell the difference. A
// mechanism nobody can write a failing test for is a mechanism that will
// be believed and not checked.
//
// # What it is not
//
// It is a symmetric key, so whoever can read the key can read every
// recording it covers. There is no per-reviewer access and no forward
// secrecy: a key that leaks exposes the recordings it wrote, including
// the ones already written. Rotating the key does not re-encrypt what is
// on disk -- each recording keeps the key it was written under, and the
// old key has to be kept for as long as the recordings it wrote are kept.
package recenc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Ext is what an encrypted recording's name ends in, after the
// container's own extension: session-...cast.enc. A directory listing
// then says which files are ciphertext, and no tool reads one as
// asciicast by mistake.
const Ext = ".enc"

// Magic begins every encrypted recording. It is readable so that
// somebody who runs head(1) on one is told what they have rather than
// left with a screen of binary.
const Magic = "XPROXYREC1"

// HeaderLen is the fixed header: the magic, the suite, one reserved
// octet, the salt and the chunk size.
const HeaderLen = len(Magic) + 1 + 1 + saltLen + 4

const (
	saltLen = 16
	tagLen  = 16
	// suiteAESGCM is the only suite. A second one would change this octet
	// and nothing else about the layout.
	suiteAESGCM = 1
	// info separates this key derivation from every other use of the same
	// configured key.
	info = "xproxy session recording encryption v1"
)

// Chunk bounds. A chunk is what one frame covers, so it decides the
// overhead (16 octets a frame) and how much has to be held in memory
// while a frame is sealed or opened.
const (
	MinChunk     = 4096
	MaxChunk     = 1 << 20
	DefaultChunk = 64 << 10
)

// Errors a reader can return. They are distinguished because the three
// mean different things to somebody holding the file: the first is not an
// encrypted recording at all, the second is the wrong key or an edited
// file, and the third is a file that stops in the middle.
var (
	// ErrNotEncrypted says the file does not begin with the magic.
	ErrNotEncrypted = errors.New("not an encrypted recording")
	// ErrKey says a frame did not open: the key is wrong, or the file was
	// changed after it was written.
	ErrKey = errors.New("the recording did not open under this key")
	// ErrTruncated says the file ended without its final frame.
	ErrTruncated = errors.New("the recording has no end marker: it was truncated, or it is still being written")
)

// Looks reports whether a file begins with the magic. It is what a tool
// uses to decide whether to ask for a key, and it reads the first
// octets only.
func Looks(b []byte) bool {
	return len(b) >= len(Magic) && string(b[:len(Magic)]) == Magic
}

// derive is the file key.
func derive(key, salt []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, key, salt, info, 32)
}

func nonce(counter uint64) []byte {
	var n [12]byte
	binary.BigEndian.PutUint64(n[4:], counter)
	return n[:]
}

// Writer seals a recording as it is written. Close must be called: it
// seals whatever is left and writes the end marker, without which the
// file reads as truncated.
type Writer struct {
	w       io.Writer
	gcm     cipher.AEAD
	header  []byte
	buf     []byte
	chunk   int
	counter uint64
	closed  bool
	err     error
}

// NewWriter writes the header and returns a writer that seals what is
// given to it. chunk of zero is DefaultChunk; a chunk outside the bounds
// is an error rather than a silent clamp, because it comes from
// configuration.
func NewWriter(w io.Writer, key []byte, chunk int) (*Writer, error) {
	if len(key) == 0 {
		return nil, errors.New("recenc: no key")
	}
	if chunk == 0 {
		chunk = DefaultChunk
	}
	if chunk < MinChunk || chunk > MaxChunk {
		return nil, fmt.Errorf("recenc: chunk %d is outside %d..%d", chunk, MinChunk, MaxChunk)
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	header := make([]byte, 0, HeaderLen)
	header = append(header, Magic...)
	header = append(header, suiteAESGCM, 0)
	header = append(header, salt...)
	header = binary.BigEndian.AppendUint32(header, uint32(chunk)) //nolint:gosec // bounded above by MaxChunk
	gcm, err := newGCM(key, salt)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(header); err != nil {
		return nil, err
	}
	return &Writer{w: w, gcm: gcm, header: header, chunk: chunk, buf: make([]byte, 0, chunk)}, nil
}

func newGCM(key, salt []byte) (cipher.AEAD, error) {
	fileKey, err := derive(key, salt)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(fileKey)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Write buffers into chunks and seals each full one.
func (w *Writer) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	if w.closed {
		return 0, errors.New("recenc: write after close")
	}
	n := len(p)
	for len(p) > 0 {
		room := w.chunk - len(w.buf)
		take := min(len(p), room)
		w.buf = append(w.buf, p[:take]...)
		p = p[take:]
		if len(w.buf) == w.chunk {
			if err := w.seal(); err != nil {
				w.err = err
				return n - len(p), err
			}
		}
	}
	return n, nil
}

// seal writes one frame and empties the buffer. An empty buffer is the
// end of the file, which is why Close calls it once more.
func (w *Writer) seal() error {
	frame := w.gcm.Seal(nil, nonce(w.counter), w.buf, w.header)
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(frame))) //nolint:gosec // a chunk plus a tag
	if _, err := w.w.Write(length[:]); err != nil {
		return err
	}
	if _, err := w.w.Write(frame); err != nil {
		return err
	}
	w.counter++
	w.buf = w.buf[:0]
	return nil
}

// Close seals what is left and writes the end marker. It does not close
// the writer underneath, which the caller owns.
func (w *Writer) Close() error {
	if w.closed {
		return nil
	}
	w.closed = true
	if w.err != nil {
		return w.err
	}
	if len(w.buf) > 0 {
		if err := w.seal(); err != nil {
			return err
		}
	}
	// The end: an empty frame. Nobody without the key can produce one, so
	// a file that lacks it was cut short.
	return w.seal()
}

// NewReader reads the header and returns the plaintext.
//
// The reader is strict in the direction that matters: a frame that does
// not open is an error rather than a gap, and reaching the end of the
// file without the end marker is ErrTruncated rather than a clean end. A
// reviewer must not be shown a recording that is missing its middle, or
// its end, as though it were whole.
func NewReader(r io.Reader, key []byte) (io.Reader, error) {
	if len(key) == 0 {
		return nil, errors.New("recenc: no key")
	}
	header := make([]byte, HeaderLen)
	if _, err := io.ReadFull(r, header); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, ErrNotEncrypted
		}
		return nil, err
	}
	if !Looks(header) {
		return nil, ErrNotEncrypted
	}
	if suite := header[len(Magic)]; suite != suiteAESGCM {
		return nil, fmt.Errorf("recenc: unknown suite %d", suite)
	}
	salt := header[len(Magic)+2 : len(Magic)+2+saltLen]
	chunk := int(binary.BigEndian.Uint32(header[len(Magic)+2+saltLen:]))
	if chunk < MinChunk || chunk > MaxChunk {
		return nil, fmt.Errorf("recenc: the header says chunk %d, outside %d..%d", chunk, MinChunk, MaxChunk)
	}
	gcm, err := newGCM(key, salt)
	if err != nil {
		return nil, err
	}
	return &reader{r: r, gcm: gcm, header: header, chunk: chunk}, nil
}

// nothingAfter reports bytes past the end. They cannot put anything into
// the plaintext -- the empty frame ends the stream -- but a file that grew
// after it was written is a fact about the file, and a reader that ignored
// it would be the one place this format lets a change through unmentioned.
func (r *reader) nothingAfter() error {
	var b [1]byte
	switch _, err := io.ReadFull(r.r, b[:]); {
	case errors.Is(err, io.EOF):
		return nil
	case err != nil:
		return err
	}
	return errors.New("recenc: there are bytes after the end of the recording")
}

type reader struct {
	r      io.Reader
	gcm    cipher.AEAD
	header []byte
	chunk  int

	counter uint64
	plain   []byte
	done    bool
	err     error
}

func (r *reader) Read(p []byte) (int, error) {
	for len(r.plain) == 0 {
		if r.err != nil {
			return 0, r.err
		}
		if r.done {
			return 0, io.EOF
		}
		if err := r.frame(); err != nil {
			r.err = err
			return 0, err
		}
	}
	n := copy(p, r.plain)
	r.plain = r.plain[n:]
	return n, nil
}

// frame reads and opens one frame.
func (r *reader) frame() error {
	var length [4]byte
	if _, err := io.ReadFull(r.r, length[:]); err != nil {
		if errors.Is(err, io.EOF) {
			// The end of the file where the end marker should have been.
			return ErrTruncated
		}
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return ErrTruncated
		}
		return err
	}
	n := int(binary.BigEndian.Uint32(length[:]))
	if n < tagLen || n > r.chunk+tagLen {
		return fmt.Errorf("recenc: a frame says %d octets, which is not %d..%d", n, tagLen, r.chunk+tagLen)
	}
	frame := make([]byte, n)
	if _, err := io.ReadFull(r.r, frame); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return ErrTruncated
		}
		return err
	}
	plain, err := r.gcm.Open(nil, nonce(r.counter), frame, r.header)
	if err != nil {
		return ErrKey
	}
	r.counter++
	if len(plain) == 0 {
		// The end. The writer seals an empty frame there and nowhere else.
		r.done = true
		return r.nothingAfter()
	}
	r.plain = plain
	return nil
}
