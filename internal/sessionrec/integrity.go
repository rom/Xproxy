package sessionrec

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"time"
)

// Integrity for a recording: a hash-chained manifest written beside it.
//
// The access ledger is hash-chained, and the recordings were not. That is the
// wrong way round for what the two are used for. The ledger says a session was
// approved; the recording is the only account of what happened inside it, and
// after an incident it is the artefact somebody is asked to stand behind. A file
// that can be edited afterwards, with nothing that would show it had been, is
// not evidence.
//
// **Why a sidecar rather than the file itself.** A recording is asciicast v2 --
// a JSON header line and one JSON array per event -- and a terminal player reads
// it directly. Interleaving hashes into it would either break every player or
// put the chain in marker events, where it would show up in the replay as
// content. So the chain lives in a file of its own, `<recording>.chain`, and the
// recording stays exactly what it was.
//
// **What the chain is.** One JSON record per line, in the same shape the ledger
// uses: each carries the previous record's hash, and its own hash covers the
// previous hash and the record with the hash field empty. A record describes a
// *segment* of the recording -- an offset, a length and the digest of those
// bytes -- so a recording that was truncated or that stops mid-session still has
// a verifiable prefix, and an edit is localised to a segment rather than only
// known to have happened somewhere.
//
// **What it is worth, exactly.** A chain in a file beside the recording, both
// written by the same process, does not stop somebody who can write both from
// recomputing the whole chain. What it does without a key is detect accidental
// corruption, a truncated file, and any partial edit by anybody who does not
// rewrite every record after it. What it does *with* a key -- and the key is a
// keysource reference, so it can live in Vault or an HSM rather than on the same
// disk -- is make the records unforgeable by somebody who has filesystem access
// and not the key, which is the realistic incident case: an intruder on the box,
// or an administrator editing their own session. It is a MAC and not a
// signature: anybody who can read the key can also forge a record, so the key
// belongs somewhere the recording host cannot read at will.

// ChainExt is the extension of the manifest written beside a recording.
const ChainExt = ".chain"

// DefaultSegmentBytes is how much of a recording one chain record covers when
// the policy names no size. A megabyte keeps the manifest small on a long
// session while still localising an edit to a minute or so of a terminal.
const DefaultSegmentBytes int64 = 1 << 20

// The record kinds of a manifest.
const (
	// ChainOpen is the first record: what file this is about.
	ChainOpen = "open"
	// ChainSegment covers a run of bytes of the recording.
	ChainSegment = "segment"
	// ChainClose is the last: the whole file's digest and its length, which
	// is what says the recording ends where the manifest says it does.
	ChainClose = "close"
)

// ChainRecord is one line of a manifest.
type ChainRecord struct {
	Seq  int64     `json:"seq"`
	At   time.Time `json:"at"`
	Kind string    `json:"kind"`
	// File is the recording's base name, on the open record only. It is the
	// base name rather than the path so that a manifest still verifies after
	// the pair has been moved or archived together.
	File string `json:"file,omitempty"`
	// Offset and Length are the run of the recording this record covers, and
	// Digest is the SHA-256 of exactly those bytes.
	Offset int64  `json:"offset"`
	Length int64  `json:"length,omitempty"`
	Digest string `json:"digest,omitempty"`
	// Truncated says the recording stopped at its byte bound rather than at
	// the end of the session, on the close record. A verifier that did not
	// carry this forward could not tell a truncation the proxy declared from
	// one somebody performed afterwards.
	Truncated bool `json:"truncated,omitempty"`
	// Prev is the previous record's Hash, and Hash covers this record with
	// Hash and MAC empty.
	Prev string `json:"prev"`
	Hash string `json:"hash"`
	// MAC is HMAC-SHA256 of Hash under the configured key, where there is
	// one. Without a key the chain is still a chain; with one it cannot be
	// rewritten by somebody who does not hold the key.
	MAC string `json:"mac,omitempty"`
}

// chainHashOf is the record's hash: the previous hash and the record itself,
// with the fields that cover it emptied so that it covers everything but
// itself.
func chainHashOf(r ChainRecord) string {
	r.Hash, r.MAC = "", ""
	body, err := json.Marshal(r)
	if err != nil {
		// Plain data; unreachable, and a hash that cannot match is the safe
		// answer if it were reached.
		return ""
	}
	sum := sha256.Sum256(append([]byte(r.Prev), body...))
	return hex.EncodeToString(sum[:])
}

// chainLabel separates this use of a configured key from every other
// one. An operator may reasonably point integrity and encryption at the
// same reference, and a key that is an HMAC key here and the input to a
// key derivation there should not be the same string of bytes doing two
// jobs unlabelled.
const chainLabel = "xproxy session recording manifest v1\x00"

// chainMAC is the keyed half.
func chainMAC(key []byte, hashHex string) string {
	if len(key) == 0 {
		return ""
	}
	m := hmac.New(sha256.New, key)
	_, _ = m.Write([]byte(chainLabel))
	_, _ = m.Write([]byte(hashHex))
	return hex.EncodeToString(m.Sum(nil))
}

// chain writes the manifest for one recording.
//
// It holds no lock of its own: every call is made by the Recording that owns it,
// under that recording's mutex.
type chain struct {
	f   *os.File
	key []byte
	// segment is how many bytes of the recording one record covers.
	segment int64
	// whole digests the entire file, and part the current segment; both are
	// fed by the writer the recording's bytes pass through.
	whole, part hash.Hash
	// at is where the current segment starts, and partLen how much of it has
	// been written.
	at, partLen int64
	seq         int64
	prev        string
	err         error
}

// newChain creates the manifest beside a recording and writes its open record.
func newChain(name, base string, key []byte, segment int64) (*chain, error) {
	if segment <= 0 {
		segment = DefaultSegmentBytes
	}
	f, err := os.OpenFile(name+ChainExt, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) //nolint:gosec // beside a file this process just created
	if err != nil {
		return nil, err
	}
	c := &chain{f: f, key: key, segment: segment,
		whole: sha256.New(), part: sha256.New()}
	if err := c.write(ChainRecord{Kind: ChainOpen, File: base}); err != nil {
		_ = f.Close()
		_ = os.Remove(name + ChainExt)
		return nil, err
	}
	return c, nil
}

// write appends one record, linking it to the last.
func (c *chain) write(r ChainRecord) error {
	if c == nil || c.f == nil {
		return nil
	}
	r.Seq, r.At, r.Prev = c.seq, time.Now().UTC(), c.prev
	r.Hash = chainHashOf(r)
	r.MAC = chainMAC(c.key, r.Hash)
	line, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if _, err := c.f.Write(append(line, '\n')); err != nil {
		return err
	}
	c.seq++
	c.prev = r.Hash
	return nil
}

// wrote is called with the bytes that reached the recording, in order.
//
// It is called from the writer the recording's own bytes pass through, which is
// after the buffer rather than before it: what the chain covers has to be what
// is on the disk, not what the proxy meant to put there.
func (c *chain) wrote(b []byte) {
	if c == nil || c.f == nil || c.err != nil {
		return
	}
	for len(b) > 0 {
		room := c.segment - c.partLen
		n := int64(len(b))
		if n > room {
			n = room
		}
		_, _ = c.whole.Write(b[:n])
		_, _ = c.part.Write(b[:n])
		c.partLen += n
		b = b[n:]
		if c.partLen >= c.segment {
			c.closeSegment()
		}
	}
}

// closeSegment writes the record for the segment just filled and starts another.
func (c *chain) closeSegment() {
	if c.partLen == 0 {
		return
	}
	err := c.write(ChainRecord{Kind: ChainSegment, Offset: c.at, Length: c.partLen,
		Digest: hex.EncodeToString(c.part.Sum(nil))})
	if err != nil && c.err == nil {
		c.err = err
	}
	c.at += c.partLen
	c.partLen = 0
	c.part.Reset()
}

// finish writes the last segment and the close record, and closes the manifest.
func (c *chain) finish(truncated bool) error {
	if c == nil || c.f == nil {
		return nil
	}
	c.closeSegment()
	err := c.write(ChainRecord{Kind: ChainClose, Offset: c.at,
		Digest: hex.EncodeToString(c.whole.Sum(nil)), Truncated: truncated})
	if err == nil {
		err = c.f.Sync()
	}
	if cerr := c.f.Close(); err == nil {
		err = cerr
	}
	c.f = nil
	if c.err != nil {
		return c.err
	}
	return err
}

// abandon removes a manifest for a recording that never happened, so a
// failure at open leaves nothing behind.
func (c *chain) abandon(name string) error {
	if c == nil || c.f == nil {
		return nil
	}
	err := c.f.Close()
	c.f = nil
	if rerr := os.Remove(name + ChainExt); err == nil {
		err = rerr
	}
	return err
}

// chainWriter is the seam the recording's bytes pass through on their way to
// the file, so that what is digested is what was written.
type chainWriter struct {
	w io.Writer
	c *chain
}

func (w chainWriter) Write(b []byte) (int, error) {
	n, err := w.w.Write(b)
	if n > 0 {
		w.c.wrote(b[:n])
	}
	return n, err
}

// Verification.

// ErrNoChain says a recording has no manifest beside it, which is not the same
// as having one that does not verify.
var ErrNoChain = errors.New("no integrity manifest beside the recording")

// Verification is what checking a recording against its manifest found.
type Verification struct {
	// File is the recording, and Chain the manifest.
	File, Chain string
	// Records is how many manifest records were read, and Covered how many
	// bytes of the recording the segments accounted for.
	Records int
	Covered int64
	// Keyed says the manifest carries MACs, and Authentic that they verified
	// under the key supplied. A manifest with no MACs is not authentic and
	// not inauthentic: nobody claimed it was.
	Keyed, Authentic bool
	// Truncated is what the proxy recorded about the recording ending early,
	// carried out of the close record so a caller can tell a truncation the
	// proxy declared from a file somebody shortened.
	Truncated bool
}

// Verify checks a recording against the manifest beside it.
//
// key may be nil, in which case the chain's links and the segment digests are
// checked and the MACs are not. Supplying a key when the manifest carries none
// is an error rather than a pass: a caller that asked for authenticity and got
// a manifest that never claimed any should hear about it.
func Verify(recording string, key []byte) (Verification, error) {
	v := Verification{File: recording, Chain: recording + ChainExt}
	lines, err := os.ReadFile(v.Chain)
	if errors.Is(err, os.ErrNotExist) {
		return v, ErrNoChain
	}
	if err != nil {
		return v, err
	}
	data, err := os.ReadFile(recording) //nolint:gosec // the path the caller named
	if err != nil {
		return v, err
	}
	dec := json.NewDecoder(bytes.NewReader(lines))
	var prev string
	var seq int64
	var sawClose bool
	whole := sha256.New()
	for {
		var r ChainRecord
		if err := dec.Decode(&r); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return v, fmt.Errorf("manifest record %d: %w", v.Records, err)
		}
		if sawClose {
			return v, fmt.Errorf("manifest record %d: a record after the close record", r.Seq)
		}
		if r.Seq != seq {
			return v, fmt.Errorf("manifest record %d: out of sequence, expected %d", r.Seq, seq)
		}
		if r.Prev != prev {
			return v, fmt.Errorf("manifest record %d: does not link to the one before it", r.Seq)
		}
		if want := chainHashOf(r); want != r.Hash {
			return v, fmt.Errorf("manifest record %d: its own hash does not cover it", r.Seq)
		}
		if r.MAC != "" {
			v.Keyed = true
			if len(key) == 0 {
				return v, fmt.Errorf("manifest record %d: carries a MAC and no key was given", r.Seq)
			}
			if !hmac.Equal([]byte(r.MAC), []byte(chainMAC(key, r.Hash))) {
				return v, fmt.Errorf("manifest record %d: the MAC does not verify", r.Seq)
			}
		} else if len(key) > 0 {
			return v, fmt.Errorf("manifest record %d: a key was given and the manifest carries no MAC", r.Seq)
		}
		switch r.Kind {
		case ChainOpen:
		case ChainSegment:
			if r.Offset != v.Covered {
				return v, fmt.Errorf("manifest record %d: covers from %d where %d was expected", r.Seq, r.Offset, v.Covered)
			}
			end := r.Offset + r.Length
			if r.Length < 0 || end > int64(len(data)) {
				return v, fmt.Errorf("manifest record %d: covers %d bytes from %d and the recording is %d long",
					r.Seq, r.Length, r.Offset, len(data))
			}
			seg := data[r.Offset:end]
			sum := sha256.Sum256(seg)
			if hex.EncodeToString(sum[:]) != r.Digest {
				return v, fmt.Errorf("manifest record %d: the recording's bytes %d to %d do not match their digest",
					r.Seq, r.Offset, end)
			}
			_, _ = whole.Write(seg)
			v.Covered = end
		case ChainClose:
			sawClose = true
			v.Truncated = r.Truncated
			if r.Offset != v.Covered {
				return v, fmt.Errorf("manifest record %d: closes at %d where the segments reached %d", r.Seq, r.Offset, v.Covered)
			}
			if hex.EncodeToString(whole.Sum(nil)) != r.Digest {
				return v, fmt.Errorf("manifest record %d: the whole recording's digest does not match", r.Seq)
			}
		default:
			return v, fmt.Errorf("manifest record %d: unknown kind %q", r.Seq, r.Kind)
		}
		prev = r.Hash
		seq++
		v.Records++
	}
	if v.Records == 0 {
		return v, errors.New("the manifest is empty")
	}
	if !sawClose {
		// The proxy did not finish: a crash, or a kill. The prefix the
		// manifest covers is verified and the rest is not accounted for,
		// which is a different answer from a file that was edited.
		return v, fmt.Errorf("the manifest has no close record: %d bytes of %d are covered", v.Covered, len(data))
	}
	if v.Covered != int64(len(data)) {
		return v, fmt.Errorf("the recording is %d bytes and the manifest covers %d", len(data), v.Covered)
	}
	// Keyed is only set where a record carried a MAC, and a MAC with no
	// key to check it against has already returned an error above, so a
	// keyed manifest that reached here verified under the key given.
	v.Authentic = v.Keyed
	return v, nil
}
