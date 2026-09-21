// Package grpcmsg reads the gRPC message framing and walks the protobuf
// wire format inside it, without a schema.
//
// A proxy that routes gRPC by its path has read the envelope. The
// messages themselves are length-prefixed frames of protobuf, and a
// proxy that does not read them cannot say how large one message is
// (only how large the whole body is), cannot notice a stream that ends
// in the middle of a frame, and cannot see a message nested a thousand
// deep — which costs the backend's parser far more than it costs the
// sender to write.
//
// No schema is needed for any of that. The protobuf wire format is self
// describing enough to walk: every field carries its number and its wire
// type, and a length-delimited field is either a nested message, a
// string or a blob. This package walks it and reports what it found,
// leaving what to do about it to the caller.
package grpcmsg

import (
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf8"
)

// HeaderSize is the gRPC message header: one compression flag and four
// octets of length.
const HeaderSize = 5

var (
	// ErrShortFrame is a stream that ended in the middle of a frame.
	// It is not the same as a stream that ended: one is a client that
	// finished, the other is a message somebody stopped sending.
	ErrShortFrame = errors.New("grpc: stream ended inside a message")
	// ErrFrameTooLarge is a message over the configured bound.
	ErrFrameTooLarge = errors.New("grpc: message too large")
	// ErrMalformed is a protobuf body that does not walk.
	ErrMalformed = errors.New("grpc: malformed message")
	// ErrTooDeep is a message nested past the configured bound.
	ErrTooDeep = errors.New("grpc: message nested too deep")
	// ErrTooManyFields is a message with more fields than the bound.
	ErrTooManyFields = errors.New("grpc: too many fields")
)

// Frame is one gRPC message: whether it is compressed, and its bytes.
type Frame struct {
	Compressed bool
	Payload    []byte
}

// SplitFrames reads as many whole frames as buf holds and returns them
// with the trailing partial frame, which the caller carries into the
// next read. max bounds one message.
//
// It never allocates for a length it has not received: a header
// claiming four gigabytes is refused on the header alone.
func SplitFrames(buf []byte, max int) (frames []Frame, rest []byte, err error) {
	for {
		if len(buf) < HeaderSize {
			return frames, buf, nil
		}
		n := binary.BigEndian.Uint32(buf[1:5])
		if max > 0 && int64(n) > int64(max) {
			return frames, nil, fmt.Errorf("%w: %d octets", ErrFrameTooLarge, n)
		}
		if int64(len(buf)) < int64(HeaderSize)+int64(n) {
			return frames, buf, nil
		}
		frames = append(frames, Frame{
			Compressed: buf[0] != 0,
			Payload:    buf[HeaderSize : HeaderSize+int(n)],
		})
		buf = buf[HeaderSize+int(n):]
	}
}

// Limits bound what a message may be. A zero field is no bound.
type Limits struct {
	// MaxDepth is how deeply messages may nest. A message nested past
	// it is refused: the cost of parsing one is the backend's, and the
	// cost of writing one is a loop.
	MaxDepth int
	// MaxFields is the total number of fields in one message, at every
	// level.
	MaxFields int
	// MaxStringBytes bounds one string handed to the callback; longer
	// ones are truncated rather than dropped, because a rule about the
	// start of a string still works on the start of it.
	MaxStringBytes int
}

// Report is what a walk found.
type Report struct {
	Depth  int
	Fields int
	// Strings is the number of length-delimited fields that were valid
	// UTF-8 and were therefore handed to the callback.
	Strings int
}

// Walk reads a protobuf message and calls text for every
// length-delimited field whose bytes are valid UTF-8 and are not
// themselves a message. The callback may stop the walk by returning
// false.
//
// Nothing here knows what the fields mean. That is the point: a schema
// would have to be kept in step with the service, and a check that is
// only as current as its schema is a check that quietly stops applying.
func Walk(b []byte, lim Limits, text func(path []int32, s string) bool) (Report, error) {
	w := &walker{lim: lim, text: text}
	if err := w.message(b, 0, nil); err != nil {
		return w.rep, err
	}
	return w.rep, nil
}

type walker struct {
	lim  Limits
	rep  Report
	text func([]int32, string) bool
	stop bool
}

func (w *walker) message(b []byte, depth int, path []int32) error {
	if depth > w.rep.Depth {
		w.rep.Depth = depth
	}
	if w.lim.MaxDepth > 0 && depth >= w.lim.MaxDepth {
		return fmt.Errorf("%w: %d", ErrTooDeep, depth)
	}
	for len(b) > 0 && !w.stop {
		key, n := binary.Uvarint(b)
		if n <= 0 {
			return fmt.Errorf("%w: field key", ErrMalformed)
		}
		b = b[n:]
		num := int32(key >> 3) //nolint:gosec // bounded below
		typ := key & 7
		if num < 1 || key>>3 > 536870911 {
			// Field numbers are 1..2^29-1 (the protobuf language guide).
			return fmt.Errorf("%w: field number %d", ErrMalformed, key>>3)
		}
		w.rep.Fields++
		if w.lim.MaxFields > 0 && w.rep.Fields > w.lim.MaxFields {
			return fmt.Errorf("%w: %d", ErrTooManyFields, w.rep.Fields)
		}
		switch typ {
		case 0: // varint
			_, n := binary.Uvarint(b)
			if n <= 0 {
				return fmt.Errorf("%w: varint", ErrMalformed)
			}
			b = b[n:]
		case 1: // 64-bit
			if len(b) < 8 {
				return fmt.Errorf("%w: 64-bit field", ErrMalformed)
			}
			b = b[8:]
		case 2: // length-delimited
			size, n := binary.Uvarint(b)
			if n <= 0 {
				return fmt.Errorf("%w: length", ErrMalformed)
			}
			b = b[n:]
			// Compared as unsigned. A varint can encode a length
			// larger than a signed integer holds, and comparing that
			// as one makes it negative: the check passes and the slice
			// that follows panics. Every length here is a client's.
			if size > uint64(len(b)) {
				return fmt.Errorf("%w: length past the end", ErrMalformed)
			}
			val := b[:size]
			b = b[size:]
			if err := w.delimited(val, depth, append(path, num)); err != nil {
				return err
			}
		case 5: // 32-bit
			if len(b) < 4 {
				return fmt.Errorf("%w: 32-bit field", ErrMalformed)
			}
			b = b[4:]
		case 3, 4:
			// The deprecated groups. Nothing has emitted them this
			// century, and a walker that guesses at them is a walker
			// whose field count can be made to disagree with the
			// backend's.
			return fmt.Errorf("%w: group wire type %d", ErrMalformed, typ)
		default:
			return fmt.Errorf("%w: wire type %d", ErrMalformed, typ)
		}
	}
	return nil
}

// delimited decides what a length-delimited field is. There is no way
// to know for certain without a schema: the same bytes can be a nested
// message and a string. It is tried as a message first, because a
// nested message that is read as a string is a subtree the depth and
// field bounds never see — and the bounds are the part that matters.
func (w *walker) delimited(val []byte, depth int, path []int32) error {
	if len(val) == 0 {
		return nil
	}
	if looksLikeMessage(val) {
		saved := w.rep.Fields
		if err := w.message(val, depth+1, path); err != nil {
			if errors.Is(err, ErrTooDeep) || errors.Is(err, ErrTooManyFields) {
				return err
			}
			// It did not walk as a message after all, so it is bytes.
			w.rep.Fields = saved
			w.string(val, path)
			return nil
		}
		return nil
	}
	w.string(val, path)
	return nil
}

func (w *walker) string(val []byte, path []int32) {
	if !utf8.Valid(val) || w.text == nil || w.stop {
		return
	}
	if n := w.lim.MaxStringBytes; n > 0 && len(val) > n {
		val = val[:n]
		for len(val) > 0 && !utf8.Valid(val) {
			val = val[:len(val)-1]
		}
	}
	w.rep.Strings++
	if !w.text(path, string(val)) {
		w.stop = true
	}
}

// looksLikeMessage reports whether bytes parse as a protobuf message
// from end to end. It is a guess, and it is the conservative one: a
// string that happens to parse costs a walk, and a message read as a
// string costs a bound.
func looksLikeMessage(b []byte) bool {
	fields := 0
	for len(b) > 0 {
		key, n := binary.Uvarint(b)
		if n <= 0 {
			return false
		}
		b = b[n:]
		if key>>3 < 1 || key>>3 > 536870911 {
			return false
		}
		switch key & 7 {
		case 0:
			_, n := binary.Uvarint(b)
			if n <= 0 {
				return false
			}
			b = b[n:]
		case 1:
			if len(b) < 8 {
				return false
			}
			b = b[8:]
		case 2:
			size, n := binary.Uvarint(b)
			if n <= 0 {
				return false
			}
			rest := b[n:]
			if size > uint64(len(rest)) {
				return false
			}
			b = rest[size:]
		case 5:
			if len(b) < 4 {
				return false
			}
			b = b[4:]
		default:
			return false
		}
		fields++
		if fields > 1<<16 {
			return false
		}
	}
	return fields > 0
}

// Method reads the service and the method from a gRPC path, which is
// "/package.Service/Method".
func Method(path string) (service, method string, ok bool) {
	if len(path) < 3 || path[0] != '/' {
		return "", "", false
	}
	rest := path[1:]
	for i := 0; i < len(rest); i++ {
		if rest[i] == '/' {
			if i == 0 || i == len(rest)-1 {
				return "", "", false
			}
			return rest[:i], rest[i+1:], true
		}
	}
	return "", "", false
}
