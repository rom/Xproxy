package mqtt

import (
	"encoding/binary"
	"strings"
)

// Sparkplug B is the convention that turns MQTT into an industrial
// protocol, and the reason it belongs in a proxy is one message type.
//
// A Sparkplug topic says what a message is in its own levels:
//
//	spBv1.0/<group>/<message type>/<node>[/<device>]
//
// Most of those types are telemetry going up: a node or device announcing
// itself (NBIRTH, DBIRTH), saying it is gone (NDEATH, DDEATH), or
// reporting values (NDATA, DDATA). Two go the other way -- NCMD and DCMD
// are *commands to equipment*, the MQTT equivalent of a Modbus write --
// and in most estates the list of publishers that have any business
// sending one is short and known. Reading the topic is what lets a proxy
// enforce that.
//
// Two more things the convention states, which a relay can check and a
// broker does not: data from a node nobody has heard a birth from is out
// of order, and every message from a node carries a sequence number that
// increments by one, wrapping at 255, with a birth resetting it to zero. A
// gap or a repeat is a lost message, a duplicated publisher, or somebody
// replaying one.
//
// What is *not* read is the metrics. A Sparkplug payload is protobuf and
// the metric set is the plant's own; decoding it would mean carrying a
// schema per estate. The top-level fields -- the timestamp and the
// sequence number -- are read, because they are two varints at a fixed
// place in every payload, and the rest is forwarded untouched.

// SparkplugNamespace is the namespace of Sparkplug B, the first level of
// every topic it defines.
const SparkplugNamespace = "spBv1.0"

// The Sparkplug B message types.
const (
	SPNBirth = "NBIRTH"
	SPNDeath = "NDEATH"
	SPDBirth = "DBIRTH"
	SPDDeath = "DDEATH"
	SPNData  = "NDATA"
	SPDData  = "DDATA"
	SPNCmd   = "NCMD"
	SPDCmd   = "DCMD"
	SPState  = "STATE"
)

// sparkplugTypes is every message type the convention defines. A type
// outside it is not a Sparkplug message, and a policy written about
// Sparkplug cannot say anything about one.
var sparkplugTypes = map[string]bool{
	SPNBirth: true, SPNDeath: true, SPDBirth: true, SPDDeath: true,
	SPNData: true, SPDData: true, SPNCmd: true, SPDCmd: true, SPState: true,
}

// SparkplugType says whether a name is one of the message types.
func SparkplugType(s string) bool { return sparkplugTypes[s] }

// SparkplugCommand says whether a message type is a command to
// equipment, which is the half of the convention that needs an author.
func SparkplugCommand(t string) bool { return t == SPNCmd || t == SPDCmd }

// SparkplugBirth says whether a message type is a birth, which is what
// resets a node's sequence and what data has to follow.
func SparkplugBirth(t string) bool { return t == SPNBirth || t == SPDBirth }

// SparkplugData says whether a message type carries values, which is
// what a birth has to precede.
func SparkplugData(t string) bool { return t == SPNData || t == SPDData }

// Sparkplug is a parsed Sparkplug B topic.
type Sparkplug struct {
	Namespace string
	Group     string
	Type      string
	Node      string
	// Device is empty for a node-level message.
	Device string
}

// Edge is the identity a sequence and a birth are tracked against: the
// group and the node, because the sequence belongs to the node whether a
// message is about it or about one of its devices.
func (s Sparkplug) Edge() string { return s.Group + "/" + s.Node }

// ParseSparkplug reads a Sparkplug B topic and says whether it is one.
//
// It is deliberately strict about shape: four levels for a node message
// and five for a device one, no empty levels, and a message type the
// convention defines. A topic that is nearly a Sparkplug topic is not one,
// and treating it as one would mean guessing which level was the node.
func ParseSparkplug(topic string) (Sparkplug, bool) {
	levels := strings.Split(topic, "/")
	if len(levels) < 4 || len(levels) > 5 {
		return Sparkplug{}, false
	}
	for _, l := range levels {
		if l == "" {
			return Sparkplug{}, false
		}
	}
	s := Sparkplug{Namespace: levels[0], Group: levels[1], Type: levels[2], Node: levels[3]}
	if len(levels) == 5 {
		s.Device = levels[4]
	}
	if !sparkplugTypes[s.Type] {
		return Sparkplug{}, false
	}
	// A device-level type needs a device and a node-level type must not
	// have one: the convention's own shapes, and the check that stops a
	// DDATA without a device being read as an NDATA with a spare level.
	switch s.Type {
	case SPDBirth, SPDDeath, SPDData, SPDCmd:
		if s.Device == "" {
			return Sparkplug{}, false
		}
	case SPNBirth, SPNDeath, SPNData, SPNCmd:
		if s.Device != "" {
			return Sparkplug{}, false
		}
	}
	return s, true
}

// SparkplugSeq reads the sequence number from a Sparkplug payload, and
// says whether it found one.
//
// The payload is protobuf: a timestamp in field 1, the metrics in field 2,
// the sequence in field 3, and two optional fields after it. Only the top
// level is read, and a field whose wire type this cannot skip stops the
// reading -- a payload half read is a sequence half known, which is worse
// than not checking.
func SparkplugSeq(payload []byte) (uint64, bool) {
	const maxFields = 64
	b := payload
	for i := 0; i < maxFields && len(b) > 0; i++ {
		key, n := binary.Uvarint(b)
		if n <= 0 {
			return 0, false
		}
		b = b[n:]
		field, wire := key>>3, key&7
		switch wire {
		case 0: // varint
			v, n := binary.Uvarint(b)
			if n <= 0 {
				return 0, false
			}
			b = b[n:]
			if field == 3 {
				return v, true
			}
		case 1: // 64-bit
			if len(b) < 8 {
				return 0, false
			}
			b = b[8:]
		case 2: // length-delimited
			l, n := binary.Uvarint(b)
			if n <= 0 {
				return 0, false
			}
			b = b[n:]
			if uint64(len(b)) < l {
				return 0, false
			}
			b = b[l:]
		case 5: // 32-bit
			if len(b) < 4 {
				return 0, false
			}
			b = b[4:]
		default:
			// A group or a deprecated wire type: this cannot skip it
			// without knowing its length.
			return 0, false
		}
	}
	return 0, false
}

// SparkplugNextSeq is the sequence a message may carry after one that
// carried last: the convention increments by one and wraps at 255.
func SparkplugNextSeq(last uint64) uint64 { return (last + 1) % 256 }
