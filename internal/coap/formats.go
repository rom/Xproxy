package coap

import "fmt"

// The content formats of RFC 7252 s12.3 and the registry since, as far as a relay
// needs them: enough to say in a log line what a payload claimed to be, and
// enough for a policy to name the formats an estate carries.
//
// The number is the whole of the declaration -- there is no media type string on
// the wire -- so an unknown number is not a malformed message, it is a
// representation this relay cannot name. Whether an estate carries one it cannot
// name is a decision, and the honest thing is to say which it was.
var contentFormats = map[uint16]string{
	0:     "text/plain",
	16:    "application/cose; cose-type=cose-encrypt0",
	17:    "application/cose; cose-type=cose-mac0",
	18:    "application/cose; cose-type=cose-sign1",
	40:    "application/link-format",
	41:    "application/xml",
	42:    "application/octet-stream",
	47:    "application/exi",
	50:    "application/json",
	51:    "application/json-patch+json",
	52:    "application/merge-patch+json",
	60:    "application/cbor",
	61:    "application/cwt",
	62:    "application/multipart-core",
	63:    "application/cbor-seq",
	110:   "application/senml+json",
	111:   "application/sensml+json",
	112:   "application/senml+cbor",
	113:   "application/sensml+cbor",
	256:   "application/coap-group+json",
	271:   "application/dots+cbor",
	280:   "application/missing-blocks+cbor-seq",
	11542: "application/vnd.oma.lwm2m+tlv",
	11543: "application/vnd.oma.lwm2m+json",
}

// ContentFormatName names a content format, or gives its number.
func ContentFormatName(n uint16) string {
	if s, ok := contentFormats[n]; ok {
		return s
	}
	return fmt.Sprintf("format_%d", n)
}

// ContentFormatOf reads a media type back, for a configuration file.
func ContentFormatOf(name string) (uint16, bool) {
	for n, s := range contentFormats {
		if s == name {
			return n, true
		}
	}
	return 0, false
}

// KnownContentFormat says the number is one this package can name.
func KnownContentFormat(n uint16) bool { _, ok := contentFormats[n]; return ok }

// LinkFormat is the content format of RFC 6690's resource discovery document,
// which is the answer /.well-known/core gives.
//
// It is named on its own because it is the largest answer most devices have and
// the smallest request to ask for, which makes it the amplification vector on this
// protocol rather than just another representation.
const LinkFormat uint16 = 40

// WellKnownCore is the discovery path of RFC 6690 s4.
var WellKnownCore = []string{".well-known", "core"}

// IsWellKnownCore says the request is asking a device to list everything it has.
func (m *Message) IsWellKnownCore() bool {
	segs := m.Segments()
	if len(segs) != len(WellKnownCore) {
		return false
	}
	for i, s := range segs {
		if s != WellKnownCore[i] {
			return false
		}
	}
	return true
}
