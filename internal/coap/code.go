package coap

import "fmt"

// Code is the one octet that is the method in a request and the result in a
// response: three bits of class and five of detail, written c.dd.
//
// The class is the whole of what a relay needs to know to tell a question from an
// answer, which matters on a protocol where both travel in the same shape of
// datagram and either direction can carry either. Class 0 is a request, 2, 4 and
// 5 are responses, and 7 is the signalling of RFC 8323's stream transports, which
// has no business arriving over UDP.
type Code uint8

// The request methods: RFC 7252 s12.1.1 and RFC 8132 for the last three.
const (
	// Empty is the code of a bare acknowledgement or a reset.
	Empty Code = 0
	// GET, POST, PUT and DELETE are RFC 7252's four.
	GET    Code = 1
	POST   Code = 2
	PUT    Code = 3
	DELETE Code = 4
	// FETCH, PATCH and iPATCH are RFC 8132's. FETCH is a GET whose selector is
	// in the payload, so a path policy sees less of it than it sees of a GET --
	// which is worth knowing before allowing it. PATCH and iPATCH modify part
	// of a resource, so they are writes, and iPATCH is the idempotent one.
	FETCH  Code = 5
	PATCH  Code = 6
	IPATCH Code = 7
)

// The response codes worth naming. The rest render as their numbers.
const (
	Created  Code = 2<<5 | 1
	Deleted  Code = 2<<5 | 2
	Valid    Code = 2<<5 | 3
	Changed  Code = 2<<5 | 4
	Content  Code = 2<<5 | 5
	Continue Code = 2<<5 | 31

	BadRequest               Code = 4 << 5
	Unauthorized             Code = 4<<5 | 1
	BadOption                Code = 4<<5 | 2
	Forbidden                Code = 4<<5 | 3
	NotFound                 Code = 4<<5 | 4
	MethodNotAllowed         Code = 4<<5 | 5
	NotAcceptable            Code = 4<<5 | 6
	RequestEntityIncomplete  Code = 4<<5 | 8
	Conflict                 Code = 4<<5 | 9
	PreconditionFailed       Code = 4<<5 | 12
	RequestEntityTooLarge    Code = 4<<5 | 13
	UnsupportedContentFormat Code = 4<<5 | 15
	UnprocessableEntity      Code = 4<<5 | 22
	TooManyRequests          Code = 4<<5 | 29

	InternalServerError  Code = 5 << 5
	NotImplemented       Code = 5<<5 | 1
	BadGateway           Code = 5<<5 | 2
	ServiceUnavailable   Code = 5<<5 | 3
	GatewayTimeout       Code = 5<<5 | 4
	ProxyingNotSupported Code = 5<<5 | 5
	HopLimitReached      Code = 5<<5 | 8

	// The signalling codes of RFC 8323, which belong to CoAP over TCP, TLS and
	// WebSockets. They are named so that one arriving over UDP can be refused
	// by name rather than counted as an unknown response.
	CSM     Code = 7<<5 | 1
	Ping    Code = 7<<5 | 2
	Pong    Code = 7<<5 | 3
	Release Code = 7<<5 | 4
	Abort   Code = 7<<5 | 5
)

// Class is the first digit.
func (c Code) Class() uint8 { return uint8(c) >> 5 }

// Detail is the two after the point.
func (c Code) Detail() uint8 { return uint8(c) & 0x1f }

// IsEmpty says the message is an acknowledgement or a reset carrying nothing.
func (c Code) IsEmpty() bool { return c == Empty }

// IsRequest says the code is a method.
func (c Code) IsRequest() bool { return c.Class() == 0 && c != Empty }

// IsResponse says the code is a result: success, client error or server error.
func (c Code) IsResponse() bool {
	switch c.Class() {
	case 2, 4, 5:
		return true
	}
	return false
}

// IsSignalling says the code belongs to RFC 8323's stream transports.
func (c Code) IsSignalling() bool { return c.Class() == 7 }

// IsSuccess, IsClientError and IsServerError split the responses, because an
// answer a relay carried and an answer a device refused are different records.
func (c Code) IsSuccess() bool     { return c.Class() == 2 }
func (c Code) IsClientError() bool { return c.Class() == 4 }
func (c Code) IsServerError() bool { return c.Class() == 5 }

// Writes says the method changes the resource, which is the distinction an
// estate cares about most: reading a valve's position and moving it are the same
// shape of message one octet apart.
//
// FETCH is a read, even though it carries a payload, because RFC 8132 s2 defines
// it as a safe method.
func (c Code) Writes() bool {
	switch c {
	case POST, PUT, DELETE, PATCH, IPATCH:
		return true
	}
	return false
}

// Known says the code is one this package can name, which is what separates "a
// method nobody defined" from a method with a policy.
func (c Code) Known() bool { return codeNames[c] != "" || c == Empty }

var codeNames = map[Code]string{
	GET: "GET", POST: "POST", PUT: "PUT", DELETE: "DELETE",
	FETCH: "FETCH", PATCH: "PATCH", IPATCH: "iPATCH",

	Created: "Created", Deleted: "Deleted", Valid: "Valid",
	Changed: "Changed", Content: "Content", Continue: "Continue",

	BadRequest: "Bad Request", Unauthorized: "Unauthorized",
	BadOption: "Bad Option", Forbidden: "Forbidden", NotFound: "Not Found",
	MethodNotAllowed: "Method Not Allowed", NotAcceptable: "Not Acceptable",
	RequestEntityIncomplete: "Request Entity Incomplete", Conflict: "Conflict",
	PreconditionFailed:       "Precondition Failed",
	RequestEntityTooLarge:    "Request Entity Too Large",
	UnsupportedContentFormat: "Unsupported Content-Format",
	UnprocessableEntity:      "Unprocessable Entity", TooManyRequests: "Too Many Requests",

	InternalServerError: "Internal Server Error", NotImplemented: "Not Implemented",
	BadGateway: "Bad Gateway", ServiceUnavailable: "Service Unavailable",
	GatewayTimeout: "Gateway Timeout", ProxyingNotSupported: "Proxying Not Supported",
	HopLimitReached: "Hop Limit Reached",

	CSM: "CSM", Ping: "Ping", Pong: "Pong", Release: "Release", Abort: "Abort",
}

// String renders the code the way the standard writes it, number first, because
// the number is what a packet capture shows and the name is what a log reader
// wants: "0.01 GET", "4.04 Not Found".
func (c Code) String() string {
	if c == Empty {
		return "0.00 Empty"
	}
	if name := codeNames[c]; name != "" {
		return fmt.Sprintf("%d.%02d %s", c.Class(), c.Detail(), name)
	}
	return fmt.Sprintf("%d.%02d", c.Class(), c.Detail())
}

// MethodOf reads a method's name back, for a configuration file. The names are
// the standard's own, case as written, because a rule that says GET should look
// like the thing it is about.
func MethodOf(name string) (Code, bool) {
	switch name {
	case "get", "GET":
		return GET, true
	case "post", "POST":
		return POST, true
	case "put", "PUT":
		return PUT, true
	case "delete", "DELETE":
		return DELETE, true
	case "fetch", "FETCH":
		return FETCH, true
	case "patch", "PATCH":
		return PATCH, true
	case "ipatch", "iPATCH", "IPATCH":
		return IPATCH, true
	}
	return 0, false
}

// MethodName is a method's bare name, for a log line and a counter.
func MethodName(c Code) string {
	if name := codeNames[c]; name != "" && c.IsRequest() {
		return name
	}
	return c.String()
}
