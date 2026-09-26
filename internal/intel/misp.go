package intel

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// MISP, read as indicators.
//
// MISP is an event store rather than a feed format, and it exposes what it holds
// in three shapes this reads, because a deployment will have whichever one its
// operators already publish:
//
//	{"Event": {"Attribute": [...], "Object": [{"Attribute": [...]}]}}
//	{"response": {"Attribute": [...]}}          /attributes/restSearch
//	{"Attribute": [...]} or a bare [...]        a feed's event file
//
// An attribute is a typed value: type "domain", "url", "ip-dst", "sha256", and
// about two hundred others. The types this proxy can match on are listed below
// and the rest are skipped -- not because they are uninteresting, but because a
// proxy has nothing to compare a bitcoin address or a mutex name against.
//
// Two MISP-specific decisions.
//
// **to_ids is honoured.** MISP marks an attribute to_ids: false to mean "this is
// context, do not detect on it" -- the sending mail server of a phishing report,
// the sandbox that ran the sample, the legitimate service the malware abused.
// Loading those is how a feed takes out a CDN. An attribute with to_ids false is
// skipped, and the count says how many were.
//
// **A composite attribute is split.** MISP writes domain|ip and filename|sha256
// as one value with a bar in it, and each half is an indicator of a different
// kind. Taking the whole string would store an entry that can never match.

// mispDoc is every shape above, decoded at once: whichever field is present is
// the one the document had.
type mispDoc struct {
	Event    *mispEvent    `json:"Event"`
	Response *mispResponse `json:"response"`
	Attrs    []mispAttr    `json:"Attribute"`
	Objects  []mispObject  `json:"Object"`
}

type mispEvent struct {
	Attrs   []mispAttr   `json:"Attribute"`
	Objects []mispObject `json:"Object"`
}

type mispResponse struct {
	Attrs []mispAttr `json:"Attribute"`
}

type mispObject struct {
	Attrs []mispAttr `json:"Attribute"`
}

// mispAttr is the part of an attribute this reads. to_ids and deleted are
// decoded as *bool and *any because MISP writes them as booleans in some
// versions and as the strings "0" and "1" in others, and a field that failed to
// decode would silently become false -- which for to_ids is the wrong default.
type mispAttr struct {
	Type    string `json:"type"`
	Value   string `json:"value"`
	ToIDS   *bool  `json:"to_ids"`
	Deleted *bool  `json:"deleted"`
}

// parseMISP reads any of the shapes above.
func parseMISP(data []byte) (*parsed, error) {
	var attrs []mispAttr
	// A bare array of attributes, which is what some feed files hold.
	if err := json.Unmarshal(data, &attrs); err != nil {
		var doc mispDoc
		if err := json.Unmarshal(data, &doc); err != nil {
			return nil, fmt.Errorf("not a MISP document: %w", err)
		}
		switch {
		case doc.Event != nil:
			attrs = append(attrs, doc.Event.Attrs...)
			for _, o := range doc.Event.Objects {
				attrs = append(attrs, o.Attrs...)
			}
		case doc.Response != nil:
			attrs = doc.Response.Attrs
		default:
			attrs = append(attrs, doc.Attrs...)
			for _, o := range doc.Objects {
				attrs = append(attrs, o.Attrs...)
			}
		}
	}
	if len(attrs) == 0 {
		return nil, errors.New("no attributes in the document")
	}
	out := newParsed()
	for _, a := range attrs {
		if a.Deleted != nil && *a.Deleted {
			continue
		}
		// to_ids absent means MISP's own default for the type, which for the
		// detection types this reads is true. Absent is therefore taken as
		// true; present and false is the publisher saying "context only".
		if a.ToIDS != nil && !*a.ToIDS {
			out.skipped++
			continue
		}
		if !mispAttribute(a.Type, a.Value, out) {
			out.skipped++
		}
	}
	if out.total() == 0 {
		return nil, fmt.Errorf("no indicators this proxy can match on among %d attributes", len(attrs))
	}
	return out, nil
}

// mispAttribute reads one attribute, reporting whether it yielded anything.
func mispAttribute(typ, value string, out *parsed) bool {
	t := strings.ToLower(strings.TrimSpace(typ))
	v := strings.TrimSpace(value)
	if v == "" {
		return false
	}
	// A composite type is halves joined by a bar, each of a different kind.
	if strings.Contains(t, "|") && strings.Contains(v, "|") {
		types := strings.Split(t, "|")
		values := strings.SplitN(v, "|", len(types))
		if len(values) != len(types) {
			return false
		}
		any := false
		for i := range types {
			if mispAttribute(types[i], values[i], out) {
				any = true
			}
		}
		return any
	}
	switch t {
	case "ip-src", "ip-dst", "ip":
		// "ip" is not a MISP attribute type of its own; it is the right half of
		// the composite "domain|ip", and the split above hands each half here
		// under its own name. The port half of "ip-dst|port" arrives as "port"
		// and is not an indicator, which is why it falls through.
		//
		// What is left here is an address or a network.
		if _, err := parsePrefix(v); err != nil {
			return false
		}
		out.add(KindCIDR, v)
		return true
	case "domain", "hostname":
		key, err := domainKey(v)
		if err != nil {
			return false
		}
		out.add(KindDomain, key)
		return true
	case "url", "uri", "link":
		key, err := urlKey(v)
		if err != nil {
			return false
		}
		out.add(KindURL, key)
		return true
	case "md5", "sha1", "sha256", "filename-md5", "filename-sha1", "filename-sha256",
		"authentihash", "imphash", "pehash":
		h, ok := digest(v)
		if !ok {
			return false
		}
		out.add(KindHash, h)
		return true
	case "filename":
		// A name, not an indicator this can match: the proxy sees a
		// Content-Disposition it does not trust and a digest it computed.
		return false
	}
	return false
}
