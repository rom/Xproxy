package scim

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// readBody reads a bounded request body. A body over the bound is
// refused rather than truncated: a resource this server only half read
// is a change the provider believes it made.
func readBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, Errorf(http.StatusBadRequest, TypeInvalidSyntax, "a body is required")
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxBody+1))
	if err != nil {
		return nil, Errorf(http.StatusBadRequest, TypeInvalidSyntax, "the body could not be read")
	}
	if len(body) > MaxBody {
		return nil, Errorf(http.StatusRequestEntityTooLarge, TypeTooMany, "the body is over %d bytes", MaxBody)
	}
	if len(body) == 0 {
		return nil, Errorf(http.StatusBadRequest, TypeInvalidSyntax, "a body is required")
	}
	return body, nil
}

// userDoc is the wire form of a user resource. Unknown attributes are
// refused: an identity provider sending "roles" to a server that ignores
// them has provisioned something that did not happen.
type userDoc struct {
	Schemas     []string `json:"schemas"`
	ID          string   `json:"id"`
	ExternalID  string   `json:"externalId"`
	UserName    string   `json:"userName"`
	DisplayName string   `json:"displayName"`
	Active      *bool    `json:"active"`
	Extension   *extDoc  `json:"urn:ietf:params:scim:schemas:extension:xproxy:2.0:User"`
}

// extDoc is the writable half of the extension: the scopes a
// provisioned API key gets. What the server reports back
// (mfaEnrolled, apiKeyIds) is read-only and refused on the way in.
type extDoc struct {
	Scopes []string `json:"scopes"`
}

// decode reads a user resource from the request.
func (h *Handler) decode(r *http.Request) (User, error) {
	body, err := readBody(r)
	if err != nil {
		return User{}, err
	}
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	var doc userDoc
	if err := dec.Decode(&doc); err != nil {
		return User{}, Errorf(http.StatusBadRequest, TypeInvalidSyntax, "the body is not a user resource: %v", unwrapJSON(err))
	}
	if err := checkSchemas(doc.Schemas, SchemaUser); err != nil {
		return User{}, err
	}
	u := User{
		UserName:    strings.TrimSpace(doc.UserName),
		ExternalID:  doc.ExternalID,
		DisplayName: doc.DisplayName,
		Active:      true,
	}
	if doc.Active != nil {
		u.Active = *doc.Active
	}
	if doc.Extension != nil {
		u.Scopes = doc.Extension.Scopes
	}
	return u, nil
}

// checkSchemas requires the resource to name the schema it is. A
// document with no schemas is refused, because the one thing every SCIM
// client does correctly is send them.
func checkSchemas(schemas []string, want string) error {
	for _, s := range schemas {
		if strings.EqualFold(s, want) {
			return nil
		}
	}
	return Errorf(http.StatusBadRequest, TypeInvalidValue, "schemas must name %s", want)
}

// patchDoc is the wire form of a PATCH request (RFC 7644 section 3.5.2).
type patchDoc struct {
	Schemas    []string  `json:"schemas"`
	Operations []patchOp `json:"Operations"`
	Ops        []patchOp `json:"operations"`
}

type patchOp struct {
	Op    string          `json:"op"`
	Path  string          `json:"path"`
	Value json.RawMessage `json:"value"`
}

// ParsePatch reads the operations this server implements: replace of
// active, externalId and displayName, either as a path with a value or
// as a value object with no path. Anything else is refused by name --
// add and remove of a multi-valued attribute this resource does not
// have, a path this server does not know -- rather than answered 200
// with nothing done.
func ParsePatch(body []byte) (PatchValues, error) {
	var out PatchValues
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	var doc patchDoc
	if err := dec.Decode(&doc); err != nil {
		return out, Errorf(http.StatusBadRequest, TypeInvalidSyntax, "the body is not a patch: %v", unwrapJSON(err))
	}
	if err := checkSchemas(doc.Schemas, SchemaPatchOp); err != nil {
		return out, err
	}
	ops := doc.Operations
	if len(ops) == 0 {
		ops = doc.Ops
	}
	if len(ops) == 0 {
		return out, Errorf(http.StatusBadRequest, TypeInvalidValue, "a patch needs at least one operation")
	}
	if len(ops) > 32 {
		return out, Errorf(http.StatusBadRequest, TypeTooMany, "a patch of %d operations is more than this endpoint applies", len(ops))
	}
	for _, op := range ops {
		if !strings.EqualFold(op.Op, "replace") {
			return out, Errorf(http.StatusBadRequest, TypeInvalidSyntax,
				"only replace is applied here, not %q", op.Op)
		}
		path := strings.TrimSpace(op.Path)
		if path == "" {
			if err := patchObject(op.Value, &out); err != nil {
				return out, err
			}
			continue
		}
		if err := patchPath(path, op.Value, &out); err != nil {
			return out, err
		}
	}
	if out.Active == nil && out.ExternalID == nil && out.DisplayName == nil {
		return out, Errorf(http.StatusBadRequest, TypeInvalidValue, "the patch named nothing this endpoint changes")
	}
	return out, nil
}

// patchObject applies a value object, which is how most providers send a
// deactivation: {"op":"replace","value":{"active":false}}.
func patchObject(raw json.RawMessage, out *PatchValues) error {
	if len(raw) == 0 {
		return Errorf(http.StatusBadRequest, TypeInvalidValue, "replace with no path needs a value object")
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	var v struct {
		Active      *bool   `json:"active"`
		ExternalID  *string `json:"externalId"`
		DisplayName *string `json:"displayName"`
	}
	if err := dec.Decode(&v); err != nil {
		return Errorf(http.StatusBadRequest, TypeInvalidPath,
			"the value names an attribute this endpoint does not change: %v", unwrapJSON(err))
	}
	if v.Active != nil {
		out.Active = v.Active
	}
	if v.ExternalID != nil {
		out.ExternalID = v.ExternalID
	}
	if v.DisplayName != nil {
		out.DisplayName = v.DisplayName
	}
	return nil
}

// patchPath applies one attribute named by a path. The path is the
// attribute name, case insensitive, optionally prefixed with the core
// schema URN, which is what RFC 7644 allows and some providers send.
func patchPath(path string, raw json.RawMessage, out *PatchValues) error {
	attr := path
	if i := strings.LastIndex(attr, ":"); i >= 0 {
		urn, name := attr[:i], attr[i+1:]
		if !strings.EqualFold(urn, SchemaUser) {
			return Errorf(http.StatusBadRequest, TypeInvalidPath, "path %q is not an attribute of a user", path)
		}
		attr = name
	}
	switch {
	case strings.EqualFold(attr, "active"):
		var b bool
		if err := json.Unmarshal(raw, &b); err != nil {
			// A provider that sends "false" as a string is a real
			// provider; the value is read either way, and anything else
			// is refused.
			var s string
			if json.Unmarshal(raw, &s) != nil || (!strings.EqualFold(s, "true") && !strings.EqualFold(s, "false")) {
				return Errorf(http.StatusBadRequest, TypeInvalidValue, "active: %s is not a boolean", raw)
			}
			b = strings.EqualFold(s, "true")
		}
		out.Active = &b
	case strings.EqualFold(attr, "externalId"):
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return Errorf(http.StatusBadRequest, TypeInvalidValue, "externalId: %s is not a string", raw)
		}
		out.ExternalID = &s
	case strings.EqualFold(attr, "displayName"):
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return Errorf(http.StatusBadRequest, TypeInvalidValue, "displayName: %s is not a string", raw)
		}
		out.DisplayName = &s
	case strings.EqualFold(attr, "userName"):
		// The name is what the credentials are keyed on, so it is not
		// something to change under them: a rename is a new user and the
		// old one deprovisioned, said in the directory rather than
		// inferred here.
		return Errorf(http.StatusBadRequest, TypeMutability, "userName cannot be patched; create the new user and deprovision the old one")
	default:
		return Errorf(http.StatusBadRequest, TypeInvalidPath, "path %q is not an attribute this endpoint changes", path)
	}
	return nil
}

// ParseFilter reads the filter subset this endpoint supports:
// `userName eq "value"`, with the attribute name case insensitive. It
// returns the name to match, empty for no filter.
//
// Everything else is refused as invalidFilter rather than ignored, which
// is the trap: a provider that filters by externalId and is answered
// with the whole list would read the first user as the match and
// deprovision somebody else's account.
func ParseFilter(filter string) (string, error) {
	f := strings.TrimSpace(filter)
	if f == "" {
		return "", nil
	}
	if len(f) > 256 {
		return "", Errorf(http.StatusBadRequest, TypeInvalidFilter, "the filter is longer than this endpoint reads")
	}
	rest := f
	attr, rest, ok := nextWord(rest)
	if !ok || !strings.EqualFold(attr, "userName") {
		return "", Errorf(http.StatusBadRequest, TypeInvalidFilter, "only a userName filter is supported here, not %q", f)
	}
	op, rest, ok := nextWord(rest)
	if !ok || !strings.EqualFold(op, "eq") {
		return "", Errorf(http.StatusBadRequest, TypeInvalidFilter, "only eq is supported here, not %q", f)
	}
	value, err := quoted(strings.TrimSpace(rest))
	if err != nil {
		return "", err
	}
	if value == "" {
		return "", Errorf(http.StatusBadRequest, TypeInvalidFilter, "the filter compares against an empty name")
	}
	return value, nil
}

// nextWord takes the next whitespace-separated token.
func nextWord(s string) (word, rest string, ok bool) {
	s = strings.TrimLeft(s, " \t")
	if s == "" {
		return "", "", false
	}
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		return s[:i], s[i:], true
	}
	return s, "", true
}

// quoted reads a JSON string, which is how RFC 7644 spells a filter's
// value, and refuses anything after it.
func quoted(s string) (string, error) {
	if !strings.HasPrefix(s, `"`) {
		return "", Errorf(http.StatusBadRequest, TypeInvalidFilter, "the value must be a quoted string")
	}
	var out string
	dec := json.NewDecoder(strings.NewReader(s))
	if err := dec.Decode(&out); err != nil {
		return "", Errorf(http.StatusBadRequest, TypeInvalidFilter, "the value is not a string")
	}
	if rest := strings.TrimSpace(s[dec.InputOffset():]); rest != "" {
		return "", Errorf(http.StatusBadRequest, TypeInvalidFilter, "only one comparison is supported here")
	}
	return out, nil
}

// unwrapJSON keeps a decoder's message useful without quoting the body
// back at the client.
func unwrapJSON(err error) string {
	msg := err.Error()
	if i := strings.Index(msg, "json: "); i == 0 {
		msg = msg[len("json: "):]
	}
	return fmt.Sprintf("%.200s", msg)
}
