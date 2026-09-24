// Package scim serves a SCIM 2.0 Users endpoint (RFC 7643 for the
// schema, RFC 7644 for the protocol) so the directory that owns an
// estate's joiner and leaver process can provision and deprovision the
// credentials this proxy holds: a second-factor enrolment and an API
// key.
//
// The point is the leaver. An account removed in the directory and not
// here is access that still works, and every estate has a story about
// the contractor whose key kept opening the door for a year. Doing it by
// hand needs somebody to remember; doing it over SCIM means the same
// event that closes the mailbox closes this too.
//
// What is implemented is the subset an identity provider actually
// drives, and nothing else:
//
//	GET    {base}/Users              list, with a userName filter
//	POST   {base}/Users              create, which provisions
//	GET    {base}/Users/{id}         read one
//	PUT    {base}/Users/{id}         replace
//	PATCH  {base}/Users/{id}         active, externalId, displayName
//	DELETE {base}/Users/{id}         deprovision
//	GET    {base}/ServiceProviderConfig | /ResourceTypes | /Schemas
//
// Everything else answers a SCIM error object rather than a guess: a
// provisioning endpoint that half-understands an operation is worse than
// one that refuses it, because the directory believes the change landed.
package scim

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The URNs RFC 7643 and RFC 7644 define, and the one extension this
// server adds for what it provisions.
const (
	SchemaUser      = "urn:ietf:params:scim:schemas:core:2.0:User"
	SchemaExtension = "urn:ietf:params:scim:schemas:extension:xproxy:2.0:User"
	SchemaError     = "urn:ietf:params:scim:api:messages:2.0:Error"
	SchemaListResp  = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	SchemaPatchOp   = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	SchemaSPConfig  = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
	SchemaResType   = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"

	// ContentType is the media type RFC 7644 section 3.1 assigns.
	ContentType = "application/scim+json"
)

// MaxBody bounds a request body. A SCIM user resource is a few hundred
// bytes; nothing legitimate is near this.
const MaxBody = 64 << 10

// DefaultMaxResults bounds a page, and is reported in the service
// provider configuration so the client pages rather than discovering the
// bound by being truncated.
const DefaultMaxResults = 100

// Error is a SCIM error response. The store returns one to say what
// went wrong in the protocol's own terms.
type Error struct {
	Status   int
	SCIMType string
	Detail   string
}

func (e *Error) Error() string {
	if e.SCIMType == "" {
		return fmt.Sprintf("scim: %d: %s", e.Status, e.Detail)
	}
	return fmt.Sprintf("scim: %d %s: %s", e.Status, e.SCIMType, e.Detail)
}

// Errorf builds a SCIM error.
func Errorf(status int, scimType, format string, args ...any) *Error {
	return &Error{Status: status, SCIMType: scimType, Detail: fmt.Sprintf(format, args...)}
}

// The scimType values RFC 7644 section 3.12 defines that this server
// uses.
const (
	TypeInvalidFilter = "invalidFilter"
	TypeInvalidPath   = "invalidPath"
	TypeInvalidSyntax = "invalidSyntax"
	TypeInvalidValue  = "invalidValue"
	TypeMutability    = "mutability"
	TypeUniqueness    = "uniqueness"
	TypeTooMany       = "tooMany"
)

// Secrets are the credentials a provisioning step created. They exist
// only in the response to the request that made them: the otpauth URI
// and the recovery codes are the enrolment, and the key is the only
// time the plaintext exists anywhere.
type Secrets struct {
	OTPAuthURI    string   `json:"otpauthUri,omitempty"`
	RecoveryCodes []string `json:"recoveryCodes,omitempty"`
	APIKey        string   `json:"apiKey,omitempty"`
}

// User is one SCIM resource, as this server keeps it.
type User struct {
	ID          string
	UserName    string
	ExternalID  string
	DisplayName string
	Active      bool
	Created     time.Time
	Modified    time.Time

	// Enrolled says whether a second factor is in place, KeyIDs names
	// the API keys provisioned for this user and Scopes their scopes.
	Enrolled bool
	KeyIDs   []string
	Scopes   []string

	// Secrets is set only on the response to a request that created
	// credentials, and is never stored.
	Secrets *Secrets
}

// Store is the resource store the endpoint drives. Every method may
// return an *Error to decide the status itself; any other error is a 500.
type Store interface {
	// List returns the users, filtered by userName when it is not empty.
	List(userName string) ([]User, error)
	Get(id string) (User, error)
	Create(u User) (User, error)
	// Replace applies a whole resource: userName, externalId,
	// displayName, active and the scopes.
	Replace(id string, u User) (User, error)
	// Patch applies the attributes an operation named. A nil field is
	// one the operation did not name.
	Patch(id string, p PatchValues) (User, error)
	Delete(id string) error
}

// PatchValues are the attributes a PATCH named, with nil for the ones it
// did not.
type PatchValues struct {
	Active      *bool
	ExternalID  *string
	DisplayName *string
}

// Config configures the handler.
type Config struct {
	// Base is the path the endpoints hang off, without a trailing
	// slash: "/scim/v2".
	Base string
	// TokenHash is the SHA-256 of the bearer token, hex encoded. A
	// request without the token is refused before the store is touched.
	TokenHash string
	// MaxResults bounds a page.
	MaxResults int
	// ReturnSecrets allows a create to answer with the credentials it
	// made. Off by default: they then exist in the provider's logs and
	// in whatever it stores, which is a decision an operator makes
	// deliberately.
	ReturnSecrets bool
	// ExternalURL is the base this endpoint is reached at from outside,
	// with scheme and host ("https://admin.example.com/scim/v2"). It is
	// what the meta.location and the Location header are built from.
	// Without it they are built from the request, which is right for a
	// proxy terminating TLS itself and wrong behind one that does not:
	// this proxy does not believe a client's own X-Forwarded-Proto for
	// something a provider will follow.
	ExternalURL string
	// Now is the clock, for tests.
	Now func() time.Time
}

// Handler serves the endpoints of one configured SCIM section.
type Handler struct {
	cfg   Config
	store Store
	now   func() time.Time
}

// New builds a handler. The base path is normalised, so "/scim/v2/" and
// "/scim/v2" are the same section.
func New(cfg Config, store Store) (*Handler, error) {
	if store == nil {
		return nil, errors.New("scim: no store")
	}
	if cfg.TokenHash == "" {
		return nil, errors.New("scim: no token")
	}
	cfg.Base = "/" + strings.Trim(cfg.Base, "/")
	if cfg.Base == "/" {
		return nil, errors.New("scim: the base path cannot be the root")
	}
	if cfg.MaxResults <= 0 {
		cfg.MaxResults = DefaultMaxResults
	}
	cfg.ExternalURL = strings.TrimRight(cfg.ExternalURL, "/")
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Handler{cfg: cfg, store: store, now: cfg.Now}, nil
}

// Base is the configured path prefix.
func (h *Handler) Base() string { return h.cfg.Base }

// Covers reports whether a request path belongs to this endpoint. It is
// the base itself or anything under it, never a path that merely starts
// with the same characters ("/scim/v2x" is not this endpoint).
func (h *Handler) Covers(path string) bool {
	return path == h.cfg.Base || strings.HasPrefix(path, h.cfg.Base+"/")
}

// Outcome is what the handler did, for the access log and the counters.
type Outcome struct {
	// Op is the operation: list, get, create, replace, patch, delete,
	// discovery, or "" when the request was refused before one was read.
	Op string
	// User is the resource acted on, when there was one.
	User string
	// Status is what was answered.
	Status int
	// Denied names why a request was refused, for a security event:
	// no_token, bad_token, method, not_found, bad_request or "".
	Denied string
}

// Serve answers one request. It returns what it did.
func (h *Handler) Serve(w http.ResponseWriter, r *http.Request) Outcome {
	if !h.authorised(r) {
		reason := "bad_token"
		if r.Header.Get("Authorization") == "" {
			reason = "no_token"
		}
		// RFC 7644 section 3.12: 401 with the challenge, and no detail
		// about which half was wrong.
		w.Header().Set("WWW-Authenticate", `Bearer realm="scim"`)
		h.writeError(w, Errorf(http.StatusUnauthorized, "", "authentication required"))
		return Outcome{Status: http.StatusUnauthorized, Denied: reason}
	}
	rest := strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, h.cfg.Base), "/")
	head, tail, _ := strings.Cut(rest, "/")
	switch {
	case strings.EqualFold(head, "Users"):
		return h.users(w, r, tail)
	case tail == "" && strings.EqualFold(head, "ServiceProviderConfig"):
		return h.discovery(w, r, h.serviceProviderConfig(r))
	case tail == "" && strings.EqualFold(head, "ResourceTypes"):
		return h.discovery(w, r, h.resourceTypes(r))
	case tail == "" && strings.EqualFold(head, "Schemas"):
		return h.discovery(w, r, h.schemas())
	}
	h.writeError(w, Errorf(http.StatusNotFound, "", "no such endpoint"))
	return Outcome{Status: http.StatusNotFound, Denied: "not_found"}
}

// authorised checks the bearer token in constant time.
func (h *Handler) authorised(r *http.Request) bool {
	const prefix = "Bearer "
	auth := r.Header.Get("Authorization")
	if len(auth) <= len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return false
	}
	sum := sha256.Sum256([]byte(strings.TrimSpace(auth[len(prefix):])))
	got := hex.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(got), []byte(h.cfg.TokenHash)) == 1
}

func (h *Handler) users(w http.ResponseWriter, r *http.Request, id string) Outcome {
	switch {
	case id == "" && r.Method == http.MethodGet:
		return h.list(w, r)
	case id == "" && r.Method == http.MethodPost:
		return h.create(w, r)
	case id == "":
		w.Header().Set("Allow", "GET, POST")
		h.writeError(w, Errorf(http.StatusMethodNotAllowed, "", "%s is not allowed on the collection", r.Method))
		return Outcome{Status: http.StatusMethodNotAllowed, Denied: "method"}
	}
	switch r.Method {
	case http.MethodGet:
		return h.get(w, r, id)
	case http.MethodPut:
		return h.replace(w, r, id)
	case http.MethodPatch:
		return h.patch(w, r, id)
	case http.MethodDelete:
		return h.delete(w, id)
	}
	w.Header().Set("Allow", "GET, PUT, PATCH, DELETE")
	h.writeError(w, Errorf(http.StatusMethodNotAllowed, "", "%s is not allowed on a user", r.Method))
	return Outcome{Status: http.StatusMethodNotAllowed, Denied: "method"}
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) Outcome {
	q := r.URL.Query()
	name, err := ParseFilter(q.Get("filter"))
	if err != nil {
		return h.fail(w, err, "list")
	}
	start := 1
	if s := q.Get("startIndex"); s != "" {
		n, convErr := strconv.Atoi(s)
		if convErr != nil || n < 1 {
			// RFC 7644 section 3.4.2.4: a value less than 1 is
			// interpreted as 1, so this is not an error.
			n = 1
		}
		start = n
	}
	count := h.cfg.MaxResults
	if s := q.Get("count"); s != "" {
		n, convErr := strconv.Atoi(s)
		switch {
		case convErr != nil:
			return h.fail(w, Errorf(http.StatusBadRequest, TypeInvalidValue, "count: %q is not a number", s), "list")
		case n < 0:
			return h.fail(w, Errorf(http.StatusBadRequest, TypeInvalidValue, "count: must not be negative"), "list")
		case n < count:
			count = n
		}
	}
	users, err := h.store.List(name)
	if err != nil {
		return h.fail(w, err, "list")
	}
	sort.Slice(users, func(i, j int) bool { return users[i].UserName < users[j].UserName })
	total := len(users)
	page := users
	if start-1 >= total {
		page = nil
	} else {
		page = page[start-1:]
	}
	if len(page) > count {
		page = page[:count]
	}
	resources := make([]map[string]any, 0, len(page))
	for _, u := range page {
		resources = append(resources, h.resource(r, u))
	}
	body := map[string]any{
		"schemas":      []string{SchemaListResp},
		"totalResults": total,
		"startIndex":   start,
		"itemsPerPage": len(resources),
		"Resources":    resources,
	}
	h.write(w, http.StatusOK, body)
	return Outcome{Op: "list", Status: http.StatusOK}
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request, id string) Outcome {
	u, err := h.store.Get(id)
	if err != nil {
		return h.fail(w, err, "get")
	}
	h.write(w, http.StatusOK, h.resource(r, u))
	return Outcome{Op: "get", User: u.UserName, Status: http.StatusOK}
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) Outcome {
	in, err := h.decode(r)
	if err != nil {
		return h.fail(w, err, "create")
	}
	if in.UserName == "" {
		return h.fail(w, Errorf(http.StatusBadRequest, TypeInvalidValue, "userName is required"), "create")
	}
	u, err := h.store.Create(in)
	if err != nil {
		return h.fail(w, err, "create")
	}
	w.Header().Set("Location", h.location(r, u.ID))
	h.write(w, http.StatusCreated, h.resource(r, u))
	return Outcome{Op: "create", User: u.UserName, Status: http.StatusCreated}
}

func (h *Handler) replace(w http.ResponseWriter, r *http.Request, id string) Outcome {
	in, err := h.decode(r)
	if err != nil {
		return h.fail(w, err, "replace")
	}
	u, err := h.store.Replace(id, in)
	if err != nil {
		return h.fail(w, err, "replace")
	}
	h.write(w, http.StatusOK, h.resource(r, u))
	return Outcome{Op: "replace", User: u.UserName, Status: http.StatusOK}
}

func (h *Handler) patch(w http.ResponseWriter, r *http.Request, id string) Outcome {
	body, err := readBody(r)
	if err != nil {
		return h.fail(w, err, "patch")
	}
	p, err := ParsePatch(body)
	if err != nil {
		return h.fail(w, err, "patch")
	}
	u, err := h.store.Patch(id, p)
	if err != nil {
		return h.fail(w, err, "patch")
	}
	h.write(w, http.StatusOK, h.resource(r, u))
	return Outcome{Op: "patch", User: u.UserName, Status: http.StatusOK}
}

func (h *Handler) delete(w http.ResponseWriter, id string) Outcome {
	// The name is read before the resource goes, so the log says who was
	// deprovisioned rather than an opaque id.
	name := ""
	if u, err := h.store.Get(id); err == nil {
		name = u.UserName
	}
	if err := h.store.Delete(id); err != nil {
		return h.fail(w, err, "delete")
	}
	w.WriteHeader(http.StatusNoContent)
	return Outcome{Op: "delete", User: name, Status: http.StatusNoContent}
}

func (h *Handler) discovery(w http.ResponseWriter, _ *http.Request, body any) Outcome {
	h.write(w, http.StatusOK, body)
	return Outcome{Op: "discovery", Status: http.StatusOK}
}

// fail answers an error, mapping anything that is not an *Error to 500:
// a store failure is this proxy's fault and says nothing else.
func (h *Handler) fail(w http.ResponseWriter, err error, op string) Outcome {
	var se *Error
	if !errors.As(err, &se) {
		se = Errorf(http.StatusInternalServerError, "", "the request could not be completed")
	}
	h.writeError(w, se)
	denied := "bad_request"
	switch {
	case se.Status == http.StatusNotFound:
		denied = "not_found"
	case se.Status >= 500:
		denied = "error"
	}
	return Outcome{Op: op, Status: se.Status, Denied: denied}
}

func (h *Handler) writeError(w http.ResponseWriter, e *Error) {
	body := map[string]any{
		"schemas": []string{SchemaError},
		"status":  strconv.Itoa(e.Status),
		"detail":  e.Detail,
	}
	if e.SCIMType != "" {
		body["scimType"] = e.SCIMType
	}
	h.write(w, e.Status, body)
}

func (h *Handler) write(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", ContentType)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(body)
}

// resource renders a user. The extension attributes say what was
// provisioned; the secrets are there only when the configuration allows
// it and the store made them.
func (h *Handler) resource(r *http.Request, u User) map[string]any {
	schemas := []string{SchemaUser, SchemaExtension}
	ext := map[string]any{
		"mfaEnrolled": u.Enrolled,
		"apiKeyIds":   orEmpty(u.KeyIDs),
		"scopes":      orEmpty(u.Scopes),
	}
	if u.Secrets != nil && h.cfg.ReturnSecrets {
		ext["secrets"] = u.Secrets
	}
	out := map[string]any{
		"schemas":  schemas,
		"id":       u.ID,
		"userName": u.UserName,
		"active":   u.Active,
		"meta": map[string]any{
			"resourceType": "User",
			"created":      u.Created.UTC().Format(time.RFC3339),
			"lastModified": u.Modified.UTC().Format(time.RFC3339),
			"location":     h.location(r, u.ID),
			"version":      version(u),
		},
		SchemaExtension: ext,
	}
	if u.ExternalID != "" {
		out["externalId"] = u.ExternalID
	}
	if u.DisplayName != "" {
		out["displayName"] = u.DisplayName
	}
	return out
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// version is a weak entity tag over what a change moves.
func version(u User) string {
	sum := sha256.Sum256([]byte(u.ID + "|" + u.Modified.UTC().Format(time.RFC3339Nano)))
	return `W/"` + hex.EncodeToString(sum[:8]) + `"`
}

// location is the absolute URI of a resource, which RFC 7644 asks for
// in meta and in the Location header of a create.
func (h *Handler) location(r *http.Request, id string) string {
	if h.cfg.ExternalURL != "" {
		return h.cfg.ExternalURL + "/Users/" + id
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + h.cfg.Base + "/Users/" + id
}
