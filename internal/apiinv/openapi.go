package apiinv

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Skeleton renders the endpoints of a report as an OpenAPI 3.0 document
// that an API team can complete: one path item per observed path
// template with the observed methods, path parameters for the variable
// segments, request and response media types, response status classes,
// the credential kinds seen as security schemes and an x-xproxy
// extension with the traffic evidence. Hosts become servers.
func Skeleton(rep Report, title string, now time.Time) map[string]any {
	if title == "" {
		title = "Endpoints discovered by Xproxy"
	}
	paths := map[string]any{}
	hosts := map[string]bool{}
	schemes := map[string]any{}
	byPath := map[string][]Endpoint{}
	var order []string
	for _, e := range rep.Items {
		p := openAPIPath(e.Path)
		if _, ok := byPath[p]; !ok {
			order = append(order, p)
		}
		byPath[p] = append(byPath[p], e)
		hosts[e.Host] = true
	}
	sort.Strings(order)
	for _, p := range order {
		item := map[string]any{}
		params := pathParameters(p)
		if len(params) > 0 {
			item["parameters"] = params
		}
		eps := byPath[p]
		sort.Slice(eps, func(i, j int) bool { return eps[i].Method < eps[j].Method })
		for _, e := range eps {
			op := operationFor(e, schemes)
			m := strings.ToLower(e.Method)
			if existing, ok := item[m].(map[string]any); ok {
				mergeOperation(existing, op)
				continue
			}
			item[m] = op
		}
		paths[p] = item
	}
	doc := map[string]any{
		"openapi": "3.0.3",
		"info": map[string]any{
			"title":       title,
			"version":     now.UTC().Format("2006-01-02"),
			"description": fmt.Sprintf("Skeleton generated from the Xproxy API inventory (view %s, %d endpoints observed since %s). Schemas, descriptions and error responses are to be completed.", rep.View, len(rep.Items), rep.Since.UTC().Format(time.RFC3339)),
		},
		"paths": paths,
	}
	if len(hosts) > 0 {
		var servers []any
		names := make([]string, 0, len(hosts))
		for h := range hosts {
			names = append(names, h)
		}
		sort.Strings(names)
		for _, h := range names {
			servers = append(servers, map[string]any{"url": "https://" + h})
		}
		doc["servers"] = servers
	}
	if len(schemes) > 0 {
		doc["components"] = map[string]any{"securitySchemes": schemes}
	}
	return doc
}

// SkeletonYAML is Skeleton as a YAML document.
func SkeletonYAML(rep Report, title string, now time.Time) ([]byte, error) {
	return yaml.Marshal(Skeleton(rep, title, now))
}

// openAPIPath turns the inventory's "*" segments into named parameters:
// /users/*/orders/* becomes /users/{usersId}/orders/{ordersId}, and a
// leading variable segment {id}.
func openAPIPath(p string) string {
	segs := strings.Split(p, "/")
	used := map[string]int{}
	prev := ""
	for i, s := range segs {
		if s == "*" {
			name := "id"
			if prev != "" && prev != "*" {
				name = paramName(prev) + "Id"
			}
			used[name]++
			if used[name] > 1 {
				name = fmt.Sprintf("%s%d", name, used[name])
			}
			segs[i] = "{" + name + "}"
		}
		prev = s
	}
	return strings.Join(segs, "/")
}

// paramName makes a camelCase identifier out of a path segment.
func paramName(seg string) string {
	var b strings.Builder
	upper := false
	for _, r := range seg {
		switch {
		case r >= 'a' && r <= 'z' || r >= '0' && r <= '9':
			if upper && b.Len() > 0 {
				r -= 'a' - 'A'
			}
			b.WriteRune(r)
			upper = false
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
			upper = false
		default:
			upper = true
		}
	}
	if b.Len() == 0 {
		return "param"
	}
	return b.String()
}

func pathParameters(p string) []any {
	var out []any
	for _, s := range strings.Split(p, "/") {
		if strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") {
			out = append(out, map[string]any{"name": s[1 : len(s)-1], "in": "path", "required": true, "schema": map[string]any{"type": "string"}})
		}
	}
	return out
}

func operationFor(e Endpoint, schemes map[string]any) map[string]any {
	op := map[string]any{
		"summary": fmt.Sprintf("%s %s (observed)", e.Method, e.Path),
	}
	if len(e.ReqTypes) > 0 && e.Method != "GET" && e.Method != "HEAD" && e.Method != "DELETE" {
		content := map[string]any{}
		for _, mt := range e.ReqTypes {
			content[mt] = mediaSchema(mt)
		}
		op["requestBody"] = map[string]any{"required": false, "content": content}
	}
	responses := map[string]any{}
	classes := []struct {
		code  string
		n     uint64
		descr string
	}{{"2XX", e.Status2xx, "Success as observed"}, {"3XX", e.Status3xx, "Redirect as observed"}, {"4XX", e.Status4xx, "Client error as observed"}, {"5XX", e.Status5xx, "Server error as observed"}}
	for _, c := range classes {
		if c.n == 0 {
			continue
		}
		r := map[string]any{"description": c.descr}
		if c.code == "2XX" && len(e.RespTypes) > 0 {
			content := map[string]any{}
			for _, mt := range e.RespTypes {
				content[mt] = mediaSchema(mt)
			}
			r["content"] = content
		}
		responses[c.code] = r
	}
	if len(responses) == 0 {
		responses["default"] = map[string]any{"description": "Not yet observed"}
	}
	op["responses"] = responses
	var security []any
	for _, a := range e.Auth {
		name, scheme := securityScheme(a)
		if name == "" {
			continue
		}
		schemes[name] = scheme
		security = append(security, map[string]any{name: []any{}})
	}
	if len(security) > 0 {
		op["security"] = security
	}
	ext := map[string]any{
		"hosts":      []any{e.Host},
		"requests":   e.Requests,
		"first_seen": e.FirstSeen.UTC().Format(time.RFC3339),
		"last_seen":  e.LastSeen.UTC().Format(time.RFC3339),
	}
	if e.Route != "" {
		ext["route"] = e.Route
	}
	if e.Version != "" {
		ext["version"] = e.Version
	}
	var state []any
	if e.Shadow {
		state = append(state, "shadow")
	}
	if e.Zombie {
		state = append(state, "zombie")
	}
	if e.Superseded {
		state = append(state, "superseded")
	}
	if e.Documented != "" {
		ext["documented"] = e.Documented == "yes"
	}
	if len(state) > 0 {
		ext["state"] = state
	}
	op["x-xproxy"] = ext
	return op
}

// mergeOperation folds a second host's observation of the same method
// and path into the first.
func mergeOperation(dst, src map[string]any) {
	de, _ := dst["x-xproxy"].(map[string]any)
	se, _ := src["x-xproxy"].(map[string]any)
	if de == nil || se == nil {
		return
	}
	dh, _ := de["hosts"].([]any)
	sh, _ := se["hosts"].([]any)
	de["hosts"] = append(dh, sh...)
	if dr, ok := de["requests"].(uint64); ok {
		if sr, ok := se["requests"].(uint64); ok {
			de["requests"] = dr + sr
		}
	}
	if dsec, ok := dst["security"].([]any); ok {
		if ssec, ok := src["security"].([]any); ok {
			dst["security"] = append(dsec, ssec...)
		}
	} else if ssec, ok := src["security"]; ok {
		dst["security"] = ssec
	}
	for code, r := range src["responses"].(map[string]any) {
		if _, ok := dst["responses"].(map[string]any)[code]; !ok {
			dst["responses"].(map[string]any)[code] = r
		}
	}
}

func mediaSchema(mt string) map[string]any {
	switch {
	case strings.Contains(mt, "json"):
		return map[string]any{"schema": map[string]any{"type": "object", "description": "Schema to be completed"}}
	case mt == "application/x-www-form-urlencoded", strings.HasPrefix(mt, "multipart/"):
		return map[string]any{"schema": map[string]any{"type": "object"}}
	}
	return map[string]any{"schema": map[string]any{"type": "string"}}
}

// securityScheme maps the inventory's credential kinds to OpenAPI
// security schemes.
func securityScheme(kind string) (string, map[string]any) {
	switch kind {
	case "bearer":
		return "bearerAuth", map[string]any{"type": "http", "scheme": "bearer"}
	case "basic":
		return "basicAuth", map[string]any{"type": "http", "scheme": "basic"}
	case "api_key":
		return "apiKey", map[string]any{"type": "apiKey", "in": "header", "name": "X-Api-Key"}
	case "cookie":
		return "cookieAuth", map[string]any{"type": "apiKey", "in": "cookie", "name": "session"}
	case "client_cert":
		return "mutualTLS", map[string]any{"type": "mutualTLS"}
	case "other":
		return "otherAuth", map[string]any{"type": "http", "scheme": "other", "description": "An Authorization scheme other than Bearer or Basic was observed"}
	}
	return "", nil
}
