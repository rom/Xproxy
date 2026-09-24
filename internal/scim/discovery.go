package scim

import "net/http"

// The three read-only endpoints a provider fetches before it provisions
// anything (RFC 7644 section 4). They are how it learns that this server
// supports PATCH but not bulk, and what a page and a filter may be, so
// it does not have to discover either by being refused.

func (h *Handler) serviceProviderConfig(r *http.Request) map[string]any {
	return map[string]any{
		"schemas":          []string{SchemaSPConfig},
		"documentationUri": "https://datatracker.ietf.org/doc/html/rfc7644",
		"patch":            map[string]any{"supported": true},
		"bulk":             map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":           map[string]any{"supported": true, "maxResults": h.cfg.MaxResults},
		"changePassword":   map[string]any{"supported": false},
		"sort":             map[string]any{"supported": false},
		"etag":             map[string]any{"supported": false},
		"authenticationSchemes": []map[string]any{{
			"type":        "oauthbearertoken",
			"name":        "OAuth Bearer Token",
			"description": "A bearer token issued to the provisioning client",
			"primary":     true,
		}},
		"meta": map[string]any{
			"resourceType": "ServiceProviderConfig",
			"location":     h.base(r) + "/ServiceProviderConfig",
		},
	}
}

func (h *Handler) resourceTypes(r *http.Request) map[string]any {
	user := map[string]any{
		"schemas":     []string{SchemaResType},
		"id":          "User",
		"name":        "User",
		"endpoint":    "/Users",
		"description": "A provisioned account: a second factor and an API key",
		"schema":      SchemaUser,
		"schemaExtensions": []map[string]any{{
			"schema":   SchemaExtension,
			"required": false,
		}},
		"meta": map[string]any{
			"resourceType": "ResourceType",
			"location":     h.base(r) + "/ResourceTypes/User",
		},
	}
	return list([]map[string]any{user})
}

func (h *Handler) schemas() map[string]any {
	str := func(name, mutability string, required bool) map[string]any {
		return map[string]any{
			"name": name, "type": "string", "multiValued": false,
			"required": required, "caseExact": false,
			"mutability": mutability, "returned": "default", "uniqueness": "none",
		}
	}
	core := map[string]any{
		"id":          SchemaUser,
		"name":        "User",
		"description": "SCIM core User, in the subset this endpoint provisions",
		"attributes": []map[string]any{
			str("userName", "immutable", true),
			str("externalId", "readWrite", false),
			str("displayName", "readWrite", false),
			{
				"name": "active", "type": "boolean", "multiValued": false,
				"required": false, "mutability": "readWrite", "returned": "default",
			},
		},
	}
	ext := map[string]any{
		"id":          SchemaExtension,
		"name":        "XproxyUser",
		"description": "What this proxy provisioned for the user",
		"attributes": []map[string]any{
			{
				"name": "mfaEnrolled", "type": "boolean", "multiValued": false,
				"required": false, "mutability": "readOnly", "returned": "default",
			},
			{
				"name": "apiKeyIds", "type": "string", "multiValued": true,
				"required": false, "mutability": "readOnly", "returned": "default",
			},
			{
				"name": "scopes", "type": "string", "multiValued": true,
				"required": false, "mutability": "readWrite", "returned": "default",
			},
			{
				"name": "secrets", "type": "complex", "multiValued": false,
				"required": false, "mutability": "readOnly", "returned": "never",
				"description": "The enrolment and the key plaintext, on the response that created them and never again",
			},
		},
	}
	return list([]map[string]any{core, ext})
}

// list wraps resources the way RFC 7644 section 3.4.2 does, which is
// what a provider expects from the discovery endpoints too.
func list(resources []map[string]any) map[string]any {
	return map[string]any{
		"schemas":      []string{SchemaListResp},
		"totalResults": len(resources),
		"startIndex":   1,
		"itemsPerPage": len(resources),
		"Resources":    resources,
	}
}

// base is the absolute base URI, from the configuration when it is set
// and from the request otherwise.
func (h *Handler) base(r *http.Request) string {
	if h.cfg.ExternalURL != "" {
		return h.cfg.ExternalURL
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + h.cfg.Base
}
