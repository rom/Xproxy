// Package schema embeds the JSON schema of the configuration for editors
// and validators. The file is generated from the types in package config;
// regenerate with go generate after changing them.
package schema

import _ "embed"

//go:generate go run ./gen -src ../config.go -out xproxy.schema.json

// JSON is the schema document (JSON Schema draft 2020-12).
//
//go:embed xproxy.schema.json
var JSON []byte
