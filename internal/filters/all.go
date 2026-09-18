// Package filters registers the built-in filter kinds. Import it (for its
// side effects) from every binary that loads configuration, and add
// further kinds here: an extension is a package that calls
// filter.Register from init and an import line in this file.
package filters

import (
	_ "github.com/rom/xproxy/internal/filters/basicauth"   // basic_auth
	_ "github.com/rom/xproxy/internal/filters/botscore"    // bot_score
	_ "github.com/rom/xproxy/internal/filters/headerguard" // header_guard
	_ "github.com/rom/xproxy/internal/filters/oidc"        // oidc
)
