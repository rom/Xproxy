package config

import "github.com/rom/xproxy/internal/tmpl"

// ExprVars are the bare variable names an expression (routes[].when,
// header when) may use: the template variables that take no argument.
// header, cookie and query are functions there.
func ExprVars() map[string]bool {
	out := make(map[string]bool, len(tmpl.Vars))
	for name := range tmpl.Vars {
		if !tmpl.TakesArg(name) {
			out[name] = true
		}
	}
	return out
}
