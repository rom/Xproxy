package expr

import (
	"strings"
	"testing"
)

type env map[string]string

func (e env) Resolve(name, arg string) (string, bool) {
	key := name
	if arg != "" {
		key = name + ":" + arg
	}
	v, ok := e[key]
	return v, ok
}

var vars = map[string]bool{"client_ip": true, "host": true, "path": true, "method": true, "scheme": true, "country": true, "hour": true, "weekday": true, "ja4": true}

func TestEval(t *testing.T) {
	e := env{
		"client_ip": "10.1.2.3", "host": "app.example.com", "path": "/api/v2/items/42", "method": "GET", "scheme": "https",
		"country": "SE", "hour": "14", "weekday": "Tue",
		"header:X-Env": "beta", "header:Content-Length": "2048", "cookie:session": "abc", "query:debug": "1", "capture:id": "42", "capture:1": "v2",
	}
	cases := map[string]bool{
		`method == "GET"`:                                           true,
		`method != "GET"`:                                           false,
		`method in ["GET", "HEAD"]`:                                 true,
		`method not in ["GET", "HEAD"]`:                             false,
		`header("X-Env") == "beta" && scheme == "https"`:            true,
		`header("x-env") == "beta" and not (country == "SE")`:       false,
		`header("Missing") == ""`:                                   true,
		`has_header("Missing")`:                                     false,
		`has_header("X-Env") || false`:                              true,
		`!has_cookie("session")`:                                    false,
		`cookie("session") == "abc"`:                                true,
		`query("debug") == 1`:                                       true,
		`header("Content-Length") > 1024`:                           true,
		`header("Content-Length") < 1024`:                           false,
		`header("Content-Length") >= 2048`:                          true,
		`"b" > "a"`:                                                 true,
		`"10" > "9"`:                                                true, // numeric when both parse
		`"abc" > "9"`:                                               true, // string otherwise
		`client_ip in cidr("10.0.0.0/8", "192.168.1.1")`:            true,
		`client_ip in cidr("192.168.0.0/16")`:                       false,
		`client_ip not in cidr("192.168.0.0/16")`:                   true,
		`path matches "^/api/v[0-9]+/items/[0-9]+$"`:                true,
		`path matches "items/[a-z]+"`:                               false,
		`matches(path, "^/api")`:                                    true,
		`starts_with(path, "/api") && ends_with(path, "42")`:        true,
		`contains(host, "example")`:                                 true,
		`lower("ABC") == "abc" && upper(host) == "APP.EXAMPLE.COM"`: true,
		`len(host) == 15`:                                           true,
		`trim("  x ") == "x"`:                                       true,
		`capture("id") == "42" && capture("1") == "v2"`:             true,
		`hour >= 9 && hour < 17 && weekday not in ["Sat", "Sun"]`:   true,
		`true`:              true,
		`false || (1 == 1)`: true,
		`ja4 == ""`:         true, // unset variable is empty
		`"" == false`:       true, // empty string is falsy against a boolean
		`method`:            true, // bare non-empty string is truthy
		`ja4`:               false,
	}
	for src, want := range cases {
		x, err := Parse(src, vars, "id")
		if err != nil {
			t.Errorf("%s: %v", src, err)
			continue
		}
		if got := x.Eval(e); got != want {
			t.Errorf("%s: got %v want %v", src, got, want)
		}
		if x.String() != src {
			t.Errorf("String() = %q", x.String())
		}
	}
}

func TestParseErrors(t *testing.T) {
	cases := map[string]string{
		``:                                "empty expression",
		`   `:                             "empty expression",
		`bogus == "x"`:                    `unknown variable "bogus"`,
		`nope("x")`:                       `unknown function "nope"`,
		`header()`:                        "takes 1 argument(s), got 0",
		`starts_with(path)`:               "takes 2 argument(s), got 1",
		`path matches "("`:                "pattern at",
		`path matches host`:               "matches needs a quoted pattern",
		`method in "GET"`:                 "in needs a [list]",
		`method in [host]`:                "list items must be quoted",
		`client_ip in cidr("10.0.0.0/x")`: `cidr("10.0.0.0/x")`,
		`client_ip in cidr()`:             "at least one prefix",
		`method == "GET" extra`:           `unexpected "extra"`,
		`(method == "GET"`:                `expected ")"`,
		`method == 'unterminated`:         "unterminated string",
		`method == "x" @`:                 `unexpected character '@'`,
		`capture("nope") == "1"`:          "no such group",
		`capture(host) == "1"`:            "quoted group name",
		`== "x"`:                          `unexpected "=="`,
	}
	for src, want := range cases {
		_, err := Parse(src, vars, "id")
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v want %q", src, err, want)
		}
	}
}

func TestNilEnv(t *testing.T) {
	x := MustParse(`header("X") == "" && !has_header("X") && method == ""`, vars)
	if !x.Eval(nil) {
		t.Fatal("nil env should resolve every variable to empty")
	}
	defer func() {
		if recover() == nil {
			t.Fatal("MustParse did not panic")
		}
	}()
	MustParse(`bogus`, vars)
}

func TestEscapes(t *testing.T) {
	e := env{"header:X": "a\"b'c\n"}
	for _, src := range []string{`header("X") == "a\"b'c\n"`, `header("X") == 'a"b\'c\n'`} {
		if !MustParse(src, vars).Eval(e) {
			t.Errorf("%s: false", src)
		}
	}
}
