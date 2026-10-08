package observability

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// settings are the per-kind settings this test holds to having a reader.
//
// Each is a promise to an operator about what the listener will do, and a
// configuration that accepts one and never reads it is worse than one that
// refuses it: the operator believes the control is in force. These four are the
// ones that say what gets recorded and what gets enforced, which is exactly where
// a silent no-op is most expensive.
var settings = map[string]string{
	"alert_on_deny": "AlertOnDeny",
	"log_requests":  "LogRequests",
	"deny_response": "DenyResponse",
	"monitor_only":  "MonitorOnly",
}

// kindSection maps a listener kind to its configuration struct, read from the
// Listener struct's own fields rather than a list here.
var kindSection = regexp.MustCompile("(?m)^\\t(\\w+)\\s+\\*(\\w+)\\s+`yaml:\"(\\w+)\"`")

// notKinds are the Listener fields that are not listener kinds.
var notKinds = map[string]bool{
	"connection_rate": true, "connection_rate_per_source": true,
	"h3": true, "policy": true, "tls": true,
}

// TestNoKindAcceptsASettingItNeverReads walks the configuration and the kinds
// together, so a setting added to a struct without being wired fails here rather
// than in an incident.
//
// The postgres kind is why this exists. Its `alerts()` was
// `func (t *server) alerts() bool { return true }` -- a stub standing in for a
// setting the listener did not have -- and the kind called it in both refusal
// paths, so the code read as though the control were there. Nothing failed,
// because nothing checked that a gate has something to read.
func TestNoKindAcceptsASettingItNeverReads(t *testing.T) {
	cfg, err := os.ReadFile("../../internal/config/config.go")
	if err != nil {
		t.Fatal(err)
	}
	listener, ok := structBody(string(cfg), "Listener")
	if !ok {
		t.Fatal("the Listener struct has moved")
	}
	var missing []string
	checked := 0
	for _, m := range kindSection.FindAllStringSubmatch(listener, -1) {
		field, kind := m[2], m[3]
		if notKinds[kind] {
			continue
		}
		body, ok := structBody(string(cfg), field)
		if !ok {
			continue
		}
		src, err := packageText(filepath.Join("../../internal/kinds", kind))
		if err != nil {
			// A kind whose package is named differently from its yaml key would
			// be a gap in this test rather than in the code, so say so.
			t.Errorf("no package for kind %q", kind)
			continue
		}
		for key, goName := range settings {
			if !strings.Contains(body, "yaml:\""+key+"\"") {
				continue
			}
			checked++
			// The reader is usually in the kind, and on four kinds it is an
			// accessor beside the struct -- ModbusListener.Alerts() and its
			// siblings -- which the kind then calls. Either counts: what must not
			// happen is a field nothing anywhere reads.
			if strings.Contains(src, goName) || accessorReads(string(cfg), field, goName) {
				continue
			}
			missing = append(missing, kind+": "+key)
		}
	}
	if checked < 60 {
		t.Fatalf("only %d settings were examined; the structs or the yaml keys have moved", checked)
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("these settings are accepted and never read:\n  %s\n"+
			"A control an operator can set and the kind ignores is worse than one "+
			"it does not offer: the operator believes it is in force.", strings.Join(missing, "\n  "))
	}
}

// TestNoKindGatesOnAnAlertSwitchItDoesNotHave is the same invariant from the other
// end: a kind that reads an alert switch must have one to read. A stub returning
// true satisfies the compiler and reads, to anyone maintaining the kind, as a
// control that exists.
func TestNoKindGatesOnAnAlertSwitchItDoesNotHave(t *testing.T) {
	cfg, err := os.ReadFile("../../internal/config/config.go")
	if err != nil {
		t.Fatal(err)
	}
	listener, ok := structBody(string(cfg), "Listener")
	if !ok {
		t.Fatal("the Listener struct has moved")
	}
	section := map[string]string{}
	for _, m := range kindSection.FindAllStringSubmatch(listener, -1) {
		section[m[3]] = m[2]
	}
	var bad []string
	gated := 0
	for kind, field := range section {
		if notKinds[kind] {
			continue
		}
		src, err := packageText(filepath.Join("../../internal/kinds", kind))
		if err != nil {
			continue
		}
		if !alertGate.MatchString(src) {
			continue
		}
		gated++
		body, _ := structBody(string(cfg), field)
		if !strings.Contains(body, `yaml:"alert_on_deny"`) {
			bad = append(bad, kind)
		}
	}
	if gated < 15 {
		t.Fatalf("only %d kinds gate on an alert switch; the spelling has changed", gated)
	}
	sort.Strings(bad)
	if len(bad) > 0 {
		t.Errorf("these kinds gate refusal records on an alert switch their configuration "+
			"has no setting for: %s", strings.Join(bad, ", "))
	}
}

// accessorReads says whether a method on the configuration struct reads the field,
// which is the other place a setting's reader lives.
func accessorReads(cfg, structName, goName string) bool {
	for _, m := range regexp.MustCompile(`func \(\w+ \*`+structName+`\) \w+\(`).FindAllStringIndex(cfg, -1) {
		open := strings.IndexByte(cfg[m[1]:], '{')
		if open < 0 {
			continue
		}
		body, ok := funcBody(cfg, m[1]+open)
		if ok && strings.Contains(body, goName) {
			return true
		}
	}
	return false
}

// structBody is the text between the braces of a named struct.
func structBody(src, name string) (string, bool) {
	i := strings.Index(src, "type "+name+" struct {")
	if i < 0 {
		return "", false
	}
	open := strings.IndexByte(src[i:], '{')
	if open < 0 {
		return "", false
	}
	return funcBody(src, i+open)
}

// packageText is every non-test Go file in a directory, concatenated.
func packageText(dir string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		src, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			return "", err
		}
		b.Write(src)
	}
	return b.String(), nil
}
