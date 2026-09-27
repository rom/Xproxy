package s7

import (
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/config"
)

// What the load refuses about an S7comm-plus section.
//
// Every one of these is a policy that would not do what its author meant, and
// on this protocol that is worse than no policy: an operator who has written a
// section stops asking whether TIA Portal is being policed.

func TestAnS7CommPlusSectionThatWouldNotWorkIsRefusedAtLoad(t *testing.T) {
	t.Parallel()
	for what, cp := range map[string]*config.S7CommPlus{
		"a mode nobody has": {Mode: "inspect"},
		"an unknown answer": {Mode: "policy", DefaultAction: "maybe"},
		"a function nobody has": {Mode: "policy",
			Functions: []string{"set_the_clock"}},
		"a class nobody has": {Mode: "policy", Classes: []string{"program"}},
		"a hex code too wide": {Mode: "policy",
			Functions: []string{"0x1054c"}},
		// The one that is a mistake rather than a typo: a policy written in a
		// mode that never reads it. Almost always a mode somebody forgot.
		"a policy the mode never reads": {Classes: []string{"read"}},
		"a policy in passthrough":       {Mode: "passthrough", DenyClasses: []string{"admin"}},
	} {
		if _, err := compilePlus(&config.S7Listener{CommPlus: cp}); err == nil {
			t.Errorf("%s: compiled", what)
		}
	}
}

// And what it accepts, including the shapes an operator actually writes.
func TestTheS7CommPlusSectionsThatWork(t *testing.T) {
	t.Parallel()
	for what, cp := range map[string]*config.S7CommPlus{
		"nothing at all":       nil,
		"refuse, said plainly": {Mode: "refuse"},
		"reads only":           {Mode: "policy", Classes: []string{"read"}},
		"a function by name":   {Mode: "policy", Functions: []string{"get_multi_variables"}},
		"a function by number": {Mode: "policy", Functions: []string{"0x054c"}},
		"a carve-out": {Mode: "policy", Classes: []string{"read", "write"},
			DenyFunctions: []string{"set_variable"}},
		"the unknown class named": {Mode: "policy", Classes: []string{"unknown"}},
		"passthrough":             {Mode: "passthrough"},
	} {
		if _, err := compilePlus(&config.S7Listener{CommPlus: cp}); err != nil {
			t.Errorf("%s: %v", what, err)
		}
	}
}

// A listener with no section refuses the variant, which is what every
// configuration written before this section existed meant. Changing that
// default would have widened every deployed s7 listener silently.
func TestNoSectionMeansTheVariantIsRefused(t *testing.T) {
	t.Parallel()
	p, err := compilePlus(&config.S7Listener{})
	if err != nil {
		t.Fatal(err)
	}
	if p.Enabled() {
		t.Error("a listener with no s7comm_plus section carries S7comm-plus")
	}
	if d := p.Plus(nil); d.Allow || !d.Hard {
		t.Errorf("the refusal is %+v, want a hard refusal", d)
	}
}

// The listener's read_only switch reaches the S7comm-plus policy. It is a
// separate compile, so this is the join that a change to either side could
// quietly break.
func TestReadOnlyReachesTheS7CommPlusPolicy(t *testing.T) {
	t.Parallel()
	p, err := compilePlus(&config.S7Listener{
		ReadOnly: true,
		CommPlus: &config.S7CommPlus{Mode: "policy", Classes: []string{"read", "write"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !p.readOnly {
		t.Fatal("read_only did not reach the S7comm-plus policy")
	}
}

// The function-name error names the alternatives, because an operator who has
// mistyped one needs the list rather than a rejection.
func TestTheFunctionNameErrorSaysWhatIsAccepted(t *testing.T) {
	t.Parallel()
	_, err := compilePlus(&config.S7Listener{
		CommPlus: &config.S7CommPlus{Mode: "policy", Functions: []string{"nonsense"}},
	})
	if err == nil {
		t.Fatal("a function name nobody has compiled")
	}
	if !strings.Contains(err.Error(), "hex") {
		t.Errorf("the error does not mention the hex alternative: %v", err)
	}
}
