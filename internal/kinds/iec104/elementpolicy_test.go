package iec104

import (
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/iec104"
)

// What the element policies refuse to load, and what they default to.
//
// Everything that can be wrong about one of these is wrong here, at load: a
// bound that would not do what its author meant is worse than no bound, because
// an operator who has written one stops watching the point.

func TestTheQualityDefault(t *testing.T) {
	p, err := compileQuality(nil)
	if err != nil {
		t.Fatal(err)
	}
	// substituted alone: it is the bit that means a person typed the value in,
	// and no HMI in the field shows it.
	if p.alert != wire.QualitySubstituted {
		t.Errorf("the default alerts on %q, want substituted alone", p.alert)
	}
	if p.deny != 0 {
		t.Errorf("the default denies %q, want nothing", p.deny)
	}
	// invalid and not_topical are left out on purpose: they are ordinary on a
	// substation with a device out for maintenance, and alerting on them by
	// default would teach an operator to ignore the alert.
	if p.alert.Invalid() || p.alert.NotTopical() {
		t.Error("the default alerts on a bit a maintenance window produces")
	}
}

// A bit named in deny is alerted on whatever alert_on says: the refusal is the
// event, and an estate that named a bit in one and left it out of the other did
// not mean for the refusal to be silent.
func TestADeniedQualityBitIsAlsoAlertedOn(t *testing.T) {
	p, err := compileQuality(&config.IEC104Quality{AlertOn: []string{}, Deny: []string{"invalid"}})
	if err != nil {
		t.Fatal(err)
	}
	if !p.alert.Invalid() {
		t.Errorf("a denied bit is not alerted on: alert=%q deny=%q", p.alert, p.deny)
	}
	// And an empty alert_on really is empty otherwise, rather than falling back
	// to the default.
	if p.alert.Substituted() {
		t.Error("an explicit empty alert_on fell back to the default")
	}
}

func TestWhatTheQualityPolicyRefusesToLoad(t *testing.T) {
	for _, tc := range []struct {
		name  string
		in    config.IEC104Quality
		wants string
	}{
		{"a bit that is not one", config.IEC104Quality{AlertOn: []string{"suspicious"}},
			`"suspicious" is not a quality bit`},
		{"a bit that is not one, in deny", config.IEC104Quality{Deny: []string{"wrong"}},
			`"wrong" is not a quality bit`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := compileQuality(&tc.in); err == nil {
				t.Fatal("it loaded")
			} else if !contains(err.Error(), tc.wants) {
				t.Errorf("the error is %v, want it to mention %q", err, tc.wants)
			}
		})
	}
	// A name with spaces round it is the same name: a list written across lines
	// in YAML should not fail on whitespace.
	if _, err := compileQuality(&config.IEC104Quality{AlertOn: []string{" blocked "}}); err != nil {
		t.Errorf("a padded name was refused: %v", err)
	}
}

func TestWhatTheMeasurementBoundsRefuseToLoad(t *testing.T) {
	for _, tc := range []struct {
		name  string
		in    config.IEC104Measurement
		wants string
	}{
		{"no name", config.IEC104Measurement{Points: []string{"1"}, Min: f64(0), Max: f64(1)},
			"measurements[0].name: required"},
		{"no points", config.IEC104Measurement{Name: "p", Min: f64(0), Max: f64(1)},
			"measurements.p.points: required"},
		{"one end open", config.IEC104Measurement{Name: "p", Points: []string{"1"}, Min: f64(0)},
			"min and max are both required"},
		{"inside out", config.IEC104Measurement{Name: "p", Points: []string{"1"}, Min: f64(40), Max: f64(0)},
			"min 40 is above max 0"},
		{"an action nobody meant", config.IEC104Measurement{Name: "p", Points: []string{"1"},
			Min: f64(0), Max: f64(1), Action: "shout"}, "action: must be alert or deny"},
		{"a command type", config.IEC104Measurement{Name: "p", Points: []string{"1"},
			Types: []string{"C_SC_NA_1"}, Min: f64(0), Max: f64(1)},
			"carries no measured value this relay reads"},
		{"a type that is not one", config.IEC104Measurement{Name: "p", Points: []string{"1"},
			Types: []string{"M_XX_NA_1"}, Min: f64(0), Max: f64(1)},
			"is not a type identification"},
		{"a type whose element this relay does not decode",
			config.IEC104Measurement{Name: "p", Points: []string{"1"},
				Types: []string{"M_EP_TA_1"}, Min: f64(0), Max: f64(1)},
			"carries no measured value this relay reads"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := compileMeasurements([]config.IEC104Measurement{tc.in}); err == nil {
				t.Fatal("it loaded")
			} else if !contains(err.Error(), tc.wants) {
				t.Errorf("the error is %v, want it to mention %q", err, tc.wants)
			}
		})
	}
	// A bound nothing can satisfy would refuse or alert on every reading and
	// look like a broken relay.
	nan := f64(0)
	*nan = nanOf()
	if _, err := compileMeasurements([]config.IEC104Measurement{
		{Name: "p", Points: []string{"1"}, Min: nan, Max: f64(1)},
	}); err == nil {
		t.Error("a bound of NaN loaded")
	}
	// Two bounds with one name: an alert nobody can attribute to a rule is an
	// alert nobody can act on.
	if _, err := compileMeasurements([]config.IEC104Measurement{
		{Name: "p", Points: []string{"1"}, Min: f64(0), Max: f64(1)},
		{Name: "p", Points: []string{"2"}, Min: f64(0), Max: f64(1)},
	}); err == nil {
		t.Error("two bounds with one name loaded")
	}
}

// The first bound that covers a point decides, so a narrow bound written above a
// wider one is how an exception is made -- the same rule `setpoints` follows.
func TestTheFirstMeasurementBoundThatCoversAPointDecides(t *testing.T) {
	rs, err := compileMeasurements([]config.IEC104Measurement{
		{Name: "exception", Points: []string{"110"}, Min: f64(0), Max: f64(400)},
		{Name: "pressure", Points: []string{"100-140"}, Min: f64(0), Max: f64(40)},
	})
	if err != nil {
		t.Fatal(err)
	}
	a := &wire.ASDU{Type: wire.MMeNB1, Common: 1}
	if !rs[0].covers(a, 110) {
		t.Error("the exception does not cover its own point")
	}
	if !rs[1].covers(a, 110) {
		t.Error("the wider bound does not cover the point either, so order means nothing")
	}
	if rs[0].covers(a, 120) {
		t.Error("the exception covers a point outside it")
	}
}

// A bound that names a common address is about that station and no other: a
// point number means nothing without one, and two substations behind one
// listener use the same numbers for different things.
func TestAMeasurementBoundCanNameAStation(t *testing.T) {
	rs, err := compileMeasurements([]config.IEC104Measurement{
		{Name: "pressure", Points: []string{"100"}, CommonAddresses: []string{"41"},
			Min: f64(0), Max: f64(40)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if rs[0].covers(&wire.ASDU{Type: wire.MMeNB1, Common: 1}, 100) {
		t.Error("a bound for station 41 covered station 1")
	}
	if !rs[0].covers(&wire.ASDU{Type: wire.MMeNB1, Common: 41}, 100) {
		t.Error("a bound for station 41 does not cover station 41")
	}
}

func TestWhatTheTimestampPolicyRefusesToLoad(t *testing.T) {
	if _, err := compileTimestamps(&config.IEC104Timestamps{
		MaxCommandAge: config.Duration(-time.Second),
	}); err == nil {
		t.Error("a negative age loaded")
	}
	// And nothing configured is a policy that evaluates nothing, so an
	// unconfigured listener does not walk the elements of every frame to
	// conclude nothing.
	p, err := compileTimestamps(nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.on() {
		t.Error("an unconfigured timestamp policy says it is on")
	}
	p, err = compileTimestamps(&config.IEC104Timestamps{MaxCommandAge: config.Duration(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if !p.on() {
		t.Error("a configured timestamp policy says it is off")
	}
}

func nanOf() float64 {
	zero := 0.0
	return zero / zero
}
