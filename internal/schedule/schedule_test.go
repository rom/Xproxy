package schedule

import (
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
)

// at is a moment, in UTC unless a test says otherwise.
func at(day time.Weekday, hh, mm int) time.Time {
	// 2026-01-04 is a Sunday, so adding the weekday's number lands on it.
	return time.Date(2026, 1, 4+int(day), hh, mm, 0, 0, time.UTC)
}

func compile(t *testing.T, c *config.ModbusSchedule) *Window {
	t.Helper()
	w, err := Compile(c)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return w
}

// The defect this package was written for: validation accepts a day written
// either way, and twelve of the thirteen copies accepted only the short form.
// A configuration with `days: [monday]` therefore passed `-validate` and then
// refused to start.
func TestADayIsReadInBothSpellings(t *testing.T) {
	for _, c := range []struct {
		in   string
		want int
	}{
		{"sun", 0}, {"sunday", 0}, {"Sunday", 0}, {" SUNDAY ", 0},
		{"mon", 1}, {"monday", 1},
		{"tue", 2}, {"tuesday", 2},
		{"wed", 3}, {"wednesday", 3},
		{"thu", 4}, {"thursday", 4},
		{"fri", 5}, {"friday", 5},
		{"sat", 6}, {"saturday", 6},
	} {
		got, ok := DayIndex(c.in)
		if !ok || got != c.want {
			t.Errorf("DayIndex(%q) = %d, %v; want %d, true", c.in, got, ok, c.want)
		}
	}
	// And the spellings validation does not accept are still refused here,
	// because a day this package guessed at would be a window nobody wrote.
	for _, s := range []string{"", "m", "mo", "mondays", "tues", "weekday", "1", "月"} {
		if _, ok := DayIndex(s); ok {
			t.Errorf("DayIndex(%q) accepted it", s)
		}
	}
}

// TestTheSpellingsAgreeWithValidation is the assertion that stops the drift
// coming back: every day name the configuration validator accepts has to
// compile, or a file that passes -validate fails at startup again.
func TestTheSpellingsAgreeWithValidation(t *testing.T) {
	for _, d := range []string{
		"mon", "monday", "tue", "tuesday", "wed", "wednesday", "thu", "thursday",
		"fri", "friday", "sat", "saturday", "sun", "sunday",
	} {
		c := &config.ModbusSchedule{Days: []string{d}, From: "06:00", To: "14:00"}
		if _, err := Compile(c); err != nil {
			t.Errorf("validation accepts the day %q and Compile refuses it: %v", d, err)
		}
	}
}

func TestANilWindowIsAlwaysInForce(t *testing.T) {
	var w *Window
	if !w.InForce(at(time.Wednesday, 3, 0)) {
		t.Error("a nil window refused a moment")
	}
	if got, err := Compile(nil); got != nil || err != nil {
		t.Errorf("Compile(nil) = %v, %v", got, err)
	}
	if w.Location() != time.UTC {
		t.Error("a nil window's location is not UTC")
	}
}

func TestAWindowWithinOneDay(t *testing.T) {
	w := compile(t, &config.ModbusSchedule{Days: []string{"sat"}, From: "06:00", To: "14:00"})
	for _, c := range []struct {
		name string
		when time.Time
		want bool
	}{
		{"the minute it opens", at(time.Saturday, 6, 0), true},
		{"the middle", at(time.Saturday, 10, 30), true},
		{"the minute before it opens", at(time.Saturday, 5, 59), false},
		// The end is exclusive, which is what makes two adjacent windows
		// not overlap on the minute they meet.
		{"the minute it closes", at(time.Saturday, 14, 0), false},
		{"the same hour on another day", at(time.Sunday, 10, 30), false},
	} {
		if got := w.InForce(c.when); got != c.want {
			t.Errorf("%s: in force = %v, want %v", c.name, got, c.want)
		}
	}
}

// A window with no times is the whole of the named days, which is how "the
// integrator may do this at all on a Saturday" is written.
func TestAWindowWithNoTimesIsTheWholeDay(t *testing.T) {
	w := compile(t, &config.ModbusSchedule{Days: []string{"sat"}})
	if !w.InForce(at(time.Saturday, 0, 0)) || !w.InForce(at(time.Saturday, 23, 59)) {
		t.Error("the whole day is not the whole day")
	}
	if w.InForce(at(time.Friday, 12, 0)) {
		t.Error("another day was in force")
	}
}

// A window with no days is every day, which is how "only during the night" is
// written.
func TestAWindowWithNoDaysIsEveryDay(t *testing.T) {
	w := compile(t, &config.ModbusSchedule{From: "22:00", To: "06:00"})
	for d := time.Sunday; d <= time.Saturday; d++ {
		if !w.InForce(at(d, 23, 0)) {
			t.Errorf("%s at 23:00 was not in force", d)
		}
		if w.InForce(at(d, 12, 0)) {
			t.Errorf("%s at noon was in force", d)
		}
	}
}

// The midnight-spanning behaviour, which is the one the thirteen copies
// disagreed about. A window belongs to the day it started on, so a Friday night
// shift reaches into Saturday's small hours -- which is what the configuration
// reference means by "a night shift" and what the modbus copy did.
func TestAWindowSpanningMidnightBelongsToTheDayItStartedOn(t *testing.T) {
	w := compile(t, &config.ModbusSchedule{Days: []string{"fri"}, From: "22:00", To: "06:00"})
	for _, c := range []struct {
		name string
		when time.Time
		want bool
	}{
		{"Friday evening, after it opens", at(time.Friday, 22, 0), true},
		{"Friday, late", at(time.Friday, 23, 59), true},
		{"Saturday's small hours, the same shift", at(time.Saturday, 2, 0), true},
		{"Saturday at the closing minute", at(time.Saturday, 6, 0), false},
		{"Saturday evening, a day nobody named", at(time.Saturday, 23, 0), false},
		{"Friday's own small hours, which are Thursday's shift", at(time.Friday, 2, 0), false},
		{"Friday afternoon", at(time.Friday, 15, 0), false},
	} {
		if got := w.InForce(c.when); got != c.want {
			t.Errorf("%s: in force = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestTheOldReadingIsGone is the regression that documents the change rather
// than only making it. Twelve of the thirteen copies checked the day list
// against the day the *moment* falls on, which read a Friday night shift as
// Friday's own small hours -- a window nobody wrote -- and refused Saturday's,
// which is the one they did. Both halves are asserted, because a fix that only
// closed the wrong window would have left the right one closed too.
func TestTheOldReadingIsGone(t *testing.T) {
	w := compile(t, &config.ModbusSchedule{Days: []string{"fri"}, From: "22:00", To: "06:00"})
	if w.InForce(at(time.Friday, 3, 0)) {
		t.Error("Friday's own small hours are in force, which is the old reading")
	}
	if !w.InForce(at(time.Saturday, 3, 0)) {
		t.Error("Saturday's small hours are not in force, which is the old reading")
	}
}

// A consecutive pair of night shifts: naming two days means the tail of each
// reaches into the next morning, and the morning after the last one is covered
// while the morning after a day nobody named is not.
func TestTwoNamedNightsEachReachIntoTheirMorning(t *testing.T) {
	w := compile(t, &config.ModbusSchedule{Days: []string{"fri", "sat"}, From: "22:00", To: "06:00"})
	for _, c := range []struct {
		name string
		when time.Time
		want bool
	}{
		{"Friday night", at(time.Friday, 23, 0), true},
		{"Saturday morning", at(time.Saturday, 3, 0), true},
		{"Saturday night", at(time.Saturday, 23, 0), true},
		{"Sunday morning", at(time.Sunday, 3, 0), true},
		{"Sunday night", at(time.Sunday, 23, 0), false},
		{"Monday morning", at(time.Monday, 3, 0), false},
		{"Friday morning", at(time.Friday, 3, 0), false},
	} {
		if got := w.InForce(c.when); got != c.want {
			t.Errorf("%s: in force = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestTheWindowIsReadInItsOwnTimezone(t *testing.T) {
	w := compile(t, &config.ModbusSchedule{From: "09:00", To: "17:00",
		Timezone: "Europe/Stockholm"})
	if w.Location().String() != "Europe/Stockholm" {
		t.Errorf("the location is %s", w.Location())
	}
	// 07:00 UTC in January is 08:00 in Stockholm, which is before the window;
	// 08:00 UTC is 09:00, which opens it.
	if w.InForce(time.Date(2026, 1, 7, 7, 0, 0, 0, time.UTC)) {
		t.Error("the window was in force an hour early")
	}
	if !w.InForce(time.Date(2026, 1, 7, 8, 0, 0, 0, time.UTC)) {
		t.Error("the window did not open")
	}
	// And in July the offset is two hours, so the same local window is an
	// hour earlier in UTC. A window read in UTC would be wrong for half the
	// year, which is the reason the timezone is carried rather than applied
	// once at compile time.
	if !w.InForce(time.Date(2026, 7, 7, 7, 0, 0, 0, time.UTC)) {
		t.Error("the window did not follow the summer offset")
	}
}

func TestWhatCannotBeCompiled(t *testing.T) {
	for _, c := range []struct {
		name string
		in   *config.ModbusSchedule
	}{
		{"a day that is not one", &config.ModbusSchedule{Days: []string{"caturday"}}},
		{"a time that is not HH:MM", &config.ModbusSchedule{From: "9am"}},
		{"an hour that does not exist", &config.ModbusSchedule{From: "24:00"}},
		{"a minute that does not exist", &config.ModbusSchedule{To: "10:60"}},
		{"a negative hour", &config.ModbusSchedule{From: "-1:00"}},
		{"a timezone that is not one", &config.ModbusSchedule{Timezone: "Mars/Olympus"}},
		// A signed or padded field would be read as a time by strconv.Atoi,
		// and a time two readers disagree about is what this refuses.
		{"a signed hour", &config.ModbusSchedule{From: "+6:00"}},
		{"a padded hour", &config.ModbusSchedule{From: "006:00"}},
		{"no separator", &config.ModbusSchedule{From: "0600"}},
		{"an empty field", &config.ModbusSchedule{From: ":"}},
	} {
		if _, err := Compile(c.in); err == nil {
			t.Errorf("%s compiled", c.name)
		}
	}
}

// Minutes is exported because two kinds read a clock outside a schedule, and
// its edges are worth pinning on their own.
func TestMinutes(t *testing.T) {
	for _, c := range []struct {
		in   string
		want int
	}{
		{"", 0}, {"00:00", 0}, {"0:00", 0}, {"6:05", 365},
		{"09:30", 570}, {"23:59", 1439}, {" 12:00 ", 720},
	} {
		got, err := Minutes(c.in)
		if err != nil || got != c.want {
			t.Errorf("Minutes(%q) = %d, %v; want %d", c.in, got, err, c.want)
		}
	}
}
