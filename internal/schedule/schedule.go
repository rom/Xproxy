// Package schedule is the time window a rule can be limited to, in the one
// spelling every listener kind uses.
//
// Thirteen kinds grew a rule list with a `schedule` section, and thirteen
// grew their own copy of this code -- ten of them byte-identical but for the
// package clause and a paragraph of comment. That is the ordinary cost of
// copying, and it was worth paying while the shape was still being found.
//
// What made it worth stopping is that the copies had drifted, and drifted in
// the direction that matters. `internal/config`'s validation accepts a day
// written either way -- `mon` or `monday` -- because that is what an operator
// writes. The modbus copy accepted both. The other twelve accepted only the
// short form and returned an error for the long one.
//
// So a configuration with `days: [monday]` on any listener but a modbus one
// passed `xrelay -config … -validate`, which said OK, and then failed at
// startup with "monday is not a day". Validation and the runtime disagreed
// about whether a file was valid, which is the worst class of configuration
// bug there is: the check an operator runs before a change window told them
// the change was safe.
//
// The second drift was worse, because nothing failed. The copies held **two
// different answers** to what a window spanning midnight means, so the same YAML
// was in force at different times depending on which listener it was written
// for -- and neither answer was the one `docs/CONFIG.md` describes. InForce says
// what was chosen and what it changes.
//
// One implementation, one answer. Whether a window is *right* is still the
// operator's problem; whether it is *read the same way everywhere* is now
// settled in one place.
package schedule

import (
	"fmt"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/config"
)

// A Window is a compiled time window. A nil *Window is always in force,
// which is what a rule with no `schedule` section means -- and having the nil
// case be the permissive one is deliberate: every caller used to have to
// remember to check, and one that forgot would have refused everything.
type Window struct {
	days   [7]bool
	anyDay bool
	// from and to are minutes since midnight. Equal means the whole day,
	// which is what an omitted `from` and `to` come to.
	from, to int
	loc      *time.Location
}

// Compile reads the configured window. A nil section compiles to a nil
// *Window, so a caller can pass a rule's section straight through.
//
// The error text names the field rather than the value alone, because this is
// reached from thirteen kinds and "not a day" with no field is a message an
// operator cannot act on.
func Compile(c *config.ModbusSchedule) (*Window, error) {
	if c == nil {
		return nil, nil
	}
	w := &Window{loc: time.UTC, anyDay: len(c.Days) == 0}
	for _, d := range c.Days {
		i, ok := DayIndex(d)
		if !ok {
			return nil, fmt.Errorf("schedule.days: %q is not a day (mon to sun, long or short)", d)
		}
		w.days[i] = true
	}
	var err error
	if w.from, err = Minutes(c.From); err != nil {
		return nil, fmt.Errorf("schedule.from: %w", err)
	}
	if w.to, err = Minutes(c.To); err != nil {
		return nil, fmt.Errorf("schedule.to: %w", err)
	}
	if c.Timezone != "" {
		if w.loc, err = time.LoadLocation(c.Timezone); err != nil {
			return nil, fmt.Errorf("schedule.timezone: %w", err)
		}
	}
	return w, nil
}

// DayIndex reads a day name as a configuration writes it, in either the short
// or the long form.
//
// Both, because `internal/config` validates both and a runtime that accepted
// fewer spellings than validation is a runtime that refuses to start on a file
// the operator was told was good.
func DayIndex(d string) (int, bool) {
	switch strings.ToLower(strings.TrimSpace(d)) {
	case "sun", "sunday":
		return 0, true
	case "mon", "monday":
		return 1, true
	case "tue", "tuesday":
		return 2, true
	case "wed", "wednesday":
		return 3, true
	case "thu", "thursday":
		return 4, true
	case "fri", "friday":
		return 5, true
	case "sat", "saturday":
		return 6, true
	}
	return 0, false
}

// Minutes reads "HH:MM" as minutes since midnight. An empty time is midnight,
// which with an equal from and to means the whole day.
func Minutes(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	hh, mm, ok := strings.Cut(s, ":")
	if !ok {
		return 0, fmt.Errorf("%q is not HH:MM", s)
	}
	h, err := atoi(hh)
	if err != nil {
		return 0, fmt.Errorf("%q is not HH:MM", s)
	}
	m, err := atoi(mm)
	if err != nil {
		return 0, fmt.Errorf("%q is not HH:MM", s)
	}
	if h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, fmt.Errorf("%q is not a time of day", s)
	}
	return h*60 + m, nil
}

// atoi reads a one- or two-digit field, and refuses everything else.
//
// It is here rather than strconv.Atoi because Atoi accepts a sign and
// arbitrary width: "+6:00" and "0006:00" would both become six o'clock, and a
// time of day that two readers disagree about is what this package exists to
// stop.
func atoi(s string) (int, error) {
	if len(s) == 0 || len(s) > 2 {
		return 0, fmt.Errorf("%q is not one or two digits", s)
	}
	n := 0
	for _, c := range []byte(s) {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("%q is not digits", s)
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}

// InForce says whether the window includes a moment.
//
// A window whose end is before its start spans midnight, and the question that
// then matters is which day it belongs to. **It belongs to the day it started
// on**: `{days: [fri], from: "22:00", to: "06:00"}` is in force from Friday
// 22:00 until Saturday 06:00, and at no other time. That is what the
// configuration reference means by "a night shift" and what an operator means by
// "Friday night".
//
// This had to be decided rather than merely copied, because the thirteen copies
// held two different answers and neither was that one:
//
//   - Twelve checked the day list against the day the moment falls on, so the
//     same rule was in force during Friday's *own* small hours -- nobody's night
//     shift -- and not during Saturday's, which is the shift that was written.
//   - The modbus copy did that too, and additionally reached into Saturday
//     morning. So it was the union of both readings: Friday 00:00-06:00,
//     Friday 22:00-24:00 and Saturday 00:00-06:00 all in force at once.
//
// Both grant a window nobody asked for. So the reading here is the narrow,
// documented one, and adopting it **changes when a midnight-spanning rule with a
// day list is in force**: the small hours of a named day are no longer covered
// by that day's own evening window, and the small hours after it now are. A rule
// with no day list, or whose window sits inside one day, is unaffected -- which
// is almost every rule anybody has written.
func (w *Window) InForce(now time.Time) bool {
	if w == nil {
		return true
	}
	t := now.In(w.loc)
	mins := t.Hour()*60 + t.Minute()
	switch {
	case w.from == w.to:
		// No times, so the whole of each named day.
		return w.anyDay || w.days[int(t.Weekday())]
	case w.to > w.from:
		// Inside one day: the day and the hours both have to match.
		if !w.anyDay && !w.days[int(t.Weekday())] {
			return false
		}
		return mins >= w.from && mins < w.to
	}
	// Spanning midnight. Before the end is the tail of the window that opened
	// yesterday; at or after the start is the head of today's.
	if mins < w.to {
		return w.anyDay || w.days[int(t.AddDate(0, 0, -1).Weekday())]
	}
	if mins >= w.from {
		return w.anyDay || w.days[int(t.Weekday())]
	}
	return false
}

// Location is the timezone the window is read in, for a caller that wants to
// say so in a log line. It is UTC for a window that named none, and UTC for a
// nil window.
func (w *Window) Location() *time.Location {
	if w == nil || w.loc == nil {
		return time.UTC
	}
	return w.loc
}
