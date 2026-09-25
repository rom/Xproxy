package postgres

import (
	"fmt"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/config"
)

// A compiled time window, the same shape the modbus, iec104, snmp and ldap
// kinds use, because a schedule in a rule means the same thing on every
// protocol and `{days, from, to, timezone}` is what an operator writes in all
// of them.
//
// On this kind it earns its keep more than on most: a firmware window is a
// schedule, and "writes are allowed during the change window and refused
// outside it" is the rule an estate actually wants and cannot express in
// TFTP itself.

// schedule is a compiled time window.
type schedule struct {
	days     [7]bool
	anyDay   bool
	from, to int // minutes since midnight; equal means the whole day
	loc      *time.Location
}

func compileSchedule(c *config.ModbusSchedule) (*schedule, error) {
	if c == nil {
		return nil, nil
	}
	s := &schedule{loc: time.UTC, anyDay: len(c.Days) == 0}
	for _, d := range c.Days {
		i, ok := dayIndex(d)
		if !ok {
			return nil, fmt.Errorf("schedule.days: %q is not a day", d)
		}
		s.days[i] = true
	}
	var err error
	if s.from, err = clockMinutes(c.From); err != nil {
		return nil, err
	}
	if s.to, err = clockMinutes(c.To); err != nil {
		return nil, err
	}
	if c.Timezone != "" {
		if s.loc, err = time.LoadLocation(c.Timezone); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func dayIndex(d string) (int, bool) {
	switch strings.ToLower(strings.TrimSpace(d)) {
	case "sun":
		return 0, true
	case "mon":
		return 1, true
	case "tue":
		return 2, true
	case "wed":
		return 3, true
	case "thu":
		return 4, true
	case "fri":
		return 5, true
	case "sat":
		return 6, true
	}
	return 0, false
}

func clockMinutes(s string) (int, error) {
	if s == "" {
		return 0, nil
	}
	var h, m int
	if _, err := fmt.Sscanf(s, "%d:%d", &h, &m); err != nil {
		return 0, fmt.Errorf("schedule: %q is not HH:MM", s)
	}
	if h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, fmt.Errorf("schedule: %q is not a time of day", s)
	}
	return h*60 + m, nil
}

// inForce says whether a schedule includes a moment. A window whose end is
// before its start spans midnight, which is how a night shift is written.
func (s *schedule) inForce(now time.Time) bool {
	if s == nil {
		return true
	}
	t := now.In(s.loc)
	if !s.anyDay && !s.days[int(t.Weekday())] {
		return false
	}
	mins := t.Hour()*60 + t.Minute()
	if s.from == s.to {
		return true
	}
	if s.to > s.from {
		return mins >= s.from && mins < s.to
	}
	return mins >= s.from || mins < s.to
}
