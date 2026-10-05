package simulate

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/rom/xproxy/internal/config"
)

// Every path the engine writes, pointed into the simulation's own directory.
//
// The state a decision depends on -- the bans, the access ledger, the
// inventories -- is copied in by Offline, so a run starts from what the estate
// has. What is left over is output: a learning report proposing a policy from
// what crossed the listener, a session recording of a session this program
// invented. Those change no decision, and that is exactly why they are easy to
// forget: leaving them pointing at the estate is the one way asking a read-only
// question ends up writing something. A learning report overwritten with a
// simulation's traffic would be worse than a stray file, because somebody would
// later promote it into a policy.
//
// They are found by type rather than by listing each kind's field. There are
// eight learning sections and five recording ones today, all of them
// config.SessionRecording or a struct whose name ends in Learn, and a kind added
// next year is covered by the walk instead of by somebody remembering this file
// exists.

// recordingType is the one struct every recording section is.
const recordingType = "SessionRecording"

// learnSuffix names the learning sections: ModbusLearn, IEC104Learn, S7Learn,
// TFTPLearn, NTPLearn and their siblings.
const learnSuffix = "Learn"

// maxWalkDepth bounds the recursion. The configuration is a tree and not a
// graph, so this is a guard against a future shape rather than a known cycle.
const maxWalkDepth = 40

// redirectWrites rewrites every output path in cfg to one under dir, creating
// the directories the engine expects to find. It reports what it moved.
func redirectWrites(cfg *config.Config, dir string, rep *Report) error {
	moved := redirect(reflect.ValueOf(cfg), dir, 0)
	if moved == 0 {
		return nil
	}
	for _, sub := range []string{recordingDir(dir), learningDir(dir)} {
		if err := os.MkdirAll(sub, 0o700); err != nil {
			return fmt.Errorf("simulation output directory: %w", err)
		}
	}
	rep.Notes = append(rep.Notes, fmt.Sprintf(
		"%d output path(s) moved into the simulation's directory, not the estate's", moved))
	return nil
}

func recordingDir(dir string) string { return filepath.Join(dir, "recordings") }
func learningDir(dir string) string  { return filepath.Join(dir, "learning") }

// redirect walks a value and rewrites the output paths it finds, returning how
// many it changed.
func redirect(v reflect.Value, dir string, depth int) int {
	if depth > maxWalkDepth || !v.IsValid() {
		return 0
	}
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if v.IsNil() {
			return 0
		}
		return redirect(v.Elem(), dir, depth+1)
	case reflect.Slice, reflect.Array:
		n := 0
		for i := range v.Len() {
			n += redirect(v.Index(i), dir, depth+1)
		}
		return n
	case reflect.Map:
		// A map's values are not addressable, so a changed one is written back.
		n := 0
		for _, k := range v.MapKeys() {
			c := reflect.New(v.Type().Elem()).Elem()
			c.Set(v.MapIndex(k))
			if m := redirect(c, dir, depth+1); m > 0 {
				v.SetMapIndex(k, c)
				n += m
			}
		}
		return n
	case reflect.Struct:
		n := outputPaths(v, dir)
		for i := range v.NumField() {
			if !v.Type().Field(i).IsExported() {
				continue
			}
			n += redirect(v.Field(i), dir, depth+1)
		}
		return n
	default:
		return 0
	}
}

// outputPaths rewrites the output path of one struct, if it is a kind of struct
// that has one.
func outputPaths(v reflect.Value, dir string) int {
	name := v.Type().Name()
	switch {
	case name == recordingType:
		return setPath(v, "Directory", recordingDir(dir))
	case strings.HasSuffix(name, learnSuffix) && name != learnSuffix:
		base := strings.ToLower(strings.TrimSuffix(name, learnSuffix))
		return setPath(v, "File", filepath.Join(learningDir(dir), base+".yaml"))
	}
	return 0
}

// setPath rewrites one string field, and only one that is set: an empty path
// means the section writes nothing, and filling it in would make a simulation
// produce a report the daemon would not have.
func setPath(v reflect.Value, field, to string) int {
	f := v.FieldByName(field)
	if !f.IsValid() || f.Kind() != reflect.String || !f.CanSet() || f.String() == "" || f.String() == to {
		return 0
	}
	f.SetString(to)
	return 1
}
