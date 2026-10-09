package mms

import (
	"testing"

	"github.com/rom/xproxy/internal/engineering"
	wire "github.com/rom/xproxy/internal/mms"
)

// The classifier on its own: which MMS requests are engineering, and which of
// them only look like it.
//
// This is the question the rest of the engineering machinery is built on top
// of, and it is the one place in this kind where the answer comes from the
// *object name* rather than from the service. A $CF$ write and a $CO$ write are
// the same service on the same wire with the same shape; one of them changes
// what a protection relay will do in a fault and the other is the control room
// closing a breaker. Getting that line wrong in either direction is a bad day:
// too wide and every operator action needs a work order, too narrow and the
// setting group that disables protection goes through as ordinary traffic.

// objOf is a domain-specific object name with its 61850 segments read, which is
// what the parser hands the policy.
func objOf(domain, item string) wire.Name {
	n := wire.ParseItem(item)
	n.Kind = wire.NameDomain
	n.Domain = domain
	return n
}

// reqOf is a confirmed request naming a service and whatever objects it
// addressed.
func reqOf(svc wire.Service, names ...wire.Name) *wire.Message {
	return &wire.Message{PDU: wire.ConfirmedRequest, Service: svc,
		HasService: true, Names: names}
}

func TestWhichMMSRequestsAreEngineering(t *testing.T) {
	cf := objOf("AA1J1Q01A1LD0", "XCBR1$CF$Pos$ctlModel")
	sg := objOf("AA1J1Q01A1LD0", "PTOC1$SG$StrVal$setMag$f")
	se := objOf("AA1J1Q01A1LD0", "PTOC1$SE$StrVal$setMag$f")
	oper := objOf("AA1J1Q01A1LD0", "XCBR1$CO$Pos$Oper")
	meas := objOf("AA1J1Q01A1LD0", "MMXU1$MX$TotW$mag$f")
	raw := objOf("AA1J1Q01A1LD0", "not-a-61850-name")

	for _, tc := range []struct {
		name  string
		m     *wire.Message
		ops   []Operation
		want  engineering.Class
		point string
	}{
		// The services that are engineering whatever they name.
		{name: "a download replaces what is inside the IED",
			m: reqOf(wire.SvcInitiateDownloadSequence), want: engineering.ClassProgramDownload},
		{name: "a segment of one is the same operation",
			m: reqOf(wire.SvcDownloadSegment), want: engineering.ClassProgramDownload},
		{name: "deleting a domain changes it too",
			m: reqOf(wire.SvcDeleteDomain), want: engineering.ClassProgramDownload},
		// An upload is the same class of act in the other direction: this is how
		// a substation's configuration leaves the site.
		{name: "an upload reads the logic out",
			m: reqOf(wire.SvcInitiateUploadSequence), want: engineering.ClassProgramUpload},
		{name: "a segment of an upload as well",
			m: reqOf(wire.SvcUploadSegment), want: engineering.ClassProgramUpload},
		// A domain service that happens to name an object reports it, so the
		// event says which one.
		{name: "a domain service naming an object names it in the event",
			m:     reqOf(wire.SvcInitiateDownloadSequence, cf),
			ops:   []Operation{{Name: cf, Write: true}},
			want:  engineering.ClassProgramDownload,
			point: "AA1J1Q01A1LD0/XCBR1$CF$Pos$ctlModel"},
		{name: "a file service moves an SCL or a firmware image",
			m: reqOf(wire.SvcObtainFile), want: engineering.ClassFileTransfer},
		{name: "reading a file is the same class",
			m: reqOf(wire.SvcFileOpen), want: engineering.ClassFileTransfer},

		// Then the writes, where the name decides.
		{name: "a $CF$ write changes what the device is",
			m: reqOf(wire.SvcWrite, cf), ops: []Operation{{Name: cf, Write: true}},
			want: engineering.ClassConfiguration, point: "AA1J1Q01A1LD0/XCBR1$CF$Pos$ctlModel"},
		{name: "a $SG$ write changes a protection setting",
			m: reqOf(wire.SvcWrite, sg), ops: []Operation{{Name: sg, Write: true}},
			want: engineering.ClassConfiguration, point: "AA1J1Q01A1LD0/PTOC1$SG$StrVal$setMag$f"},
		{name: "a $SE$ write is the edit copy of one",
			m: reqOf(wire.SvcWrite, se), ops: []Operation{{Name: se, Write: true}},
			want: engineering.ClassConfiguration, point: "AA1J1Q01A1LD0/PTOC1$SE$StrVal$setMag$f"},
		// The first engineering name in the request decides, so a write that
		// mixes an ordinary point with a setting is not ordinary.
		{name: "a measurement beside a setting does not hide it",
			m:    reqOf(wire.SvcWrite, meas, sg),
			ops:  []Operation{{Name: meas, Write: true}, {Name: sg, Write: true}},
			want: engineering.ClassConfiguration, point: "AA1J1Q01A1LD0/PTOC1$SG$StrVal$setMag$f"},

		// And the ones that are not engineering, which is the half that keeps
		// this usable.
		{name: "an operate is the control room's own work", m: reqOf(wire.SvcWrite, oper),
			ops: []Operation{{Name: oper, Write: true}}},
		{name: "so is a setpoint", m: reqOf(wire.SvcWrite, meas),
			ops: []Operation{{Name: meas, Write: true}}},
		{name: "a read changes nothing", m: reqOf(wire.SvcRead, cf),
			ops: []Operation{{Name: cf, Write: false}}},
		{name: "a write naming no object is not a setting change",
			m: reqOf(wire.SvcWrite)},
		// A name the parser could not break into segments has no functional
		// constraint to decide about, and guessing from the text would be
		// deciding on a substring.
		{name: "a name that is not in the 61850 form is not guessed about",
			m: reqOf(wire.SvcWrite, raw), ops: []Operation{{Name: raw, Write: true}}},
		// An entry the caller marked as not a write is skipped even where the
		// service changes things, which is what keeps a read inside a mixed
		// request from being reported as a setting change.
		{name: "a name the request only read is skipped",
			m: reqOf(wire.SvcWrite, sg), ops: []Operation{{Name: sg, Write: false}}},

		// No message, and a PDU carrying no service at all: an initiate or a
		// conclude, which this is asked about on the same path.
		{name: "no message", m: nil},
		{name: "a PDU with no service",
			m: &wire.Message{PDU: wire.InitiateRequest}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			op, ok := engineeringOf(tc.m, tc.ops)
			if tc.want == "" {
				if ok {
					t.Fatalf("reported as engineering: %+v", op)
				}
				return
			}
			if !ok {
				t.Fatal("not reported as engineering")
			}
			if op.Class != tc.want {
				t.Errorf("class %q, want %q", op.Class, tc.want)
			}
			if op.Point != tc.point {
				t.Errorf("point %q, want %q", op.Point, tc.point)
			}
			if op.Detail == "" {
				t.Error("the operation carries no detail, so the event would not say what happened")
			}
		})
	}
}
