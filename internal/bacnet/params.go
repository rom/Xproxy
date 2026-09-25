package bacnet

// Target is one object, and where named the one property of it, that a
// service request is about.
type Target struct {
	Object      ObjectID
	Property    PropertyID
	HasProperty bool
}

// where says where in a service's parameters its object identifier is.
// A service names its parameters by context tag number, so the place is
// a number -- except for the handful that use an application-tagged
// identifier, and the two that carry a list of them.
type where struct {
	// object is the context tag number holding the object identifier, or
	// application when the identifier is application-tagged.
	object int
	// property is the context tag number holding the property
	// identifier, or absent when the service names no single property.
	property int
	// list marks the two services whose parameter is a sequence of
	// access specifications, each with its own object.
	list bool
}

const (
	application = -1
	absent      = -2
)

// locate is where each service keeps the object it is about.
//
// The table exists because the alternative is a policy that reads the
// first object identifier it can find in the parameters, and the first
// one is the wrong one often enough to matter: in a COV notification the
// first is the device that sent it and the third is the object that
// changed, and in subscribeCOV the first is a process identifier that is
// not an object at all.
var locate = map[Service]where{
	{Confirmed: true, Choice: ReadProperty}:               {object: 0, property: 1},
	{Confirmed: true, Choice: WriteProperty}:              {object: 0, property: 1},
	{Confirmed: true, Choice: AddListElement}:             {object: 0, property: 1},
	{Confirmed: true, Choice: RemoveListElement}:          {object: 0, property: 1},
	{Confirmed: true, Choice: ReadRange}:                  {object: 0, property: 1},
	{Confirmed: true, Choice: ReadPropertyMultiple}:       {object: 0, property: absent, list: true},
	{Confirmed: true, Choice: WritePropertyMultiple}:      {object: 0, property: absent, list: true},
	{Confirmed: true, Choice: SubscribeCOV}:               {object: 1, property: absent},
	{Confirmed: true, Choice: SubscribeCOVProperty}:       {object: 1, property: absent},
	{Confirmed: true, Choice: AcknowledgeAlarm}:           {object: 1, property: absent},
	{Confirmed: true, Choice: ConfirmedCOVNotification}:   {object: 2, property: absent},
	{Confirmed: true, Choice: ConfirmedEventNotification}: {object: 2, property: absent},
	{Confirmed: true, Choice: LifeSafetyOperation}:        {object: 3, property: absent},
	{Confirmed: true, Choice: AtomicReadFile}:             {object: application, property: absent},
	{Confirmed: true, Choice: AtomicWriteFile}:            {object: application, property: absent},
	{Confirmed: true, Choice: DeleteObject}:               {object: application, property: absent},
	{Choice: UnconfirmedCOVNotification}:                  {object: 2, property: absent},
	{Choice: UnconfirmedEventNotification}:                {object: 2, property: absent},
	{Choice: IAm}:                                         {object: application, property: absent},
	{Choice: IHave}:                                       {object: application, property: absent},
}

// objectless is the services that name no object at all. They are listed
// rather than left to fall through, because "this service is about no
// object" and "this package cannot find the object" are different
// answers and a policy acts differently on them.
var objectless = map[Service]bool{
	{Confirmed: true, Choice: GetAlarmSummary}:            true,
	{Confirmed: true, Choice: DeviceCommunicationControl}: true,
	{Confirmed: true, Choice: ReinitializeDevice}:         true,
	{Confirmed: true, Choice: ConfirmedPrivateTransfer}:   true,
	{Confirmed: true, Choice: ConfirmedTextMessage}:       true,
	{Confirmed: true, Choice: VTOpen}:                     true,
	{Confirmed: true, Choice: VTClose}:                    true,
	{Confirmed: true, Choice: VTData}:                     true,
	{Confirmed: true, Choice: Authenticate}:               true,
	{Confirmed: true, Choice: RequestKey}:                 true,
	{Choice: TimeSynchronization}:                         true,
	{Choice: UTCTimeSynchronization}:                      true,
	{Choice: WhoIs}:                                       true,
	{Choice: WhoAmI}:                                      true,
	{Choice: UnconfirmedPrivateTransfer}:                  true,
	{Choice: UnconfirmedTextMessage}:                      true,
	{Choice: WriteGroup}:                                  true,
}

// Targets reads the objects a request is about.
//
// The second return is whether this package knows where they are. It is
// false for the services whose object is somewhere a fixed position
// cannot describe -- createObject names a type or an identifier inside a
// choice, who-Has names an object or a name, the COV-multiple and audit
// services carry lists of lists -- and for a service choice this package
// does not know at all.
//
// That distinction is the whole point of the pair. A listener with rules
// about objects cannot apply them to a request whose object it has not
// found, and the two ways of getting that wrong are to check the wrong
// field and to let the request through unchecked. Saying "I could not
// find it" lets the caller refuse, which is the only answer that is not
// one of those two.
func Targets(a APDU) ([]Target, bool) {
	if !a.HasService {
		return nil, false
	}
	if objectless[a.Service] {
		return nil, true
	}
	w, ok := locate[a.Service]
	if !ok {
		return nil, false
	}
	r := &reader{b: a.Params}
	if w.list {
		return accessList(r, w)
	}
	if w.object == application {
		return appObjects(r)
	}
	return contextObject(r, w)
}

// appObjects collects every application-tagged object identifier at the
// top level. There is one in atomicReadFile and in i-Am, and two in
// i-Have -- the device and the object it has -- and all of them are
// objects the request is about, so all of them are returned.
func appObjects(r *reader) ([]Target, bool) {
	var out []Target
	for !r.done() {
		t, err := r.next()
		if err != nil {
			return nil, false
		}
		if t.Opening {
			if err := r.skip(); err != nil {
				return nil, false
			}
			continue
		}
		if t.Context || t.Number != tagObjectID {
			continue
		}
		o, err := DecodeObjectID(t.Data)
		if err != nil {
			return nil, false
		}
		out = append(out, Target{Object: o})
	}
	if len(out) == 0 {
		return nil, false
	}
	return out, true
}

// contextObject reads one object identifier from its context tag, and
// the property identifier from its own when the service has one.
func contextObject(r *reader, w where) ([]Target, bool) {
	var t Target
	var haveObject bool
	for !r.done() {
		tg, err := r.next()
		if err != nil {
			return nil, false
		}
		if tg.Opening {
			if err := r.skip(); err != nil {
				return nil, false
			}
			continue
		}
		if !tg.Context {
			continue
		}
		switch int(tg.Number) {
		case w.object:
			o, err := DecodeObjectID(tg.Data)
			if err != nil {
				return nil, false
			}
			t.Object, haveObject = o, true
		case w.property:
			p, ok := tg.property()
			if !ok {
				return nil, false
			}
			t.Property, t.HasProperty = p, true
		}
	}
	if !haveObject {
		// The service names an object at a fixed place and there is
		// nothing there. Something is wrong with the request, and
		// reporting it as a request about no object would let it past a
		// rule that is about objects.
		return nil, false
	}
	return []Target{t}, true
}

// accessList reads readPropertyMultiple and writePropertyMultiple: a
// sequence of specifications, each an object identifier followed by a
// constructed list of the properties wanted from it.
//
// Every object in the sequence is returned, and every property of every
// object. A request that reads one property from each of forty objects is
// one datagram, and a policy that checked only the first would be
// checking one fortieth of it.
func accessList(r *reader, w where) ([]Target, bool) {
	var out []Target
	var cur ObjectID
	var haveObject bool
	for !r.done() {
		tg, err := r.next()
		if err != nil {
			return nil, false
		}
		switch {
		case tg.Context && !tg.Opening && !tg.Closing && int(tg.Number) == w.object:
			o, err := DecodeObjectID(tg.Data)
			if err != nil {
				return nil, false
			}
			cur, haveObject = o, true
		case tg.Opening && tg.Number == 1:
			// The list of property references for the object just read.
			if !haveObject {
				return nil, false
			}
			props, ok := propertyRefs(r)
			if !ok {
				return nil, false
			}
			if len(props) == 0 {
				out = append(out, Target{Object: cur})
				break
			}
			for _, p := range props {
				out = append(out, Target{Object: cur, Property: p, HasProperty: true})
			}
		case tg.Opening:
			if err := r.skip(); err != nil {
				return nil, false
			}
		}
	}
	if len(out) == 0 {
		return nil, false
	}
	return out, true
}

// propertyRefs reads the property references inside one access
// specification, up to and including its closing tag. Each reference is
// a property identifier at context tag 0 and an optional array index at
// context tag 1.
func propertyRefs(r *reader) ([]PropertyID, bool) {
	var out []PropertyID
	for {
		tg, err := r.next()
		if err != nil {
			return nil, false
		}
		switch {
		case tg.Closing:
			return out, true
		case tg.Opening:
			if err := r.skip(); err != nil {
				return nil, false
			}
		case tg.Context && tg.Number == 0:
			p, ok := tg.property()
			if !ok {
				return nil, false
			}
			out = append(out, p)
		}
	}
}

// DeviceRange reads the instance range of a Who-Is, which is the
// broadcast every device on the network answers.
//
// The range is what separates a client asking after the one controller it
// talks to from a client sweeping the estate: the parameters are
// optional, and a Who-Is sent without them asks every device there is to
// answer at once. A relay cannot tell those apart without reading it,
// which is why this is here and not left as "an unconfirmed request".
func DeviceRange(a APDU) (low, high uint32, bounded bool) {
	if !a.HasService || a.Service.Confirmed || a.Service.Choice != WhoIs {
		return 0, 0, false
	}
	r := &reader{b: a.Params}
	var haveLow, haveHigh bool
	for !r.done() {
		tg, err := r.next()
		if err != nil {
			return 0, 0, false
		}
		if tg.Opening {
			if err := r.skip(); err != nil {
				return 0, 0, false
			}
			continue
		}
		if !tg.Context {
			continue
		}
		v, ok := tg.uint()
		if !ok {
			return 0, 0, false
		}
		switch tg.Number {
		case 0:
			low, haveLow = v, true
		case 1:
			high, haveHigh = v, true
		}
	}
	if !haveLow || !haveHigh || low > high || high > maxInstance {
		return 0, 0, false
	}
	return low, high, true
}

// NoPriority is the priority a write without one gets. Clause 19.2 makes
// an unprioritised write to a commandable property the lowest priority
// there is, which is why absence is the safe reading rather than an
// unknown.
const NoPriority uint8 = 16

// CommandPriority reads the priority a write asks for.
//
// This is BACnet's own privilege ladder and it is worth a relay's
// attention. A commandable object holds sixteen slots; the value the plant
// follows is the highest-priority slot that is filled. Slot 1 is manual
// life safety and slot 2 automatic life safety, and a write there cannot
// be overridden by the building management system, by a schedule, or by
// an operator at a workstation -- it stands until whoever wrote it
// relinquishes it. So a client that writes at priority 1 has taken the
// plant away from everything else that commands it, with one datagram and
// no identity.
//
// The second return is whether the service is one that carries a
// priority at all. For writeProperty it is the optional parameter at
// context tag 4; for writePropertyMultiple it is optional inside each
// value in each specification, and the most privileged one found is the
// one returned -- a request that writes two properties, one at 16 and one
// at 1, is a request that writes at 1.
func CommandPriority(a APDU) (uint8, bool) {
	if !a.HasService || !a.Service.Confirmed {
		return 0, false
	}
	switch a.Service.Choice {
	case WriteProperty:
		return topLevelPriority(a.Params)
	case WritePropertyMultiple:
		return listPriority(a.Params)
	}
	return 0, false
}

// topLevelPriority reads writeProperty's optional priority at context
// tag 4.
func topLevelPriority(params []byte) (uint8, bool) {
	r := &reader{b: params}
	best := NoPriority
	for !r.done() {
		tg, err := r.next()
		if err != nil {
			return 0, false
		}
		if tg.Opening {
			if err := r.skip(); err != nil {
				return 0, false
			}
			continue
		}
		if !tg.Context || tg.Number != 4 {
			continue
		}
		p, ok := priorityOf(tg)
		if !ok {
			return 0, false
		}
		best = min(best, p)
	}
	return best, true
}

// listPriority walks writePropertyMultiple's specifications and returns
// the most privileged priority any value in any of them asks for.
func listPriority(params []byte) (uint8, bool) {
	r := &reader{b: params}
	best := NoPriority
	for !r.done() {
		tg, err := r.next()
		if err != nil {
			return 0, false
		}
		if !tg.Opening {
			continue
		}
		if tg.Number != 1 {
			if err := r.skip(); err != nil {
				return 0, false
			}
			continue
		}
		p, ok := valuePriorities(r)
		if !ok {
			return 0, false
		}
		best = min(best, p)
	}
	return best, true
}

// valuePriorities reads one list of property values, up to its closing
// tag, and returns the most privileged priority in it.
//
// The priority is at context tag 3 of a property value, and the value
// itself is a constructed [2] -- so the walk has to step over the value
// rather than through it, or a priority-looking tag inside somebody's
// encoded structure would be read as the request's priority.
func valuePriorities(r *reader) (uint8, bool) {
	best := NoPriority
	for {
		tg, err := r.next()
		if err != nil {
			return 0, false
		}
		switch {
		case tg.Closing:
			return best, true
		case tg.Opening:
			if err := r.skip(); err != nil {
				return 0, false
			}
		case tg.Context && tg.Number == 3:
			p, ok := priorityOf(tg)
			if !ok {
				return 0, false
			}
			best = min(best, p)
		}
	}
}

// priorityOf reads a priority and refuses one outside the sixteen slots
// clause 19.2 defines. A number outside them is not a priority, and
// reading it as one would compare a policy's bound against a value the
// device will reject anyway -- in the direction that lets it through.
func priorityOf(tg tag) (uint8, bool) {
	v, ok := tg.uint()
	if !ok || v < 1 || v > uint32(NoPriority) {
		return 0, false
	}
	return uint8(v), true
}
