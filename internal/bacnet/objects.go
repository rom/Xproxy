package bacnet

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

// ObjectType is a BACnet object type: the top ten bits of an object
// identifier. It is held in a uint32 rather than the uint16 that would
// fit, so that reading one out of an identifier is a mask rather than a
// narrowing conversion -- there is no width here for a value to be lost
// in.
type ObjectType uint32

// ObjectID is a BACnet object identifier: an object type and an instance
// number, packed into four octets.
type ObjectID struct {
	Type     ObjectType
	Instance uint32
}

// maxInstance is the largest instance number the twenty-two bits hold.
// 4194303 is also the standard's "unassigned" instance, which a device
// uses before it has been given a number.
const maxInstance = 0x3FFFFF

// DecodeObjectID reads the four-octet encoding.
func DecodeObjectID(b []byte) (ObjectID, error) {
	if len(b) != 4 {
		return ObjectID{}, fmt.Errorf("%w: an object identifier of %d octets, and the encoding is 4", ErrMalformed, len(b))
	}
	v := binary.BigEndian.Uint32(b)
	// The type is the top ten bits and the instance the low twenty-two,
	// so both are masked to their own width: the type's mask is what
	// makes the narrowing exact rather than merely true.
	return ObjectID{Type: ObjectType(v >> 22 & 0x3FF), Instance: v & maxInstance}, nil
}

// Encode writes the four-octet form, which the tests use to build
// requests and which nothing in the relay path needs.
func (o ObjectID) Encode() []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], (uint32(o.Type)&0x3FF)<<22|(o.Instance&maxInstance))
	return b[:]
}

// String renders the identifier the way the standard's own examples do,
// as a type and an instance.
func (o ObjectID) String() string {
	return o.Type.String() + ":" + strconv.FormatUint(uint64(o.Instance), 10)
}

// Unassigned reports whether the instance is the standard's "not yet
// numbered" value, which only a device that has never been commissioned
// should carry.
func (o ObjectID) Unassigned() bool { return o.Instance == maxInstance }

// The object types worth naming: everything the standard defines up to
// the proprietary range.
const (
	AnalogInput      ObjectType = 0
	AnalogOutput     ObjectType = 1
	AnalogValue      ObjectType = 2
	BinaryInput      ObjectType = 3
	BinaryOutput     ObjectType = 4
	BinaryValue      ObjectType = 5
	Calendar         ObjectType = 6
	Command          ObjectType = 7
	DeviceObject     ObjectType = 8
	EventEnrollment  ObjectType = 9
	FileObject       ObjectType = 10
	GroupObject      ObjectType = 11
	Loop             ObjectType = 12
	MultiStateInput  ObjectType = 13
	MultiStateOutput ObjectType = 14
	NotificationCls  ObjectType = 15
	ProgramObject    ObjectType = 16
	ScheduleObject   ObjectType = 17
	Averaging        ObjectType = 18
	MultiStateValue  ObjectType = 19
	TrendLog         ObjectType = 20
	LifeSafetyPoint  ObjectType = 21
	LifeSafetyZone   ObjectType = 22
	NetworkPort      ObjectType = 56
)

var objectTypeNames = map[ObjectType]string{
	AnalogInput: "analog-input", AnalogOutput: "analog-output", AnalogValue: "analog-value",
	BinaryInput: "binary-input", BinaryOutput: "binary-output", BinaryValue: "binary-value",
	Calendar: "calendar", Command: "command", DeviceObject: "device",
	EventEnrollment: "event-enrollment", FileObject: "file", GroupObject: "group", Loop: "loop",
	MultiStateInput: "multi-state-input", MultiStateOutput: "multi-state-output",
	NotificationCls: "notification-class", ProgramObject: "program", ScheduleObject: "schedule",
	Averaging: "averaging", MultiStateValue: "multi-state-value", TrendLog: "trend-log",
	LifeSafetyPoint: "life-safety-point", LifeSafetyZone: "life-safety-zone",
	23: "accumulator", 24: "pulse-converter", 25: "event-log", 26: "global-group",
	27: "trend-log-multiple", 28: "load-control", 29: "structured-view", 30: "access-door",
	32: "access-credential", 33: "access-point", 34: "access-rights", 35: "access-user",
	36: "access-zone", 37: "credential-data-input", 39: "bitstring-value",
	40: "characterstring-value", 41: "date-pattern-value", 42: "date-value",
	43: "datetime-pattern-value", 44: "datetime-value", 45: "integer-value",
	46: "large-analog-value", 47: "octetstring-value", 48: "positive-integer-value",
	49: "time-pattern-value", 50: "time-value", 51: "notification-forwarder",
	52: "alert-enrollment", 53: "channel", 54: "lighting-output", 55: "binary-lighting-output",
	NetworkPort: "network-port", 57: "elevator-group", 58: "escalator", 59: "lift",
	60: "staging", 61: "audit-log", 62: "audit-reporter",
}

// proprietaryObject is where clause 21 hands the numbering over to
// vendors. A type in this range has no standard meaning, so it is named
// as proprietary rather than given a name it does not have.
const proprietaryObject ObjectType = 128

// String names the object type.
func (t ObjectType) String() string {
	if n, ok := objectTypeNames[t]; ok {
		return n
	}
	if t >= proprietaryObject {
		return fmt.Sprintf("proprietary-object-%d", uint32(t))
	}
	return fmt.Sprintf("object-type-%d", uint32(t))
}

// Known reports whether the standard defines this object type.
func (t ObjectType) Known() bool { _, ok := objectTypeNames[t]; return ok }

// Proprietary reports whether the type is in the vendor range.
func (t ObjectType) Proprietary() bool { return t >= proprietaryObject }

// Commandable reports whether writing the object's present value drives
// something physical: a valve, a damper, a relay, a lamp, a lift.
//
// It is what separates "somebody wrote to a value object a graphics page
// reads" from "somebody moved a piece of plant". The two are the same
// service with the same shape, so a relay that wants to treat them
// differently has only the object type to do it with.
func (t ObjectType) Commandable() bool {
	switch t {
	case AnalogOutput, BinaryOutput, MultiStateOutput,
		54, 55, // lighting-output, binary-lighting-output
		28, 53, 30, // load-control, channel, access-door
		57, 58, 59: // elevator-group, escalator, lift
		return true
	}
	return false
}

// ParseObjectType reads an object type by the standard's name, or by
// number for the proprietary range a vendor's estate will have. It is
// what a configuration file's object rules are written in.
func ParseObjectType(s string) (ObjectType, bool) {
	l := lower(strings.TrimSpace(s))
	for t, n := range objectTypeNames {
		if n == l {
			return t, true
		}
	}
	// A number is accepted, because a vendor's proprietary type has no
	// name to write and an estate that uses one still has to allow it.
	if n, err := strconv.ParseUint(l, 10, 10); err == nil {
		return ObjectType(n), true
	}
	return 0, false
}

// AllObjectTypes names every object type the standard defines, for the
// documentation and for a validator's error message.
func AllObjectTypes() []string {
	out := make([]string, 0, len(objectTypeNames))
	for _, n := range objectTypeNames {
		out = append(out, n)
	}
	sortStrings(out)
	return out
}

// PropertyID is a property identifier.
type PropertyID uint32

// The properties a policy or a log line has reason to name. There are
// several hundred; these are the ones that decide something.
const (
	PropObjectIdentifier  PropertyID = 75
	PropObjectName        PropertyID = 77
	PropObjectType        PropertyID = 79
	PropPresentValue      PropertyID = 85
	PropOutOfService      PropertyID = 81
	PropPriorityArray     PropertyID = 87
	PropRelinquishDefault PropertyID = 104
	PropStatusFlags       PropertyID = 111
	PropReliability       PropertyID = 103
	PropDescription       PropertyID = 28
	PropUnits             PropertyID = 117
	PropSystemStatus      PropertyID = 112
	PropProtocolVersion   PropertyID = 98
	PropProtocolRevision  PropertyID = 139
	PropVendorIdentifier  PropertyID = 120
	PropVendorName        PropertyID = 121
	PropModelName         PropertyID = 70
	PropFirmwareRevision  PropertyID = 44
	PropAppSoftwareVer    PropertyID = 12
	PropDatabaseRevision  PropertyID = 155
	PropLocalDate         PropertyID = 56
	PropLocalTime         PropertyID = 57
	PropUTCOffset         PropertyID = 119
	PropTimeSyncRecip     PropertyID = 116
	PropRestartRecip      PropertyID = 202
	PropMaxMaster         PropertyID = 64
	PropMaxInfoFrames     PropertyID = 63
	PropAPDUTimeout       PropertyID = 10
	PropAPDURetries       PropertyID = 73
	PropAddressBinding    PropertyID = 30
	PropProgramChange     PropertyID = 90
	PropProgramState      PropertyID = 92
	PropReasonForHalt     PropertyID = 100
	PropObjectList        PropertyID = 76
	PropAll               PropertyID = 8
	PropRequired          PropertyID = 105
	PropOptional          PropertyID = 80
)

var propertyNames = map[PropertyID]string{
	PropObjectIdentifier: "object-identifier", PropObjectName: "object-name",
	PropObjectType: "object-type", PropPresentValue: "present-value",
	PropOutOfService: "out-of-service", PropPriorityArray: "priority-array",
	PropRelinquishDefault: "relinquish-default", PropStatusFlags: "status-flags",
	PropReliability: "reliability", PropDescription: "description", PropUnits: "units",
	PropSystemStatus: "system-status", PropProtocolVersion: "protocol-version",
	PropProtocolRevision: "protocol-revision", PropVendorIdentifier: "vendor-identifier",
	PropVendorName: "vendor-name", PropModelName: "model-name",
	PropFirmwareRevision: "firmware-revision", PropAppSoftwareVer: "application-software-version",
	PropDatabaseRevision: "database-revision", PropLocalDate: "local-date",
	PropLocalTime: "local-time", PropUTCOffset: "utc-offset",
	PropTimeSyncRecip: "time-synchronization-recipients",
	PropRestartRecip:  "restart-notification-recipients",
	PropMaxMaster:     "max-master", PropMaxInfoFrames: "max-info-frames",
	PropAPDUTimeout: "apdu-timeout", PropAPDURetries: "number-of-apdu-retries",
	PropAddressBinding: "device-address-binding", PropProgramChange: "program-change",
	PropProgramState: "program-state", PropReasonForHalt: "reason-for-halt",
	PropObjectList: "object-list", PropAll: "all", PropRequired: "required",
	PropOptional: "optional",
}

// proprietaryProperty is where clause 21 hands property numbering to
// vendors.
const proprietaryProperty PropertyID = 512

// maxProperty is the largest property identifier clause 21 allows: the
// proprietary range runs to 4194303 and stops. A number past it is not a
// property any device can name, so a request that carries one is refused
// rather than reported as being about a property that cannot exist.
const maxProperty PropertyID = 0x3FFFFF

// String names the property, or renders its number when this package has
// no name for it. Most of the several hundred are not named here, and a
// number is the honest rendering of one that is not.
func (p PropertyID) String() string {
	if n, ok := propertyNames[p]; ok {
		return n
	}
	if p >= proprietaryProperty {
		return fmt.Sprintf("proprietary-property-%d", uint32(p))
	}
	return fmt.Sprintf("property-%d", uint32(p))
}

// Named reports whether this package has a name for the property.
func (p PropertyID) Named() bool { _, ok := propertyNames[p]; return ok }

// Proprietary reports whether the property is in the vendor range.
func (p PropertyID) Proprietary() bool { return p >= proprietaryProperty }

// Wholesale reports whether the property identifier is one of the three
// that stand for a set rather than a property: all, required and
// optional. A read of "all" on a device object is how an estate gets
// inventoried, by its own tools and by anybody else.
func (p PropertyID) Wholesale() bool {
	return p == PropAll || p == PropRequired || p == PropOptional
}

// sensitive is the properties whose value is the device's own behaviour
// rather than a measurement or a setpoint.
//
// out-of-service is the one to understand. Writing it true cuts a point
// loose from the physical world: the present value becomes whatever was
// last written, and every graphics page, trend and alarm in the estate
// then reports that number as the truth. It is how a sensor is made to
// lie without touching the sensor.
var sensitive = map[PropertyID]bool{
	PropObjectIdentifier: true, PropObjectName: true, PropOutOfService: true,
	PropProgramChange: true, PropRelinquishDefault: true, PropMaxMaster: true,
	PropMaxInfoFrames: true, PropAPDUTimeout: true, PropAPDURetries: true,
	PropTimeSyncRecip: true, PropRestartRecip: true, PropAddressBinding: true,
	PropDatabaseRevision: true, PropUTCOffset: true, PropLocalDate: true, PropLocalTime: true,
	PropReliability: true,
}

// Sensitive reports whether writing the property changes how the device
// behaves rather than what it holds.
func (p PropertyID) Sensitive() bool { return sensitive[p] }

// SensitiveProperties names every property Sensitive reports, for the
// documentation.
func SensitiveProperties() []string {
	out := make([]string, 0, len(sensitive))
	for p := range sensitive {
		out = append(out, p.String())
	}
	sortStrings(out)
	return out
}

// ParseProperty reads a property by name, or by number for the many this
// package does not name and the proprietary range.
func ParseProperty(s string) (PropertyID, bool) {
	l := lower(strings.TrimSpace(s))
	for p, n := range propertyNames {
		if n == l {
			return p, true
		}
	}
	if n, err := strconv.ParseUint(l, 10, 22); err == nil {
		return PropertyID(n), true
	}
	return 0, false
}
