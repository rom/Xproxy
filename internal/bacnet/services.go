package bacnet

import "fmt"

// Service is a service choice together with which of the two request
// shapes it belongs to. Both are needed to name it: confirmed choice 6
// is atomicReadFile and unconfirmed choice 6 is timeSynchronization, so
// a policy that matched on the number alone would allow one by allowing
// the other.
type Service struct {
	Confirmed bool
	Choice    uint8
}

// The confirmed services of clause 13 to 17, by service choice. The
// three withdrawn ones are kept, because a device in a ceiling still
// answers them and a client still asks.
const (
	AcknowledgeAlarm                 uint8 = 0
	ConfirmedCOVNotification         uint8 = 1
	ConfirmedEventNotification       uint8 = 2
	GetAlarmSummary                  uint8 = 3
	GetEnrollmentSummary             uint8 = 4
	SubscribeCOV                     uint8 = 5
	AtomicReadFile                   uint8 = 6
	AtomicWriteFile                  uint8 = 7
	AddListElement                   uint8 = 8
	RemoveListElement                uint8 = 9
	CreateObject                     uint8 = 10
	DeleteObject                     uint8 = 11
	ReadProperty                     uint8 = 12
	ReadPropertyConditional          uint8 = 13
	ReadPropertyMultiple             uint8 = 14
	WriteProperty                    uint8 = 15
	WritePropertyMultiple            uint8 = 16
	DeviceCommunicationControl       uint8 = 17
	ConfirmedPrivateTransfer         uint8 = 18
	ConfirmedTextMessage             uint8 = 19
	ReinitializeDevice               uint8 = 20
	VTOpen                           uint8 = 21
	VTClose                          uint8 = 22
	VTData                           uint8 = 23
	Authenticate                     uint8 = 24
	RequestKey                       uint8 = 25
	ReadRange                        uint8 = 26
	LifeSafetyOperation              uint8 = 27
	SubscribeCOVProperty             uint8 = 28
	GetEventInformation              uint8 = 29
	SubscribeCOVPropertyMultiple     uint8 = 30
	ConfirmedCOVNotificationMultiple uint8 = 31
	ConfirmedAuditNotification       uint8 = 32
	AuditLogQuery                    uint8 = 33
)

// The unconfirmed services of clause 16 and 17, by service choice.
const (
	IAm                                uint8 = 0
	IHave                              uint8 = 1
	UnconfirmedCOVNotification         uint8 = 2
	UnconfirmedEventNotification       uint8 = 3
	UnconfirmedPrivateTransfer         uint8 = 4
	UnconfirmedTextMessage             uint8 = 5
	TimeSynchronization                uint8 = 6
	WhoHas                             uint8 = 7
	WhoIs                              uint8 = 8
	UTCTimeSynchronization             uint8 = 9
	WriteGroup                         uint8 = 10
	UnconfirmedCOVNotificationMultiple uint8 = 11
	UnconfirmedAuditNotification       uint8 = 12
	WhoAmI                             uint8 = 13
	YouAre                             uint8 = 14
)

var confirmedNames = map[uint8]string{
	AcknowledgeAlarm: "acknowledgeAlarm", ConfirmedCOVNotification: "confirmedCOVNotification",
	ConfirmedEventNotification: "confirmedEventNotification", GetAlarmSummary: "getAlarmSummary",
	GetEnrollmentSummary: "getEnrollmentSummary", SubscribeCOV: "subscribeCOV",
	AtomicReadFile: "atomicReadFile", AtomicWriteFile: "atomicWriteFile",
	AddListElement: "addListElement", RemoveListElement: "removeListElement",
	CreateObject: "createObject", DeleteObject: "deleteObject",
	ReadProperty: "readProperty", ReadPropertyConditional: "readPropertyConditional",
	ReadPropertyMultiple: "readPropertyMultiple", WriteProperty: "writeProperty",
	WritePropertyMultiple: "writePropertyMultiple", DeviceCommunicationControl: "deviceCommunicationControl",
	ConfirmedPrivateTransfer: "confirmedPrivateTransfer", ConfirmedTextMessage: "confirmedTextMessage",
	ReinitializeDevice: "reinitializeDevice", VTOpen: "vtOpen", VTClose: "vtClose", VTData: "vtData",
	Authenticate: "authenticate", RequestKey: "requestKey", ReadRange: "readRange",
	LifeSafetyOperation: "lifeSafetyOperation", SubscribeCOVProperty: "subscribeCOVProperty",
	GetEventInformation: "getEventInformation", SubscribeCOVPropertyMultiple: "subscribeCOVPropertyMultiple",
	ConfirmedCOVNotificationMultiple: "confirmedCOVNotificationMultiple",
	ConfirmedAuditNotification:       "confirmedAuditNotification", AuditLogQuery: "auditLogQuery",
}

var unconfirmedNames = map[uint8]string{
	IAm: "i-Am", IHave: "i-Have", UnconfirmedCOVNotification: "unconfirmedCOVNotification",
	UnconfirmedEventNotification: "unconfirmedEventNotification",
	UnconfirmedPrivateTransfer:   "unconfirmedPrivateTransfer", UnconfirmedTextMessage: "unconfirmedTextMessage",
	TimeSynchronization: "timeSynchronization", WhoHas: "who-Has", WhoIs: "who-Is",
	UTCTimeSynchronization: "utcTimeSynchronization", WriteGroup: "writeGroup",
	UnconfirmedCOVNotificationMultiple: "unconfirmedCOVNotificationMultiple",
	UnconfirmedAuditNotification:       "unconfirmedAuditNotification",
	WhoAmI:                             "whoAmI", YouAre: "youAre",
}

// Name is the service's name as the standard spells it, which is also
// how it is written in a configuration file and in a log line. A choice
// the standard does not define is rendered with its number, so an
// unknown service is reported as unknown rather than as nothing.
func (s Service) Name() string {
	if s.Confirmed {
		if n, ok := confirmedNames[s.Choice]; ok {
			return n
		}
		return fmt.Sprintf("confirmed-service-%d", s.Choice)
	}
	if n, ok := unconfirmedNames[s.Choice]; ok {
		return n
	}
	return fmt.Sprintf("unconfirmed-service-%d", s.Choice)
}

// String is Name, so a Service prints as itself.
func (s Service) String() string { return s.Name() }

// Known reports whether the standard defines this choice.
func (s Service) Known() bool {
	if s.Confirmed {
		_, ok := confirmedNames[s.Choice]
		return ok
	}
	_, ok := unconfirmedNames[s.Choice]
	return ok
}

// writing is every service that changes something at the far end: the
// value of a property, the set of objects, a subscription the device now
// has to maintain, a terminal session, the time it thinks it is, or
// whether it is talking at all.
var writing = map[Service]bool{
	{Confirmed: true, Choice: AcknowledgeAlarm}:             true,
	{Confirmed: true, Choice: SubscribeCOV}:                 true,
	{Confirmed: true, Choice: AtomicWriteFile}:              true,
	{Confirmed: true, Choice: AddListElement}:               true,
	{Confirmed: true, Choice: RemoveListElement}:            true,
	{Confirmed: true, Choice: CreateObject}:                 true,
	{Confirmed: true, Choice: DeleteObject}:                 true,
	{Confirmed: true, Choice: WriteProperty}:                true,
	{Confirmed: true, Choice: WritePropertyMultiple}:        true,
	{Confirmed: true, Choice: DeviceCommunicationControl}:   true,
	{Confirmed: true, Choice: ConfirmedPrivateTransfer}:     true,
	{Confirmed: true, Choice: ReinitializeDevice}:           true,
	{Confirmed: true, Choice: VTOpen}:                       true,
	{Confirmed: true, Choice: VTClose}:                      true,
	{Confirmed: true, Choice: VTData}:                       true,
	{Confirmed: true, Choice: LifeSafetyOperation}:          true,
	{Confirmed: true, Choice: SubscribeCOVProperty}:         true,
	{Confirmed: true, Choice: SubscribeCOVPropertyMultiple}: true,
	{Choice: UnconfirmedPrivateTransfer}:                    true,
	{Choice: TimeSynchronization}:                           true,
	{Choice: UTCTimeSynchronization}:                        true,
	{Choice: WriteGroup}:                                    true,
	{Choice: YouAre}:                                        true,
}

// Writes reports whether the service changes something.
//
// A service this package does not know counts as a write. There are
// vendors shipping proprietary choices in the standard's range, and the
// only safe reading of a service whose effect is unknown is that it has
// one -- a relay that let an unrecognised choice through as a read would
// be deciding by the gap in its own table.
func (s Service) Writes() bool {
	if !s.Known() {
		return true
	}
	return writing[s]
}

// dangerous is the services whose subject is the device rather than the
// data in it, and the three the standard withdrew.
//
// The distinction from Writes matters in practice. A building management
// front end writes setpoints all day, so writeProperty is a write an
// estate may well allow across this relay. Nothing in a normal day
// restarts a controller, tells one to stop communicating for an hour,
// opens a virtual terminal on one, creates or deletes its objects, sets
// its clock from a broadcast, or hands it a new device instance number --
// and every one of those is an unauthenticated request in this protocol.
var dangerous = map[Service]bool{
	{Confirmed: true, Choice: ReinitializeDevice}:         true,
	{Confirmed: true, Choice: DeviceCommunicationControl}: true,
	{Confirmed: true, Choice: AtomicWriteFile}:            true,
	{Confirmed: true, Choice: CreateObject}:               true,
	{Confirmed: true, Choice: DeleteObject}:               true,
	{Confirmed: true, Choice: AddListElement}:             true,
	{Confirmed: true, Choice: RemoveListElement}:          true,
	{Confirmed: true, Choice: ConfirmedPrivateTransfer}:   true,
	{Confirmed: true, Choice: VTOpen}:                     true,
	{Confirmed: true, Choice: VTClose}:                    true,
	{Confirmed: true, Choice: VTData}:                     true,
	{Confirmed: true, Choice: LifeSafetyOperation}:        true,
	{Confirmed: true, Choice: Authenticate}:               true,
	{Confirmed: true, Choice: RequestKey}:                 true,
	{Confirmed: true, Choice: ReadPropertyConditional}:    true,
	{Choice: UnconfirmedPrivateTransfer}:                  true,
	{Choice: TimeSynchronization}:                         true,
	{Choice: UTCTimeSynchronization}:                      true,
	{Choice: WriteGroup}:                                  true,
	{Choice: YouAre}:                                      true,
}

// Dangerous reports whether the service is one of those. An unknown
// choice is not dangerous by this measure -- it is unknown, which Writes
// already treats as the worse case.
func (s Service) Dangerous() bool { return dangerous[s] }

// deprecated is the three services the standard withdrew.
// readPropertyConditional was removed because it is a query a device
// answers by walking every object it has, which is a denial of service
// with a service choice; authenticate and requestKey were the withdrawn
// attempt at security in clause 24 and a device that still answers them
// answers a password guess.
var deprecated = map[Service]bool{
	{Confirmed: true, Choice: ReadPropertyConditional}: true,
	{Confirmed: true, Choice: Authenticate}:            true,
	{Confirmed: true, Choice: RequestKey}:              true,
}

// Deprecated reports whether the standard has withdrawn the service. A
// client that sends one is either very old or looking for something very
// old, and either is worth a log line.
func (s Service) Deprecated() bool { return deprecated[s] }

// DangerousServices names every service Dangerous reports, for the
// documentation and for the message a refusal carries.
func DangerousServices() []string { return names(dangerous) }

// DefaultServices is the services a listener allows when its
// configuration names none: reading, discovery and the notifications a
// device sends of its own accord.
//
// Nothing in it changes anything. An estate that wants this relay to
// carry writes says so, one service at a time, which is the difference
// between a relay in front of a building and a wire.
func DefaultServices() []string {
	return names(map[Service]bool{
		{Confirmed: true, Choice: GetAlarmSummary}:                  true,
		{Confirmed: true, Choice: GetEnrollmentSummary}:             true,
		{Confirmed: true, Choice: GetEventInformation}:              true,
		{Confirmed: true, Choice: ReadProperty}:                     true,
		{Confirmed: true, Choice: ReadPropertyMultiple}:             true,
		{Confirmed: true, Choice: ReadRange}:                        true,
		{Confirmed: true, Choice: AtomicReadFile}:                   true,
		{Confirmed: true, Choice: ConfirmedCOVNotification}:         true,
		{Confirmed: true, Choice: ConfirmedEventNotification}:       true,
		{Confirmed: true, Choice: ConfirmedCOVNotificationMultiple}: true,
		{Confirmed: true, Choice: ConfirmedAuditNotification}:       true,
		{Confirmed: true, Choice: AuditLogQuery}:                    true,
		{Choice: IAm}:                                               true,
		{Choice: IHave}:                                             true,
		{Choice: WhoIs}:                                             true,
		{Choice: WhoHas}:                                            true,
		{Choice: WhoAmI}:                                            true,
		{Choice: UnconfirmedCOVNotification}:                        true,
		{Choice: UnconfirmedEventNotification}:                      true,
		{Choice: UnconfirmedCOVNotificationMultiple}:                true,
		{Choice: UnconfirmedAuditNotification}:                      true,
	})
}

// ParseService reads a service name as a configuration file writes it,
// matching the standard's own spelling case-insensitively. It returns
// false for a name no edition of the standard has, rather than a service
// number nothing will ever send.
func ParseService(name string) (Service, bool) {
	l := lower(name)
	for c, n := range confirmedNames {
		if lower(n) == l {
			return Service{Confirmed: true, Choice: c}, true
		}
	}
	for c, n := range unconfirmedNames {
		if lower(n) == l {
			return Service{Choice: c}, true
		}
	}
	return Service{}, false
}

// AllServices names every service the standard defines, which is what a
// configuration validator checks a name against and what the
// documentation lists.
func AllServices() []string {
	m := make(map[Service]bool, len(confirmedNames)+len(unconfirmedNames))
	for c := range confirmedNames {
		m[Service{Confirmed: true, Choice: c}] = true
	}
	for c := range unconfirmedNames {
		m[Service{Choice: c}] = true
	}
	return names(m)
}

// names renders a set of services as sorted names, so a list in a
// document, a refusal and a test all read the same way.
func names(m map[Service]bool) []string {
	out := make([]string, 0, len(m))
	for s := range m {
		out = append(out, s.Name())
	}
	sortStrings(out)
	return out
}
