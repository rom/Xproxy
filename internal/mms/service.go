package mms

import "fmt"

// The MMS service layer (ISO 9506), and the part of it IEC 61850 uses.
//
// MMS is a general-purpose manufacturing-message protocol with about eighty
// confirmed services, of which a substation uses a dozen. The rest are named here
// anyway, for one reason: a relay has to be able to say that a request was
// `initiateDownloadSequence` rather than "service 26", because an engineering tool
// downloading into a protection relay is the operation an operator most wants a log
// line and a refusal for, and a listener that could only name the services it
// expected would forward the ones it did not.
//
// The services are grouped by what they *do*, not by their number, because that is
// what a policy is written about. Reading status is not writing a setpoint, and
// neither is deleting a domain.

// PDU is the outer MMS choice.
type PDU byte

const (
	ConfirmedRequest  PDU = 0
	ConfirmedResponse PDU = 1
	ConfirmedError    PDU = 2
	Unconfirmed       PDU = 3
	Reject            PDU = 4
	CancelRequest     PDU = 5
	CancelResponse    PDU = 6
	CancelError       PDU = 7
	InitiateRequest   PDU = 8
	InitiateResponse  PDU = 9
	InitiateError     PDU = 10
	ConcludeRequest   PDU = 11
	ConcludeResponse  PDU = 12
	ConcludeError     PDU = 13
)

// String names the PDU.
func (p PDU) String() string {
	switch p {
	case ConfirmedRequest:
		return "confirmed_request"
	case ConfirmedResponse:
		return "confirmed_response"
	case ConfirmedError:
		return "confirmed_error"
	case Unconfirmed:
		return "unconfirmed"
	case Reject:
		return "reject"
	case CancelRequest:
		return "cancel_request"
	case CancelResponse:
		return "cancel_response"
	case CancelError:
		return "cancel_error"
	case InitiateRequest:
		return "initiate_request"
	case InitiateResponse:
		return "initiate_response"
	case InitiateError:
		return "initiate_error"
	case ConcludeRequest:
		return "conclude_request"
	case ConcludeResponse:
		return "conclude_response"
	case ConcludeError:
		return "conclude_error"
	}
	return fmt.Sprintf("pdu(%d)", byte(p))
}

// Service is one confirmed service, by its choice tag.
type Service uint8

// The confirmed services (ISO 9506-2 Annex A). Named in full because a relay that
// could not name one would forward it.
const (
	SvcStatus                        Service = 0
	SvcGetNameList                   Service = 1
	SvcIdentify                      Service = 2
	SvcRename                        Service = 3
	SvcRead                          Service = 4
	SvcWrite                         Service = 5
	SvcGetVariableAccessAttributes   Service = 6
	SvcDefineNamedVariable           Service = 7
	SvcDefineScatteredAccess         Service = 8
	SvcGetScatteredAccessAttributes  Service = 9
	SvcDeleteVariableAccess          Service = 10
	SvcDefineNamedVariableList       Service = 11
	SvcGetNamedVariableListAttrs     Service = 12
	SvcDeleteNamedVariableList       Service = 13
	SvcDefineNamedType               Service = 14
	SvcGetNamedTypeAttributes        Service = 15
	SvcDeleteNamedType               Service = 16
	SvcInput                         Service = 17
	SvcOutput                        Service = 18
	SvcTakeControl                   Service = 19
	SvcRelinquishControl             Service = 20
	SvcDefineSemaphore               Service = 21
	SvcDeleteSemaphore               Service = 22
	SvcReportSemaphoreStatus         Service = 23
	SvcReportPoolSemaphoreStatus     Service = 24
	SvcReportSemaphoreEntryStatus    Service = 25
	SvcInitiateDownloadSequence      Service = 26
	SvcDownloadSegment               Service = 27
	SvcTerminateDownloadSequence     Service = 28
	SvcInitiateUploadSequence        Service = 29
	SvcUploadSegment                 Service = 30
	SvcTerminateUploadSequence       Service = 31
	SvcRequestDomainDownload         Service = 32
	SvcRequestDomainUpload           Service = 33
	SvcLoadDomainContent             Service = 34
	SvcStoreDomainContent            Service = 35
	SvcDeleteDomain                  Service = 36
	SvcGetDomainAttributes           Service = 37
	SvcCreateProgramInvocation       Service = 38
	SvcDeleteProgramInvocation       Service = 39
	SvcStart                         Service = 40
	SvcStop                          Service = 41
	SvcResume                        Service = 42
	SvcReset                         Service = 43
	SvcKill                          Service = 44
	SvcGetProgramInvocationAttrs     Service = 45
	SvcObtainFile                    Service = 46
	SvcDefineEventCondition          Service = 47
	SvcDeleteEventCondition          Service = 48
	SvcGetEventConditionAttributes   Service = 49
	SvcReportEventConditionStatus    Service = 50
	SvcAlterEventConditionMonitoring Service = 51
	SvcTriggerEvent                  Service = 52
	SvcDefineEventAction             Service = 53
	SvcDeleteEventAction             Service = 54
	SvcGetEventActionAttributes      Service = 55
	SvcReportEventActionStatus       Service = 56
	SvcDefineEventEnrollment         Service = 57
	SvcDeleteEventEnrollment         Service = 58
	SvcAlterEventEnrollment          Service = 59
	SvcReportEventEnrollmentStatus   Service = 60
	SvcGetEventEnrollmentAttributes  Service = 61
	SvcAcknowledgeEventNotification  Service = 62
	SvcGetAlarmSummary               Service = 63
	SvcGetAlarmEnrollmentSummary     Service = 64
	SvcReadJournal                   Service = 65
	SvcWriteJournal                  Service = 66
	SvcInitializeJournal             Service = 67
	SvcReportJournalStatus           Service = 68
	SvcCreateJournal                 Service = 69
	SvcDeleteJournal                 Service = 70
	SvcGetCapabilityList             Service = 71
	SvcFileOpen                      Service = 72
	SvcFileRead                      Service = 73
	SvcFileClose                     Service = 74
	SvcFileRename                    Service = 75
	SvcFileDelete                    Service = 76
	SvcFileDirectory                 Service = 77
)

// Class is what a service does, which is what a policy is written about.
type Class uint8

const (
	// ClassUnknown is a service this build does not name.
	ClassUnknown Class = iota
	// ClassBrowse is discovery: GetNameList, Identify, the attribute readers, the
	// directory. It is how a client finds the data model, and it is also how a
	// stranger maps a substation.
	ClassBrowse
	// ClassRead is reading values.
	ClassRead
	// ClassWrite is writing them. What the write *means* is in the object name's
	// functional constraint, not in the service.
	ClassWrite
	// ClassReport is the report and log machinery: enrollments, event conditions,
	// journals. Turning a report control block off does not change the plant; it
	// stops the control centre hearing about it.
	ClassReport
	// ClassDataSet is defining and deleting named variable lists, which is a
	// client changing what a report will carry.
	ClassDataSet
	// ClassControl is the semaphore and program-invocation services: take
	// control, start, stop, resume, reset, kill. On an IED these reach the
	// firmware rather than the data model.
	ClassControl
	// ClassDomain is download, upload and delete of a domain's content: an
	// engineering tool replacing what is in a protection relay. It is the most
	// consequential class here and the one least often needed in service.
	ClassDomain
	// ClassFile is the file services, which is how configuration and disturbance
	// records move.
	ClassFile
	// ClassSession is initiate, conclude, cancel and the status service.
	ClassSession
)

// String names the class.
func (c Class) String() string {
	switch c {
	case ClassBrowse:
		return "browse"
	case ClassRead:
		return "read"
	case ClassWrite:
		return "write"
	case ClassReport:
		return "report"
	case ClassDataSet:
		return "dataset"
	case ClassControl:
		return "control"
	case ClassDomain:
		return "domain"
	case ClassFile:
		return "file"
	case ClassSession:
		return "session"
	}
	return "unknown"
}

type serviceInfo struct {
	name  string
	class Class
	// changes says the service changes something on the device rather than
	// reading it, which is what `read_only` is about. It is not the same as the
	// write class: deleting a domain changes a great deal and is not a Write.
	changes bool
}

var services = map[Service]serviceInfo{
	SvcStatus:                        {"status", ClassSession, false},
	SvcGetNameList:                   {"get_name_list", ClassBrowse, false},
	SvcIdentify:                      {"identify", ClassBrowse, false},
	SvcRename:                        {"rename", ClassWrite, true},
	SvcRead:                          {"read", ClassRead, false},
	SvcWrite:                         {"write", ClassWrite, true},
	SvcGetVariableAccessAttributes:   {"get_variable_access_attributes", ClassBrowse, false},
	SvcDefineNamedVariable:           {"define_named_variable", ClassDataSet, true},
	SvcDefineScatteredAccess:         {"define_scattered_access", ClassDataSet, true},
	SvcGetScatteredAccessAttributes:  {"get_scattered_access_attributes", ClassBrowse, false},
	SvcDeleteVariableAccess:          {"delete_variable_access", ClassDataSet, true},
	SvcDefineNamedVariableList:       {"define_named_variable_list", ClassDataSet, true},
	SvcGetNamedVariableListAttrs:     {"get_named_variable_list_attributes", ClassBrowse, false},
	SvcDeleteNamedVariableList:       {"delete_named_variable_list", ClassDataSet, true},
	SvcDefineNamedType:               {"define_named_type", ClassDataSet, true},
	SvcGetNamedTypeAttributes:        {"get_named_type_attributes", ClassBrowse, false},
	SvcDeleteNamedType:               {"delete_named_type", ClassDataSet, true},
	SvcInput:                         {"input", ClassControl, true},
	SvcOutput:                        {"output", ClassControl, true},
	SvcTakeControl:                   {"take_control", ClassControl, true},
	SvcRelinquishControl:             {"relinquish_control", ClassControl, true},
	SvcDefineSemaphore:               {"define_semaphore", ClassControl, true},
	SvcDeleteSemaphore:               {"delete_semaphore", ClassControl, true},
	SvcReportSemaphoreStatus:         {"report_semaphore_status", ClassBrowse, false},
	SvcReportPoolSemaphoreStatus:     {"report_pool_semaphore_status", ClassBrowse, false},
	SvcReportSemaphoreEntryStatus:    {"report_semaphore_entry_status", ClassBrowse, false},
	SvcInitiateDownloadSequence:      {"initiate_download_sequence", ClassDomain, true},
	SvcDownloadSegment:               {"download_segment", ClassDomain, true},
	SvcTerminateDownloadSequence:     {"terminate_download_sequence", ClassDomain, true},
	SvcInitiateUploadSequence:        {"initiate_upload_sequence", ClassDomain, false},
	SvcUploadSegment:                 {"upload_segment", ClassDomain, false},
	SvcTerminateUploadSequence:       {"terminate_upload_sequence", ClassDomain, false},
	SvcRequestDomainDownload:         {"request_domain_download", ClassDomain, true},
	SvcRequestDomainUpload:           {"request_domain_upload", ClassDomain, false},
	SvcLoadDomainContent:             {"load_domain_content", ClassDomain, true},
	SvcStoreDomainContent:            {"store_domain_content", ClassDomain, true},
	SvcDeleteDomain:                  {"delete_domain", ClassDomain, true},
	SvcGetDomainAttributes:           {"get_domain_attributes", ClassBrowse, false},
	SvcCreateProgramInvocation:       {"create_program_invocation", ClassControl, true},
	SvcDeleteProgramInvocation:       {"delete_program_invocation", ClassControl, true},
	SvcStart:                         {"start", ClassControl, true},
	SvcStop:                          {"stop", ClassControl, true},
	SvcResume:                        {"resume", ClassControl, true},
	SvcReset:                         {"reset", ClassControl, true},
	SvcKill:                          {"kill", ClassControl, true},
	SvcGetProgramInvocationAttrs:     {"get_program_invocation_attributes", ClassBrowse, false},
	SvcObtainFile:                    {"obtain_file", ClassFile, true},
	SvcDefineEventCondition:          {"define_event_condition", ClassReport, true},
	SvcDeleteEventCondition:          {"delete_event_condition", ClassReport, true},
	SvcGetEventConditionAttributes:   {"get_event_condition_attributes", ClassBrowse, false},
	SvcReportEventConditionStatus:    {"report_event_condition_status", ClassBrowse, false},
	SvcAlterEventConditionMonitoring: {"alter_event_condition_monitoring", ClassReport, true},
	SvcTriggerEvent:                  {"trigger_event", ClassReport, true},
	SvcDefineEventAction:             {"define_event_action", ClassReport, true},
	SvcDeleteEventAction:             {"delete_event_action", ClassReport, true},
	SvcGetEventActionAttributes:      {"get_event_action_attributes", ClassBrowse, false},
	SvcReportEventActionStatus:       {"report_event_action_status", ClassBrowse, false},
	SvcDefineEventEnrollment:         {"define_event_enrollment", ClassReport, true},
	SvcDeleteEventEnrollment:         {"delete_event_enrollment", ClassReport, true},
	SvcAlterEventEnrollment:          {"alter_event_enrollment", ClassReport, true},
	SvcReportEventEnrollmentStatus:   {"report_event_enrollment_status", ClassBrowse, false},
	SvcGetEventEnrollmentAttributes:  {"get_event_enrollment_attributes", ClassBrowse, false},
	SvcAcknowledgeEventNotification:  {"acknowledge_event_notification", ClassReport, true},
	SvcGetAlarmSummary:               {"get_alarm_summary", ClassRead, false},
	SvcGetAlarmEnrollmentSummary:     {"get_alarm_enrollment_summary", ClassBrowse, false},
	SvcReadJournal:                   {"read_journal", ClassRead, false},
	SvcWriteJournal:                  {"write_journal", ClassReport, true},
	SvcInitializeJournal:             {"initialize_journal", ClassReport, true},
	SvcReportJournalStatus:           {"report_journal_status", ClassBrowse, false},
	SvcCreateJournal:                 {"create_journal", ClassReport, true},
	SvcDeleteJournal:                 {"delete_journal", ClassReport, true},
	SvcGetCapabilityList:             {"get_capability_list", ClassBrowse, false},
	SvcFileOpen:                      {"file_open", ClassFile, false},
	SvcFileRead:                      {"file_read", ClassFile, false},
	SvcFileClose:                     {"file_close", ClassFile, false},
	SvcFileRename:                    {"file_rename", ClassFile, true},
	SvcFileDelete:                    {"file_delete", ClassFile, true},
	SvcFileDirectory:                 {"file_directory", ClassFile, false},
}

// byName is the reverse, for reading a configuration.
var byName = func() map[string]Service {
	m := make(map[string]Service, len(services))
	for s, i := range services {
		m[i.name] = s
	}
	return m
}()

// String names the service, or says which number it was.
func (s Service) String() string {
	if i, ok := services[s]; ok {
		return i.name
	}
	return fmt.Sprintf("service(%d)", uint8(s))
}

// Known says the service is one this build names.
func (s Service) Known() bool { _, ok := services[s]; return ok }

// Class is what the service does.
func (s Service) Class() Class { return services[s].class }

// Changes says the service changes something on the device.
func (s Service) Changes() bool { return services[s].changes }

// ServiceOf reads a service back from its configuration name.
func ServiceOf(name string) (Service, bool) {
	s, ok := byName[name]
	return s, ok
}

// ServiceNames is every name a configuration may use, for the validator's error
// messages.
func ServiceNames() []string {
	out := make([]string, 0, len(byName))
	for n := range byName {
		out = append(out, n)
	}
	return out
}
