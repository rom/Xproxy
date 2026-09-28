package opcua

import (
	"fmt"
	"strings"
	"time"
)

// A Service is one request or response in namespace zero, identified by the binary
// encoding's TypeId.
//
// The numbers are the *encoding* identifiers rather than the data types': the
// standard gives each structure a node, and its DefaultBinary encoding is that node
// plus two. A reader that used the data type's own number would match nothing on the
// wire, which is a mistake worth naming because both numbers appear in the NodeSet
// and only one appears in a message.
type Service uint32

// The services a relay in front of a plant has opinions about. This is not every
// service the standard defines — there are around forty — it is the ones a policy is
// written in terms of, plus the ones whose absence from a log would be a gap.
const (
	// The discovery services, which a client calls before it has a session.
	SvcFindServers        Service = 422
	SvcFindServersReply   Service = 425
	SvcGetEndpoints       Service = 428
	SvcGetEndpointsReply  Service = 431
	SvcRegisterServer     Service = 437
	SvcRegisterServerAck  Service = 440
	SvcOpenChannel        Service = 446
	SvcOpenChannelReply   Service = 449
	SvcCloseChannel       Service = 452
	SvcCloseChannelReply  Service = 455
	SvcCreateSession      Service = 461
	SvcCreateSessionReply Service = 464
	SvcActivateSession    Service = 467
	SvcActivateReply      Service = 470
	SvcCloseSession       Service = 473
	SvcCloseSessionReply  Service = 476
	SvcCancel             Service = 479
	SvcCancelReply        Service = 482

	// The node management services, which change the address space itself.
	SvcAddNodes            Service = 488
	SvcAddNodesReply       Service = 491
	SvcAddReferences       Service = 494
	SvcAddReferencesReply  Service = 497
	SvcDeleteNodes         Service = 500
	SvcDeleteNodesReply    Service = 503
	SvcDeleteRefs          Service = 506
	SvcDeleteRefsReply     Service = 509
	SvcBrowse              Service = 527
	SvcBrowseReply         Service = 530
	SvcBrowseNext          Service = 533
	SvcBrowseNextReply     Service = 536
	SvcTranslatePaths      Service = 554
	SvcTranslatePathsReply Service = 557
	SvcRegisterNodes       Service = 560
	SvcRegisterNodesReply  Service = 563
	SvcUnregisterNodes     Service = 566
	SvcUnregisterReply     Service = 569

	// The attribute services: the reads and the writes.
	SvcQueryFirst         Service = 615
	SvcQueryFirstReply    Service = 618
	SvcQueryNext          Service = 621
	SvcQueryNextReply     Service = 624
	SvcRead               Service = 631
	SvcReadReply          Service = 634
	SvcHistoryRead        Service = 664
	SvcHistoryReadReply   Service = 667
	SvcWrite              Service = 673
	SvcWriteReply         Service = 676
	SvcHistoryUpdate      Service = 700
	SvcHistoryUpdateReply Service = 703

	// The method service, which is how a client makes a plant do something.
	SvcCall      Service = 712
	SvcCallReply Service = 715

	// The subscription and monitored-item services.
	SvcCreateMonitored       Service = 751
	SvcCreateMonitoredReply  Service = 754
	SvcModifyMonitored       Service = 763
	SvcModifyMonitoredReply  Service = 766
	SvcSetMonitoringMode     Service = 769
	SvcSetMonitoringReply    Service = 772
	SvcSetTriggering         Service = 775
	SvcSetTriggeringReply    Service = 778
	SvcDeleteMonitored       Service = 781
	SvcDeleteMonitoredReply  Service = 784
	SvcCreateSubscription    Service = 787
	SvcCreateSubReply        Service = 790
	SvcModifySubscription    Service = 793
	SvcModifySubReply        Service = 796
	SvcSetPublishingMode     Service = 799
	SvcSetPublishingReply    Service = 802
	SvcPublish               Service = 826
	SvcPublishReply          Service = 829
	SvcRepublish             Service = 832
	SvcRepublishReply        Service = 835
	SvcTransferSubscriptions Service = 839
	SvcTransferSubsReply     Service = 842
	SvcDeleteSubscriptions   Service = 845
	SvcDeleteSubsReply       Service = 848

	// A ServiceFault is what a server answers with when it refuses a request
	// outright: a response header and nothing else. Its TypeId is the one that
	// appears in place of every response's, so a reader that did not know it
	// would report an unknown service for every refusal.
	SvcFault Service = 397
)

// serviceInfo is what this package knows about a service: its name, whether it is a
// request, and what it does.
type serviceInfo struct {
	name    string
	request bool
	// writes says the service changes something: a value, a node, a method's
	// effect, or the subscription state a server holds. It is the coarse question
	// a read-only listener asks, and it is the one that has to be right by
	// default, because a service this package did not classify must not come out
	// as harmless.
	writes bool
	// control says the service can make the plant act rather than merely change
	// a stored value: a method call, a historical rewrite, a node added or
	// removed. It is a narrower class than writes and the one a four-eyes rule is
	// written about.
	control bool
}

var services = map[Service]serviceInfo{
	SvcFindServers:        {"find_servers", true, false, false},
	SvcFindServersReply:   {"find_servers_response", false, false, false},
	SvcGetEndpoints:       {"get_endpoints", true, false, false},
	SvcGetEndpointsReply:  {"get_endpoints_response", false, false, false},
	SvcRegisterServer:     {"register_server", true, true, false},
	SvcRegisterServerAck:  {"register_server_response", false, false, false},
	SvcOpenChannel:        {"open_secure_channel", true, false, false},
	SvcOpenChannelReply:   {"open_secure_channel_response", false, false, false},
	SvcCloseChannel:       {"close_secure_channel", true, false, false},
	SvcCloseChannelReply:  {"close_secure_channel_response", false, false, false},
	SvcCreateSession:      {"create_session", true, false, false},
	SvcCreateSessionReply: {"create_session_response", false, false, false},
	SvcActivateSession:    {"activate_session", true, false, false},
	SvcActivateReply:      {"activate_session_response", false, false, false},
	SvcCloseSession:       {"close_session", true, false, false},
	SvcCloseSessionReply:  {"close_session_response", false, false, false},
	SvcCancel:             {"cancel", true, false, false},
	SvcCancelReply:        {"cancel_response", false, false, false},

	SvcAddNodes:            {"add_nodes", true, true, true},
	SvcAddNodesReply:       {"add_nodes_response", false, false, false},
	SvcAddReferences:       {"add_references", true, true, true},
	SvcAddReferencesReply:  {"add_references_response", false, false, false},
	SvcDeleteNodes:         {"delete_nodes", true, true, true},
	SvcDeleteNodesReply:    {"delete_nodes_response", false, false, false},
	SvcDeleteRefs:          {"delete_references", true, true, true},
	SvcDeleteRefsReply:     {"delete_references_response", false, false, false},
	SvcBrowse:              {"browse", true, false, false},
	SvcBrowseReply:         {"browse_response", false, false, false},
	SvcBrowseNext:          {"browse_next", true, false, false},
	SvcBrowseNextReply:     {"browse_next_response", false, false, false},
	SvcTranslatePaths:      {"translate_browse_paths", true, false, false},
	SvcTranslatePathsReply: {"translate_browse_paths_response", false, false, false},
	SvcRegisterNodes:       {"register_nodes", true, false, false},
	SvcRegisterNodesReply:  {"register_nodes_response", false, false, false},
	SvcUnregisterNodes:     {"unregister_nodes", true, false, false},
	SvcUnregisterReply:     {"unregister_nodes_response", false, false, false},

	SvcQueryFirst:         {"query_first", true, false, false},
	SvcQueryFirstReply:    {"query_first_response", false, false, false},
	SvcQueryNext:          {"query_next", true, false, false},
	SvcQueryNextReply:     {"query_next_response", false, false, false},
	SvcRead:               {"read", true, false, false},
	SvcReadReply:          {"read_response", false, false, false},
	SvcHistoryRead:        {"history_read", true, false, false},
	SvcHistoryReadReply:   {"history_read_response", false, false, false},
	SvcWrite:              {"write", true, true, false},
	SvcWriteReply:         {"write_response", false, false, false},
	SvcHistoryUpdate:      {"history_update", true, true, true},
	SvcHistoryUpdateReply: {"history_update_response", false, false, false},

	SvcCall:      {"call", true, true, true},
	SvcCallReply: {"call_response", false, false, false},

	SvcCreateMonitored:       {"create_monitored_items", true, true, false},
	SvcCreateMonitoredReply:  {"create_monitored_items_response", false, false, false},
	SvcModifyMonitored:       {"modify_monitored_items", true, true, false},
	SvcModifyMonitoredReply:  {"modify_monitored_items_response", false, false, false},
	SvcSetMonitoringMode:     {"set_monitoring_mode", true, true, false},
	SvcSetMonitoringReply:    {"set_monitoring_mode_response", false, false, false},
	SvcSetTriggering:         {"set_triggering", true, true, false},
	SvcSetTriggeringReply:    {"set_triggering_response", false, false, false},
	SvcDeleteMonitored:       {"delete_monitored_items", true, true, false},
	SvcDeleteMonitoredReply:  {"delete_monitored_items_response", false, false, false},
	SvcCreateSubscription:    {"create_subscription", true, true, false},
	SvcCreateSubReply:        {"create_subscription_response", false, false, false},
	SvcModifySubscription:    {"modify_subscription", true, true, false},
	SvcModifySubReply:        {"modify_subscription_response", false, false, false},
	SvcSetPublishingMode:     {"set_publishing_mode", true, true, false},
	SvcSetPublishingReply:    {"set_publishing_mode_response", false, false, false},
	SvcPublish:               {"publish", true, false, false},
	SvcPublishReply:          {"publish_response", false, false, false},
	SvcRepublish:             {"republish", true, false, false},
	SvcRepublishReply:        {"republish_response", false, false, false},
	SvcTransferSubscriptions: {"transfer_subscriptions", true, true, true},
	SvcTransferSubsReply:     {"transfer_subscriptions_response", false, false, false},
	SvcDeleteSubscriptions:   {"delete_subscriptions", true, true, false},
	SvcDeleteSubsReply:       {"delete_subscriptions_response", false, false, false},

	SvcFault: {"service_fault", false, false, false},
}

// byName is the reverse table, built once, for a configuration file.
var byName = func() map[string]Service {
	m := make(map[string]Service, len(services))
	for s, i := range services {
		m[i.name] = s
	}
	return m
}()

func (s Service) String() string {
	if i, ok := services[s]; ok {
		return i.name
	}
	return fmt.Sprintf("service(%d)", uint32(s))
}

// Known says the service is one in this package's table.
func (s Service) Known() bool { _, ok := services[s]; return ok }

// Request says the service is a client's call rather than a server's answer.
func (s Service) Request() bool { return services[s].request }

// Writes says the service changes something. An unknown service reports true,
// because a service this package has not classified is one whose effect it does not
// know — and the safe answer to "may a read-only listener carry this?" is no.
func (s Service) Writes() bool {
	i, ok := services[s]
	if !ok {
		return true
	}
	return i.writes
}

// Control says the service can make the plant act: a method call, a node added or
// removed, a history rewritten, a subscription taken over. An unknown service again
// reports true.
func (s Service) Control() bool {
	i, ok := services[s]
	if !ok {
		return true
	}
	return i.control
}

// ServiceOf reads a service back from its name, which is what a configuration file
// writes. A decimal number is also accepted, for a vendor service or one this
// table does not carry.
func ServiceOf(name string) (Service, bool) {
	if s, ok := byName[strings.ToLower(name)]; ok {
		return s, true
	}
	return 0, false
}

// A ServiceCall is the readable head of a secured message: which service it is and
// the request header that precedes every one of them.
//
// Reading stops after the header by default. The header is common to every service
// and it is where the session token and the timeout are, so a listener that only
// enforces service-level rules needs nothing more — and each service's own body is
// parsed on demand by the function for it, so a message naming a service this
// package does not decode is still a message whose service and session are known.
type ServiceCall struct {
	// Service is the TypeId at the head of the body.
	Service Service
	// TypeID is the node id as it arrived, which matters when it is not in
	// namespace zero: a vendor service is a real thing and its identifier is what
	// names it.
	TypeID NodeId
	// Header is the request header, present on every request.
	Header RequestHeader
	// Response is the response header, present on every response.
	Response ResponseHeader
	// Body is what follows the header: the service's own fields.
	Body []byte
}

// A RequestHeader precedes every service request.
type RequestHeader struct {
	// AuthenticationToken is the session's identifier, which the server gave the
	// client in CreateSession. A null token means the request is outside a
	// session — legitimate only for the discovery services.
	AuthenticationToken NodeId
	// Timestamp is when the client says it sent the request.
	Timestamp time.Time
	// RequestHandle is the client's own number for the request, echoed in the
	// response.
	RequestHandle uint32
	// ReturnDiagnostics asks the server for diagnostic information, and is a
	// field worth watching: a client that sets it is asking a server to describe
	// its own internals in the response.
	ReturnDiagnostics uint32
	// AuditEntryId ties the request to an entry in the client's own audit log.
	AuditEntryID string
	// TimeoutHint is how long the client will wait, in milliseconds. Zero means
	// the client sets no limit, which for a Publish is normal and for a Write is
	// a client that will wait forever.
	TimeoutHint uint32
	// AdditionalHeader is an ExtensionObject the standard reserves and nothing
	// uses; its type identifier is kept and its body is not.
	AdditionalHeader NodeId
}

// A ResponseHeader precedes every service response.
type ResponseHeader struct {
	Timestamp     time.Time
	RequestHandle uint32
	// ServiceResult is the status of the request as a whole, as against the
	// per-operation statuses in the body. A Read of ten nodes where the service
	// succeeded and every node failed has a good ServiceResult and ten bad
	// operation results, which is why both are worth reading.
	ServiceResult uint32
	StringTable   []string
}

// MaxStringTable bounds the diagnostic string table a response carries.
const MaxStringTable = 64

// ParseCall reads the head of a readable service message: the TypeId, then the
// request or response header.
//
// body is the message body *after* the security and sequence headers. request says
// which direction the message travelled, because the two headers are different
// structures and nothing in the message says which is present — the direction does.
func ParseCall(body []byte, request bool) (*ServiceCall, error) {
	r := &reader{b: body}
	c := &ServiceCall{}
	c.TypeID = r.nodeID(false)
	if err := r.done(); err != nil {
		return nil, err
	}
	// A service is identified by a numeric node id in namespace zero. A vendor
	// service in its own namespace is a real thing, and it is not one of these:
	// leaving Service at zero is what says so, and Known() then reports false.
	if c.TypeID.Namespace == 0 && c.TypeID.Kind != String && c.TypeID.Kind != Guid && c.TypeID.Kind != Opaque {
		c.Service = Service(c.TypeID.Numeric)
	}
	if request {
		c.Header = r.requestHeader()
	} else {
		c.Response = r.responseHeader()
	}
	if err := r.done(); err != nil {
		return nil, err
	}
	c.Body = body[r.i:]
	return c, nil
}

func (r *reader) requestHeader() RequestHeader {
	h := RequestHeader{}
	h.AuthenticationToken = r.nodeID(false)
	h.Timestamp = FileTime(r.int64())
	h.RequestHandle = r.uint32()
	h.ReturnDiagnostics = r.uint32()
	h.AuditEntryID = r.str()
	h.TimeoutHint = r.uint32()
	h.AdditionalHeader = r.extensionObject(1)
	return h
}

func (r *reader) responseHeader() ResponseHeader {
	h := ResponseHeader{}
	h.Timestamp = FileTime(r.int64())
	h.RequestHandle = r.uint32()
	h.ServiceResult = r.uint32()
	r.diagnosticInfo(1)
	n, ok := r.length("string table", MaxStringTable)
	if ok {
		for i := 0; i < n; i++ {
			h.StringTable = append(h.StringTable, r.str())
		}
	}
	r.extensionObject(1)
	return h
}
