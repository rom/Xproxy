// Package cluster shares rate limit consumption, bans and security events
// (honeypot marks, revoked sessions) between xproxy nodes (docs/AMR.md,
// AMR-009 and AMR-021).
//
// Topology: every node listens on a mutual TLS port and dials every
// configured peer. A node sends on the connections it dialled and receives
// on the connections it accepted, so each direction is one connection and
// there is no election, no membership protocol and no state that must
// agree. Losing a peer degrades to local limiting for that peer's share of
// the traffic, never to no limiting.
//
// Wire format: TLS 1.3, newline-delimited JSON, one message per line, at
// most MaxMessageBytes per line. Peers are authenticated by the cluster CA
// (and optionally by certificate name); there is no other credential.
package cluster

import (
	"time"

	"github.com/rom/xproxy/internal/ban"
)

// Protocol constants.
const (
	ProtocolVersion = 2
	// minProtocolVersion is the oldest hello accepted. Version 1 nodes
	// send no events and ignore none: they close a connection that
	// carries an events message, so mixed clusters set share_events:
	// false until every node speaks version 2.
	minProtocolVersion = 1
	// MaxMessageBytes bounds one line on the wire.
	MaxMessageBytes = 1 << 20
	// MaxBansPerMessage bounds ban snapshots and batches.
	MaxBansPerMessage = 10000
	// MaxInbound bounds accepted connections.
	MaxInbound = 256
	// banQueueSize bounds queued local ban changes awaiting broadcast.
	banQueueSize = 8192
	// MaxEventsPerMessage bounds one events batch.
	MaxEventsPerMessage = 10000
	// eventQueueSize bounds queued local events awaiting broadcast.
	eventQueueSize = 8192
	// Bounds on one event's fields.
	maxEventKind = 128
	maxEventKey  = 512
	maxEventTTL  = 366 * 24 * time.Hour
)

// Message types.
const (
	typeHello = "hello"
	typeRates = "rates"
	typeBans  = "bans"
	typePing  = "ping"
	// typeEvents carries security events (protocol version 2).
	typeEvents = "events"
)

// Event is one shared fact: a client marked by a honeypot, a provider
// session revoked by a logout. Kind names the fact and selects who
// consumes it; Key identifies the subject; Until is when the fact stops
// mattering; Route is optional context. Every field is bounded on the
// wire and events are applied with the receiver's own limits.
type Event struct {
	Kind  string    `json:"kind"`
	Key   string    `json:"key"`
	Route string    `json:"route,omitempty"`
	Until time.Time `json:"until"`
}

// message is the wire envelope.
type message struct {
	T    string `json:"t"`
	Node string `json:"node,omitempty"`
	Ver  int    `json:"ver,omitempty"`
	Seq  uint64 `json:"seq,omitempty"`
	// Rates: policy name -> key -> tokens consumed during IntervalMS.
	IntervalMS int64                         `json:"interval_ms,omitempty"`
	Rates      map[string]map[string]float64 `json:"rates,omitempty"`
	// Bans added and targets removed.
	Bans    []ban.Entry `json:"bans,omitempty"`
	Removed []string    `json:"removed,omitempty"`
	// Events shared between nodes.
	Events []Event `json:"events,omitempty"`
}

// PeerStatus describes one configured peer for the management API.
type PeerStatus struct {
	Address     string    `json:"address"`
	NodeID      string    `json:"node_id,omitempty"`
	Connected   bool      `json:"connected"`
	ConnectedAt time.Time `json:"connected_at,omitempty"`
	LastError   string    `json:"last_error,omitempty"`
	MessagesOut uint64    `json:"messages_out"`
	Reconnects  uint64    `json:"reconnects"`
}

// InboundStatus describes one accepted peer connection.
type InboundStatus struct {
	Remote     string    `json:"remote"`
	NodeID     string    `json:"node_id,omitempty"`
	CertName   string    `json:"cert_name"`
	Since      time.Time `json:"since"`
	LastSeen   time.Time `json:"last_seen"`
	MessagesIn uint64    `json:"messages_in"`
}

// Status is the management view of the cluster layer.
type Status struct {
	NodeID        string          `json:"node_id"`
	Listen        string          `json:"listen"`
	Peers         []PeerStatus    `json:"peers"`
	Inbound       []InboundStatus `json:"inbound"`
	RatesSent     uint64          `json:"rates_sent"`
	RatesReceived uint64          `json:"rates_received"`
	KeysReceived  uint64          `json:"keys_received"`
	BansSent      uint64          `json:"bans_sent"`
	BansReceived  uint64          `json:"bans_received"`
	EventsSent    uint64          `json:"events_sent"`
	EventsRecv    uint64          `json:"events_received"`
	Ignored       uint64          `json:"ignored_messages"`
	Rejected      uint64          `json:"rejected_connections"`
	Dropped       uint64          `json:"dropped_updates"`
}
