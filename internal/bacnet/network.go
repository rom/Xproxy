package bacnet

import "fmt"

// NetworkMessageType is a network layer message: the routers of a BACnet
// internetwork talking to each other rather than an application asking a
// device for anything.
type NetworkMessageType uint8

// The network layer messages of clause 6.4, and the security messages of
// clause 24.
const (
	NetWhoIsRouterToNetwork      NetworkMessageType = 0x00
	NetIAmRouterToNetwork        NetworkMessageType = 0x01
	NetICouldBeRouterToNetwork   NetworkMessageType = 0x02
	NetRejectMessageToNetwork    NetworkMessageType = 0x03
	NetRouterBusyToNetwork       NetworkMessageType = 0x04
	NetRouterAvailableToNetwork  NetworkMessageType = 0x05
	NetInitializeRoutingTable    NetworkMessageType = 0x06
	NetInitializeRoutingTableAck NetworkMessageType = 0x07
	NetEstablishConnection       NetworkMessageType = 0x08
	NetDisconnectConnection      NetworkMessageType = 0x09
	NetChallengeRequest          NetworkMessageType = 0x0A
	NetSecurityPayload           NetworkMessageType = 0x0B
	NetSecurityResponse          NetworkMessageType = 0x0C
	NetRequestKeyUpdate          NetworkMessageType = 0x0D
	NetUpdateKeySet              NetworkMessageType = 0x0E
	NetUpdateDistributionKey     NetworkMessageType = 0x0F
	NetRequestMasterKey          NetworkMessageType = 0x10
	NetSetMasterKey              NetworkMessageType = 0x11
	NetWhatIsNetworkNumber       NetworkMessageType = 0x12
	NetNetworkNumberIs           NetworkMessageType = 0x13
)

var networkNames = map[NetworkMessageType]string{
	NetWhoIsRouterToNetwork:      "who-is-router-to-network",
	NetIAmRouterToNetwork:        "i-am-router-to-network",
	NetICouldBeRouterToNetwork:   "i-could-be-router-to-network",
	NetRejectMessageToNetwork:    "reject-message-to-network",
	NetRouterBusyToNetwork:       "router-busy-to-network",
	NetRouterAvailableToNetwork:  "router-available-to-network",
	NetInitializeRoutingTable:    "initialize-routing-table",
	NetInitializeRoutingTableAck: "initialize-routing-table-ack",
	NetEstablishConnection:       "establish-connection-to-network",
	NetDisconnectConnection:      "disconnect-connection-to-network",
	NetChallengeRequest:          "challenge-request",
	NetSecurityPayload:           "security-payload",
	NetSecurityResponse:          "security-response",
	NetRequestKeyUpdate:          "request-key-update",
	NetUpdateKeySet:              "update-key-set",
	NetUpdateDistributionKey:     "update-distribution-key",
	NetRequestMasterKey:          "request-master-key",
	NetSetMasterKey:              "set-master-key",
	NetWhatIsNetworkNumber:       "what-is-network-number",
	NetNetworkNumberIs:           "network-number-is",
}

// String names the message. The proprietary range is rendered as such,
// because a vendor's message has no standard name to give it.
func (t NetworkMessageType) String() string {
	if s, ok := networkNames[t]; ok {
		return s
	}
	if t.Proprietary() {
		return fmt.Sprintf("proprietary-0x%02x", uint8(t))
	}
	return fmt.Sprintf("network-message-0x%02x", uint8(t))
}

// Proprietary reports whether the type is in the vendor range, which
// carries a vendor identifier and whose meaning is the vendor's.
func (t NetworkMessageType) Proprietary() bool { return t >= 0x80 }

// Known reports whether the standard defines this message.
func (t NetworkMessageType) Known() bool { _, ok := networkNames[t]; return ok }

// Routing reports whether the message changes or asks about how the
// internetwork is routed, as against reporting on it.
//
// Initialize-Routing-Table rewrites a router's table from an
// unauthenticated message, which is enough to take a whole BACnet
// network off the air or to put this relay's own address in front of one.
// Establish- and Disconnect-Connection-To-Network dial and drop a
// half-router's link. None of the three is something a client network
// sends to a building in the ordinary course of a day.
func (t NetworkMessageType) Routing() bool {
	switch t {
	case NetInitializeRoutingTable, NetEstablishConnection, NetDisconnectConnection:
		return true
	}
	return false
}

// Security reports whether the message belongs to clause 24's network
// security: the challenge, the wrapped payloads and the key distribution.
//
// A relay cannot read inside a Security-Payload, which is the point of
// it. That is a policy decision rather than a defect: an estate that has
// deployed BACnet network security has a stronger control than this relay
// and can let the payloads through, and one that has not should not be
// seeing key distribution messages arrive from a client network at all.
func (t NetworkMessageType) Security() bool {
	switch t {
	case NetChallengeRequest, NetSecurityPayload, NetSecurityResponse,
		NetRequestKeyUpdate, NetUpdateKeySet, NetUpdateDistributionKey,
		NetRequestMasterKey, NetSetMasterKey:
		return true
	}
	return false
}
