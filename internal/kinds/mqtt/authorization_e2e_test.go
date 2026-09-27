package mqtt_test

import (
	"fmt"
	"testing"

	_ "github.com/rom/xproxy/internal/kinds/mqtt"
	"github.com/rom/xproxy/internal/mqtt"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
)

// authzServerFor is a relay under the estate's authorisation policy.
func authzServerFor(t *testing.T, b *fakeBroker, extra, policy string) (*proxy.Server, string) {
	t.Helper()
	s := proxytest.Start(t, fmt.Sprintf(mqttYAML, extra, b.addr())+"authorization:\n"+policy)
	return s, s.Addrs()["iot"]
}

// The CONNECT packet is where the username appears, so it is where the policy is
// asked -- and before the packet is forwarded, so a client no rule covers never
// reaches the broker.
func TestAPolicyRefusesBeforeTheBrokerSeesTheConnect(t *testing.T) {
	b := startBroker(t, &fakeBroker{})
	s, addr := authzServerFor(t, b, "", `  rules:
    - {name: gateways, allow: true, users: [gateway]}
`)

	c := dialMQTT(t, addr)
	c.send(mqttConnect(mqtt.V311, "device-1", "device-1"))
	if ack := c.expect(mqtt.CONNACK, "connack"); ack.Body[1] == 0 {
		t.Error("a client no rule covers was accepted")
	}
	if _, ok := b.saw(mqtt.CONNECT); ok {
		t.Error("the CONNECT reached the broker")
	}
	if n := s.Stats().Refusals["mqtt"]["authorization"]; n != 1 {
		t.Errorf("authorization refusals %d, want 1: %v", n, s.Stats().Refusals["mqtt"])
	}
}

// And the client a rule does name gets through to the broker.
func TestAPolicyAdmitsTheClientItNames(t *testing.T) {
	b := startBroker(t, &fakeBroker{})
	_, addr := authzServerFor(t, b, "", `  rules:
    - {name: devices, allow: true, users: [device-1], targets: [broker], actions: [connect]}
`)

	c := dialMQTT(t, addr)
	c.send(mqttConnect(mqtt.V311, "device-1", "device-1"))
	if ack := c.expect(mqtt.CONNACK, "connack"); ack.Body[1] != 0 {
		t.Fatalf("connack code %d", ack.Body[1])
	}
	if _, ok := b.saw(mqtt.CONNECT); !ok {
		t.Error("the CONNECT did not reach the broker")
	}
}

// The client identifier is not an identity and does not reach a rule: it is the
// mqtt policy's own business. A rule naming the identifier as a user therefore
// matches nobody, and the default decides -- which is what keeps an operator from
// writing an identity rule against a string any client may choose.
func TestTheClientIdentifierIsNotAnIdentity(t *testing.T) {
	b := startBroker(t, &fakeBroker{})
	_, addr := authzServerFor(t, b, "", `  default: allow
  rules:
    - {name: not-device-9, users: [device-9]}
`)

	// The username is device-1 and the identifier device-9. The deny rule names
	// device-9, and it must not match, because it is a rule about users.
	c := dialMQTT(t, addr)
	c.send(mqttConnect(mqtt.V311, "device-9", "device-1"))
	if ack := c.expect(mqtt.CONNACK, "connack"); ack.Body[1] != 0 {
		t.Fatalf("a rule about users matched the client identifier: connack %d", ack.Body[1])
	}
}

// A policy in shadow mode records and admits.
func TestAShadowedPolicyRecordsAndAdmitsOnMQTT(t *testing.T) {
	b := startBroker(t, &fakeBroker{})
	s, addr := authzServerFor(t, b, "", `  shadow: true
  rules:
    - {name: not-device-1, users: [device-1]}
`)

	c := dialMQTT(t, addr)
	c.send(mqttConnect(mqtt.V311, "device-1", "device-1"))
	if ack := c.expect(mqtt.CONNACK, "connack"); ack.Body[1] != 0 {
		t.Fatalf("a shadowed policy refused a client: connack %d", ack.Body[1])
	}
	if _, ok := b.saw(mqtt.CONNECT); !ok {
		t.Error("the CONNECT did not reach the broker, so the session was not really admitted")
	}
	if n := s.Stats().Refusals["mqtt"]["authorization"]; n != 0 {
		t.Errorf("a shadowed refusal was counted as a refusal: %d", n)
	}
	found := false
	for _, e := range s.Shadow().Report() {
		if e.Kind == "mqtt" && e.Reason == "authorization" && e.Rule == "not-device-1" {
			found = true
		}
	}
	if !found {
		t.Errorf("no shadow entry naming the rule: %+v", s.Shadow().Report())
	}
}
