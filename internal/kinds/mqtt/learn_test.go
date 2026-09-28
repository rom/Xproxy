package mqtt_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	mqtt "github.com/rom/xproxy/internal/mqtt"
	"github.com/rom/xproxy/internal/proxy"
)

// Learning mode, through the whole proxy.
//
// A broker in a plant carries topics nobody wrote down. A `publish_allow` list
// written from the naming convention refuses the traffic that does not follow
// it, which on a message bus means telemetry silently stops arriving: the client
// keeps connecting and keeps publishing, and nothing changes on the screen until
// somebody notices a flat line.

func learnServer(t *testing.T, b *fakeBroker, extra string, enforce bool) (*proxy.Server, string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "learned.yaml")
	s, addr := mqttServerFor(t, b, fmt.Sprintf(`        learn:
          enabled: true
          file: %s
          enforce: %t
%s`, path, enforce, extra))
	return s, addr, path
}

// learnedReport shuts the listener down, which is what writes the report, and
// reads it.
func learnedReport(t *testing.T, s *proxy.Server, c *mqttClient, path string) string {
	t.Helper()
	// The client is closed first: a shutdown waits for the sessions to drain,
	// and an idle connection nobody closed makes every test here wait out the
	// grace period.
	_ = c.conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the learning report was not written: %v", err)
	}
	return string(body)
}

// withoutComments drops the report's prose, so an assertion about what the
// proposal contains is about the YAML and not about the explanation beside it.
func withoutComments(s string) string {
	lines := strings.Split(s, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

// learnSession connects and returns the client.
func learnSession(t *testing.T, addr, clientID, username string) *mqttClient {
	t.Helper()
	c := dialMQTT(t, addr)
	c.send(mqttConnect(mqtt.V311, clientID, username))
	if ack := c.expect(mqtt.CONNACK, "connack"); ack.Body[1] != 0 {
		t.Fatalf("connack code %d", ack.Body[1])
	}
	return c
}

// The generalisation is the whole point: concrete topics become a filter of the
// depth that was seen, with `+` where the traffic varied -- and never a `#`.
func TestAnMQTTLearningRunGeneralisesWithoutAHash(t *testing.T) {
	b := startBroker(t, &fakeBroker{})
	s, addr, path := learnServer(t, b, `        publish_allow: ["#"]
        subscribe_allow: ["#"]`, true)

	c := learnSession(t, addr, "press-1", "line3")
	// Three topics of the same depth: the third level varies, the fourth
	// varies, the first two do not.
	for _, topic := range []string{
		"plant/line3/press1/temperature",
		"plant/line3/press1/pressure",
		"plant/line3/press2/temperature",
	} {
		c.send(mqttPublishAs(mqtt.V311, topic, 0, 0, false, "21.5"))
	}
	c.send(mqtt.Packet{Type: mqtt.PINGREQ})
	c.expect(mqtt.PINGRESP, "pingresp")
	got := learnedReport(t, s, c, path)

	obs, rules, ok := strings.Cut(got, "\n# The lists that permit")
	if !ok {
		t.Fatalf("the report proposes no lists:\n%s", got)
	}
	for _, want := range []string{
		"MQTT traffic",
		`listener "iot"`,
		"identity: user:line3",
		"direction: publish",
		"depth: 4",
		"messages: 3",
		`level_0: ["plant"]`,
		`level_1: ["line3"]`,
		`level_2: ["press1", "press2"]`,
		`client_ids: ["press-1"]`,
	} {
		if !strings.Contains(obs, want) {
			t.Errorf("the report has no %q:\n%s", want, obs)
		}
	}
	// The levels that did not vary stay literal; the ones that did become `+`.
	if !strings.Contains(rules, `"plant/line3/+/+"`) {
		t.Errorf("the filter was not generalised per position:\n%s", rules)
	}
	// And no multi-level wildcard is proposed, ever.
	if y := withoutComments(rules); strings.Contains(y, "#") {
		t.Errorf("the proposal reaches for a multi-level wildcard:\n%s", y)
	}
}

// Topics of different depths do not share a filter, because a `+` matches
// exactly one level. Folding them together would leave no way to write one but
// `#`, which is the thing this must not do.
func TestTopicsOfDifferentDepthsGetSeparateFilters(t *testing.T) {
	b := startBroker(t, &fakeBroker{})
	s, addr, path := learnServer(t, b, `        publish_allow: ["#"]`, true)

	c := learnSession(t, addr, "gw-1", "gateway")
	c.send(mqttPublishAs(mqtt.V311, "plant/line3/temperature", 0, 0, false, "21"))
	c.send(mqttPublishAs(mqtt.V311, "plant/line3/press1/temperature", 0, 0, false, "22"))
	c.send(mqtt.Packet{Type: mqtt.PINGREQ})
	c.expect(mqtt.PINGRESP, "pingresp")
	got := learnedReport(t, s, c, path)

	_, rules, ok := strings.Cut(got, "\n# The lists that permit")
	if !ok {
		t.Fatalf("the report proposes no lists:\n%s", got)
	}
	for _, want := range []string{`"plant/line3/temperature"`, `"plant/line3/press1/temperature"`} {
		if !strings.Contains(rules, want) {
			t.Errorf("the proposal has no %q:\n%s", want, rules)
		}
	}
	if y := withoutComments(rules); strings.Contains(y, "#") {
		t.Errorf("the proposal reaches for a multi-level wildcard:\n%s", y)
	}
}

// A filter the client wrote is recorded verbatim and proposed verbatim: a
// subscription is already a filter, and narrowing it would break the client
// that asked for it. A `#` in one is flagged rather than quietly kept.
func TestAClientWrittenFilterIsKeptVerbatimAndFlagged(t *testing.T) {
	b := startBroker(t, &fakeBroker{})
	s, addr, path := learnServer(t, b, `        subscribe_allow: ["#"]`, true)

	c := learnSession(t, addr, "hist-1", "historian")
	c.send(mqttSubscribe(1, "plant/#"))
	c.expect(mqtt.SUBACK, "suback")
	got := learnedReport(t, s, c, path)

	obs, rules, ok := strings.Cut(got, "\n# The lists that permit")
	if !ok {
		t.Fatalf("the report proposes no lists:\n%s", got)
	}
	if !strings.Contains(obs, "depth: filter") {
		t.Errorf("the client-written filter is not recorded as one:\n%s", obs)
	}
	if !strings.Contains(obs, `filters: ["plant/#"]`) {
		t.Errorf("the filter was not recorded verbatim:\n%s", obs)
	}
	if !strings.Contains(obs, "multi-level wildcard") {
		t.Errorf("the multi-level wildcard was not flagged:\n%s", obs)
	}
	// It is proposed under subscribe_allow, because the historian needs it.
	if !strings.Contains(rules, "subscribe_allow:\n  - \"plant/#\"") {
		t.Errorf("the filter the client needs was not proposed:\n%s", rules)
	}
	// And it is not proposed under publish_allow, which nothing published to.
	pubList, _, _ := strings.Cut(rules, "subscribe_allow")
	if strings.Contains(pubList, "plant") {
		t.Errorf("a subscription leaked into publish_allow:\n%s", pubList)
	}
}

// A learning run is observe-only by default, which is the point: a run that
// refused half the traffic would have changed the thing it was measuring.
func TestAnMQTTLearningRunDoesNotEnforceByDefault(t *testing.T) {
	b := startBroker(t, &fakeBroker{})
	s, addr, path := learnServer(t, b, `        publish_allow: ["devices/+/telemetry"]`, false)

	c := learnSession(t, addr, "press-1", "line3")
	// Nothing allows this topic. The listener is learning, so it goes through
	// and the report says the policy disagreed.
	c.send(mqttPublishAs(mqtt.V311, "plant/line3/press1/temperature", 0, 0, false, "21"))
	c.send(mqtt.Packet{Type: mqtt.PINGREQ})
	c.expect(mqtt.PINGRESP, "pingresp")
	if _, ok := b.saw(mqtt.PUBLISH); !ok {
		t.Fatal("a learning run refused the publication it was meant to be measuring")
	}
	got := learnedReport(t, s, c, path)
	if !strings.Contains(got, "denied_by_policy: 1") {
		t.Errorf("the report does not say the policy disagreed:\n%s", got)
	}
}

// Learning with enforcement on is a listener that still refuses. The two are
// separate knobs on purpose: a run on an estate that cannot be left unprotected
// keeps the policy in force and writes down what it refused.
func TestAnMQTTLearningRunWithEnforcementStillRefuses(t *testing.T) {
	b := startBroker(t, &fakeBroker{})
	// drop rather than the default disconnect, so the session survives the
	// refusal and the test can ask the listener what it recorded.
	s, addr, path := learnServer(t, b, `        publish_allow: ["devices/+/telemetry"]
        action: drop`, true)

	c := learnSession(t, addr, "press-1", "line3")
	c.send(mqttPublishAs(mqtt.V311, "plant/line3/press1/temperature", 0, 0, false, "21"))
	c.send(mqtt.Packet{Type: mqtt.PINGREQ})
	c.expect(mqtt.PINGRESP, "pingresp")
	if _, ok := b.saw(mqtt.PUBLISH); ok {
		t.Error("the publication reached the broker anyway")
	}
	got := learnedReport(t, s, c, path)
	if !strings.Contains(got, "denied_by_policy: 1") {
		t.Errorf("the refusal is not in the report:\n%s", got)
	}
}

// The payload sizes and the qualities of service are what the topic rules are
// written from, and the payloads themselves are never recorded.
func TestTheReportCarriesSizesAndNotPayloads(t *testing.T) {
	b := startBroker(t, &fakeBroker{})
	s, addr, path := learnServer(t, b, `        publish_allow: ["#"]`, true)

	c := learnSession(t, addr, "press-1", "line3")
	c.send(mqttPublishAs(mqtt.V311, "plant/line3/press1/temperature", 0, 0, false, "21"))
	c.send(mqttPublishAs(mqtt.V311, "plant/line3/press1/pressure", 1, 7, false, "a-secret-recipe-value"))
	c.expect(mqtt.PUBACK, "puback")
	got := learnedReport(t, s, c, path)

	if strings.Contains(got, "a-secret-recipe-value") {
		t.Errorf("the report carries a payload:\n%s", got)
	}
	if !strings.Contains(got, "max_payload_seen: 21") {
		t.Errorf("the largest payload size is not recorded:\n%s", got)
	}
	if !strings.Contains(got, "qos_seen: 0..1") {
		t.Errorf("the qualities of service are not recorded:\n%s", got)
	}
	// And the topic rule is written from those.
	_, rules, _ := strings.Cut(got, "\n# The lists that permit")
	for _, want := range []string{"topics:", "max_payload_bytes: 21", "max_qos: 1"} {
		if !strings.Contains(rules, want) {
			t.Errorf("the topic rule has no %q:\n%s", want, rules)
		}
	}
}

// Retain is the one topic property a report must not guess at. A run that saw no
// retained message has not learned that none is wanted, so `allow_retain: false`
// is never written.
func TestRetainIsNeverProposedAsFalse(t *testing.T) {
	b := startBroker(t, &fakeBroker{})
	s, addr, path := learnServer(t, b, `        publish_allow: ["#"]
        allow_retain: true`, true)

	c := learnSession(t, addr, "press-1", "line3")
	c.send(mqttPublishAs(mqtt.V311, "plant/line3/press1/temperature", 0, 0, false, "21"))
	c.send(mqtt.Packet{Type: mqtt.PINGREQ})
	c.expect(mqtt.PINGRESP, "pingresp")
	got := learnedReport(t, s, c, path)

	if strings.Contains(got, "allow_retain: false") {
		t.Errorf("the proposal wrote a retain policy it had not observed:\n%s", got)
	}
	if !strings.Contains(got, "allow_retain is left") {
		t.Errorf("the proposal does not say why retain is absent:\n%s", got)
	}
}

// A retained publication is recorded, and then the rule says so.
func TestARetainedPublicationIsProposedAsOne(t *testing.T) {
	b := startBroker(t, &fakeBroker{})
	s, addr, path := learnServer(t, b, `        publish_allow: ["#"]
        allow_retain: true`, true)

	c := learnSession(t, addr, "gw-1", "gateway")
	c.send(mqttPublishAs(mqtt.V311, "plant/line3/press1/birth", 0, 0, true, "up"))
	c.send(mqtt.Packet{Type: mqtt.PINGREQ})
	c.expect(mqtt.PINGRESP, "pingresp")
	got := learnedReport(t, s, c, path)

	if !strings.Contains(got, "retained: 1") {
		t.Errorf("the retained publication is not recorded:\n%s", got)
	}
	if !strings.Contains(got, "allow_retain: true") {
		t.Errorf("the rule does not permit the retain that was observed:\n%s", got)
	}
}

// What the section refuses to load.
func TestWhatAnMQTTLearningSectionRefusesToLoad(t *testing.T) {
	b := startBroker(t, &fakeBroker{})
	for _, tc := range []struct{ name, section, wants string }{
		{
			name:    "learning with no file",
			section: "        learn: {enabled: true}",
			wants:   "learn.file: required",
		},
		{
			name:    "a relative path",
			section: "        learn: {enabled: true, file: learned.yaml}",
			wants:   "must be an absolute path",
		},
		{
			name:    "an interval nobody meant",
			section: "        learn: {enabled: true, file: /tmp/l.yaml, interval: 1s}",
			wants:   "learn.interval: must be between 10s and 24h",
		},
		{
			name:    "a bound nobody meant",
			section: "        learn: {enabled: true, file: /tmp/l.yaml, max_subjects: 2}",
			wants:   "learn.max_subjects: must be between 16 and 1000000",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			yaml := fmt.Sprintf(mqttYAML, tc.section, b.addr())
			if _, err := config.Parse([]byte(yaml)); err == nil {
				t.Fatal("the section loaded")
			} else if !strings.Contains(err.Error(), tc.wants) {
				t.Errorf("the error is %v, want it to mention %q", err, tc.wants)
			}
		})
	}
}

// A subscription the policy refuses is recorded as refused, against the filter
// the policy actually stopped at.
//
// The packet is refused as a whole -- a partial grant would leave this proxy's
// idea of the session and the broker's out of step -- so the report marks the
// filter that was reached and not the ones behind it, which were never decided.
func TestTheRefusedFilterIsTheOneRecorded(t *testing.T) {
	b := startBroker(t, &fakeBroker{})
	s, addr, path := learnServer(t, b, `        subscribe_allow: ["plant/line3/+/setpoint"]
        action: drop`, true)

	c := learnSession(t, addr, "hist-1", "historian")
	// The first filter is allowed and the second is not, so the packet is
	// refused at the second.
	c.send(mqttSubscribe(1, "plant/line3/press1/setpoint", "plant/line3/press1/secret"))
	c.expect(mqtt.SUBACK, "suback")
	got := learnedReport(t, s, c, path)

	// Both filters are four levels deep, so they share a subject; the refusal is
	// one of the two messages in it.
	if !strings.Contains(got, "messages: 2") {
		t.Errorf("both filters were not recorded:\n%s", got)
	}
	if !strings.Contains(got, "denied_by_policy: 1") {
		t.Errorf("the refusal was not recorded, or was charged to both filters:\n%s", got)
	}
}
