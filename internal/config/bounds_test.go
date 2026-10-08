package config

import (
	"strings"
	"testing"
)

// The bounds a relay listener's settings are held to, one listener kind
// at a time.
//
// Each of these settings is a limit on what the relay will carry, and a
// limit that did not load as written is worse than no limit at all: an
// operator who has set max_repetitions stops thinking about SNMP
// amplification. So every bound is checked at load, and every check is
// here with the configuration that trips it.
//
// The validator collects problems rather than stopping at the first,
// which is what lets one configuration carry a dozen mistakes and get a
// dozen answers -- an operator fixing one error per restart is the
// failure mode this avoids. The tests below rely on it: a section wrong
// in every way must be told about every way.

// refuses parses a configuration that must not load and reports the
// problem for each want that is missing.
func refuses(t *testing.T, yaml string, wants ...string) {
	t.Helper()
	_, err := ParseWith([]byte(yaml), false)
	if err == nil {
		t.Fatal("the configuration loaded")
	}
	got := err.Error()
	for _, w := range wants {
		if !strings.Contains(got, w) {
			t.Errorf("no problem mentioning %q", w)
		}
	}
	if t.Failed() {
		t.Logf("problems were:\n%s", got)
	}
}

// advises parses a configuration that must load and reports the warning
// for each want that is missing.
func advises(t *testing.T, yaml string, wants ...string) {
	t.Helper()
	c, err := ParseWith([]byte(yaml), false)
	if err != nil {
		t.Fatalf("did not load: %v", err)
	}
	for _, w := range wants {
		if !hasAdvice(c, w) {
			t.Errorf("no warning mentioning %q", w)
		}
	}
	if t.Failed() {
		t.Logf("warnings were:\n%s", strings.Join(c.Advice(), "\n"))
	}
}

// Every enumerated setting and every numeric bound on an snmp listener,
// wrong at once.
func TestEveryBoundOnAnSNMPListener(t *testing.T) {
	long := strings.Repeat("c", 256)
	refuses(t, snmpDeceptionConfig(`        upstream: agents
        mode: sideways
        transport: sctp
        tls_mode: whenever
        upstream_tls_mode: sometimes
        versions: [v2c, v9]
        communities: ["", "`+long+`"]
        users: [""]
        min_security_level: medium
        replay_window: 2h
        max_usm_engines: -1
        upgrade_version: v4
        upstream_community: "`+long+`"
        default_action: perhaps
        deny_response: shout
        max_repetitions: -1
        max_var_binds: -1
        max_response_bytes: -1
        max_response_ratio: -1
        max_pending: -1
        max_connections: 99999
        idle_timeout: 2h
        request_timeout: 2m
        connect_timeout: 1ms
        max_message_bytes: 100
        rate_limit: -1
        rate_burst: -1`),
		"mode: must be reverse or forward",
		"transport: must be udp or tcp",
		"tls_mode: must be implicit or none",
		"upstream_tls_mode: must be none or implicit",
		`versions[1]: "v9" must be v1, v2c or v3`,
		"communities[0]: empty",
		"communities[1]: longer than 255 octets",
		"users[0]: must be 1 to 255 octets",
		"min_security_level: must be noAuthNoPriv, authNoPriv or authPriv",
		"replay_window: must be between 1s and 1h",
		"max_usm_engines: must be between 0 and 1024",
		"upgrade_version: must be v1, v2c or v3",
		"upstream_community: longer than 255 octets",
		"default_action: must be deny or allow",
		"deny_response: must be error, drop or close",
		"max_repetitions: must be between 0 and 1048576",
		"max_var_binds: must be between 0 and",
		"max_response_bytes: must be between 0 and",
		"max_response_ratio: must be between 0 and 65536",
		"max_pending: must be between 0 and 65536",
		"max_connections: must be between 0 and 4096",
		"idle_timeout: must be between 1s and 1h",
		"request_timeout: must be between 100ms and 1m0s",
		"connect_timeout: must be between 100ms and 1m0s",
		"max_message_bytes: must be between 484",
		"rate_limit: must be between 0 and 1048576",
		"rate_burst: must be between 0 and 1048576",
	)
}

// The same for one rule, which is where the policy actually lives: a
// rule that does not load as written is a control an operator believes
// is there.
func TestEveryMistakeInAnSNMPRule(t *testing.T) {
	refuses(t, snmpDeceptionConfig(`        upstream: agents
        rules:
          - name: "not a name!"
            action: perhaps
            versions: [v9]
            pdus: [dance]
            access: [erase]
            oids: ["1.3.6.1.4.1.x"]
            deny_oids: ["not an oid"]
            write_oids: [""]
            min_security_level: medium
            transports: [sctp]
            security_names: [""]
            users: [poller]
            max_repetitions: -1
          - {name: twice, action: deny, pdus: [set]}
          - {name: twice, action: deny, pdus: [get]}`),
		`name: "not a name!" is not a valid name`,
		"action: must be allow, deny or observe",
		`versions[0]: "v9" must be v1, v2c or v3`,
		`pdus[0]: "dance" is not an operation`,
		`access[0]: "erase" must be read, write or notify`,
		"oids[0]:",
		"deny_oids[0]:",
		"write_oids[0]:",
		"min_security_level: must be noAuthNoPriv",
		`transports[0]: "sctp" must be udp, tcp, tls or dtls`,
		"security_names[0]: must be 1 to 255 octets",
		"cert_to_name is what maps a certificate to one",
		"one message is never both",
		"max_repetitions: must be between 0 and 1048576",
		`name: duplicate "twice"`,
	)
}

// implicit TLS with nothing to present it with.
func TestSNMPImplicitTLSNeedsTheListenersOwnCertificate(t *testing.T) {
	refuses(t, snmpDeceptionConfig(`        upstream: agents
        transport: tcp
        tls_mode: implicit`),
		"tls_mode: implicit needs the listener's tls section")
}

// The warnings that depend on the transport, which is the half of this
// listener an operator is most likely to get wrong: SNMP is a datagram
// protocol with a stream mode bolted on, and a setting that only means
// something on one half silently means nothing on the other.
func TestTheSNMPWarningsThatDependOnTheTransport(t *testing.T) {
	advises(t, snmpDeceptionConfig(`        upstream: agents
        upstream_tls_mode: implicit
        deny_response: close
        traps: true
        read_only: true
        rate_burst: 10
        rules:
          - {name: open, action: allow}
          - {name: watch, action: observe, write_oids: ["1.3.6.1.2.1.1.5.0"]}`),
		"implicit applies to the stream half only",
		"close ends a stream session",
		"a trap listener carries no SetRequest",
		"a burst without a rate_limit bounds nothing",
		"allow rule that names no client",
		"an observe rule records the message and decides nothing",
	)
}

// ldapConfig is one ldap listener and a directory to relay to.
func ldapConfig(section string) string {
	return `
version: 1
server:
  listeners:
    - name: dir
      address: "127.0.0.1:0"
      kind: ldap
      ldap:
` + section + `
upstreams:
  - name: directory
    endpoints: [{address: "10.0.0.9:389"}]
`
}

// Every enumerated setting and every numeric bound on an ldap listener.
func TestEveryBoundOnAnLDAPListener(t *testing.T) {
	refuses(t, ldapConfig(`        upstream: directory
        mode: sideways
        tls_mode: whenever
        upstream_tls_mode: sometimes
        min_version: 4
        methods: [whatever]
        sasl_mechanisms: ["", "A-very-long-mechanism-name"]
        base_dns: ["", "not a distinguished name"]
        deny_attributes: [""]
        on_denied_attribute: hide
        max_entries: -1
        max_filter_terms: -1
        max_filter_depth: -1
        extended_operations: ["not an oid"]
        deny_controls: ["also not an oid"]
        default_action: perhaps
        deny_response: shout
        max_outstanding: -1
        max_connections: 99999999
        idle_timeout: 48h
        request_timeout: 20m
        connect_timeout: 1ms
        max_message_bytes: 100
        rate_limit: -1
        rate_burst: -1
        bind_rate_limit: -1
        bind_rate_burst: -1`),
		"mode: must be reverse or forward",
		"tls_mode: must be implicit, starttls or none",
		"upstream_tls_mode: must be none, implicit or starttls",
		"min_version: must be 2 or 3",
		`methods[0]: "whatever" must be anonymous, unauthenticated, simple or sasl`,
		"sasl_mechanisms[0]: empty",
		"sasl_mechanisms[1]: longer than 20 characters",
		"base_dns[0]: empty; the root is not a suffix worth naming",
		"base_dns[1]:",
		"deny_attributes[0]: empty",
		"on_denied_attribute: must be strip or deny",
		"max_entries: must be between 0 and 1048576",
		"max_filter_terms: must be between 0 and",
		"max_filter_depth: must be between 0 and",
		`extended_operations[0]: "not an oid" is not an object identifier`,
		`deny_controls[0]: "also not an oid" is not an object identifier`,
		"default_action: must be deny or allow",
		"deny_response: must be insufficient, unwilling, drop or close",
		"max_outstanding: must be between 0 and 65536",
		"max_connections: must be between 0 and 65536",
		"idle_timeout: must be between 1s and 24h0m0s",
		"request_timeout: must be between 1s and 10m0s",
		"connect_timeout: must be between 100ms and 1m0s",
		"max_message_bytes: must be between 1024 and",
		"rate_limit: must be between 0 and 1048576",
		"rate_burst: must be between 0 and 1048576",
		"bind_rate_limit: must be between 0 and 1048576",
		"bind_rate_burst: must be between 0 and 1048576",
	)
}

func TestEveryMistakeInAnLDAPRule(t *testing.T) {
	refuses(t, ldapConfig(`        upstream: directory
        rules:
          - name: "not a name!"
            action: perhaps
            methods: [whatever]
            base_dns: [""]
            deny_dns: ["not a distinguished name"]
            bind_dns: ["also not one"]
            operations: [dance]
            access: [erase]
            scopes: [everything]
            max_entries: -1
            max_filter_terms: -1
            max_filter_depth: -1
          - {name: twice, action: deny, operations: [add]}
          - {name: twice, action: deny, operations: [delete]}`),
		`name: "not a name!" is not a valid name`,
		"action: must be allow, deny or observe",
		`methods[0]: "whatever" must be anonymous`,
		"base_dns[0]: empty",
		"deny_dns[0]:",
		"bind_dns[0]:",
		`operations[0]: "dance" is not an operation`,
		`access[0]: "erase" must be read, write or bind`,
		`scopes[0]: "everything" must be base, one or sub`,
		"max_entries: must be between 0 and 1048576",
		"max_filter_terms: must be between 0 and",
		"max_filter_depth: must be between 0 and",
		`name: duplicate "twice"`,
	)
}

// The LDAP warnings, which are mostly about one thing: a bind that
// looks like authentication and is not.
func TestTheLDAPWarningsAboutBindsAndBounds(t *testing.T) {
	advises(t, ldapConfig(`        upstream: directory
        min_version: 2
        require_tls: false
        methods: [unauthenticated, sasl]
        sasl_mechanisms: [PLAIN]
        deny_attributes: [mail]
        default_action: allow
        rate_burst: 10`),
		"allow_clients: empty",
		"require_tls: false on a listener that is not TLS throughout",
		"min_version: 2 accepts LDAPv2",
		"an anonymous bind and most directories answer with success",
		"PLAIN carries a password exactly as a simple bind does",
		"base_dns: empty",
		"deny_attributes: set without userPassword",
		"max_entries: 0 leaves the entries one search may return unbounded",
		"default_action allow with no rules",
		"rate_burst: a burst without a rate_limit bounds nothing",
		"bind_rate_limit: 0 leaves binds unbounded",
	)
}

// dhcp6Config is one dhcp6 listener on the port a client sends to.
func dhcp6Config(section string) string {
	return `
version: 1
server:
  listeners:
    - name: relay
      address: "127.0.0.1:547"
      kind: dhcp6
      dhcp6:
` + section + `
upstreams:
  - name: servers
    endpoints: [{address: "[2001:db8::1]:547"}]
`
}

// Every enumerated setting and every numeric bound on a dhcp6 listener.
func TestEveryBoundOnADHCPv6Listener(t *testing.T) {
	refuses(t, dhcp6Config(`        upstream: servers
        mode: sideways
        link_address: "fe80::1"
        allow_resolvers: ["not an address", "192.0.2.1"]
        message_types: [dance, relay_forward]
        deny_options: [not-an-option]
        allow_options: [dns_servers]
        deny_requested_options: ["99999"]
        allow_domains: [""]
        allow_boot_urls: ["["]
        on_denied_option: hide
        on_client_relay_option: hide
        default_action: perhaps
        max_relay_hops: 99
        max_message_bytes: 10
        max_pending: -1
        max_clients: -1
        request_timeout: 2m
        rate_limit: -1
        min_lease_time: 2h
        max_lease_time: 1h
        remote_id_enterprise: 99999999999
        prefix_delegation:
          prefixes: ["not a network", "192.0.2.0/24", "::/0"]
          min_length: 200
          max_length: 64`),
		"mode: must be reverse or forward",
		`link_address: "fe80::1" is link-local`,
		`allow_resolvers[0]: "not an address" is not an address`,
		`allow_resolvers[1]: "192.0.2.1" is not an IPv6 address`,
		`message_types[0]: "dance" is not a DHCPv6 message type`,
		`message_types[1]: "relay_forward" is a relay agent's own message`,
		`deny_options[0]: "not-an-option" is not a DHCPv6 option name or number`,
		`deny_requested_options[0]: "99999" is not a DHCPv6 option`,
		"deny_options and allow_options are two ways of writing the same policy",
		"allow_domains[0]: empty",
		"allow_boot_urls[0]:",
		"on_denied_option: must be strip or deny",
		"on_client_relay_option: must be strip or deny",
		"default_action: must be allow or deny",
		"max_relay_hops: must be between 1 and 32",
		"max_message_bytes: must be between 128 and",
		"max_pending: must be between 1 and 1048576",
		"max_clients: must be between 1 and 1048576",
		"request_timeout: must be between 1s and 1m",
		"rate_limit and rate_burst cannot be negative",
		"min_lease_time is longer than max_lease_time",
		"remote_id_enterprise: must be a 32-bit enterprise number",
		`prefixes[0]: "not a network" is not a network`,
		`prefixes[1]: "192.0.2.0/24" is not an IPv6 network`,
		"prefixes[2]: ::/0 is every prefix there is",
		"min_length: must be between 1 and 128",
		"min_length is longer than max_length",
	)
}

// The link address is what tells a server which segment to allocate
// from, so a relay without a usable one is not a relay.
func TestTheDHCPv6LinkAddressIsAnAddressOfASegment(t *testing.T) {
	refuses(t, dhcp6Config(`        upstream: servers`),
		"link_address: required in reverse mode")
	refuses(t, dhcp6Config(`        upstream: servers
        link_address: "::1 or thereabouts"`),
		"is not an address")
	refuses(t, dhcp6Config(`        upstream: servers
        link_address: "192.0.2.1"`),
		"is not an IPv6 address")
}

func TestEveryMistakeInADHCPv6Rule(t *testing.T) {
	refuses(t, dhcp6Config(`        upstream: servers
        link_address: "2001:db8::1"
        rules:
          - action: perhaps
            message_types: [dance]
            deny_options: [not-an-option]
            allow_resolvers: ["192.0.2.1"]
            duids: [""]
            vendor_classes: ["["]
            user_classes: [""]
            allow_domains: [""]
            allow_boot_urls: [""]
          - {name: twice, action: deny}
          - {name: twice, action: deny}`),
		"rules[0].name: required",
		"rules[0].action: must be allow, deny or observe",
		`rules[0].message_types[0]: "dance" is not a DHCPv6 message type`,
		"rules[0].deny_options[0]:",
		"rules[0].allow_resolvers[0]:",
		"rules[0].duids[0]: empty",
		"rules[0].vendor_classes[0]:",
		"rules[0].user_classes[0]: empty",
		"rules[0].allow_domains[0]: empty",
		"rules[0].allow_boot_urls[0]: empty",
		`rules[2].name: "twice" is used twice`,
	)
}

// The DHCPv6 warnings, which are each about a reply this relay would
// carry: a server that configures the client, a resolver nobody vouched
// for, a prefix the size of the internet.
func TestTheDHCPv6WarningsAboutWhatAReplyCarries(t *testing.T) {
	advises(t, `
version: 1
server:
  listeners:
    - name: relay
      address: "127.0.0.1:1547"
      kind: dhcp6
      dhcp6:
        upstream: servers
        link_address: "2001:db8::1"
        allow_reconfigure: true
        deny_options: [dns_servers]
        remote_id: "relay-7"
        prefix_delegation: {min_length: 0, max_length: 0}
upstreams:
  - name: servers
    endpoints: [{address: "[2001:db8::1]:547"}]
`,
		"allow_reconfigure carries a RECONFIGURE from a server",
		"deny_options replaces the built-in list",
		"remote_id has no remote_id_enterprise",
		"prefix delegation is carried with no prefixes and no length bound",
		"allow_resolvers: empty",
		"rather than 547",
	)
}

// Every enumerated setting and every numeric bound on an smtp listener.
func TestEveryBoundOnAnSMTPListener(t *testing.T) {
	refuses(t, mailConfig("smtp", `        tls_mode: whenever
        upstream_tls_mode: whenever
        bare_newlines: ignore
        max_command_line: 10
        max_text_line: 5
        max_message_size: -1
        max_recipients: -1
        max_messages: -1
        max_errors: -1
        max_connections: -1
        read_timeout: 2h
        session_timeout: -1s
        commands: [MAIL, MAIL, SMUGGLE]
        hide_capabilities: ["two words", ""]
        allow_clients: ["not a cidr"]
`, false),
		"tls_mode: must be starttls, implicit or none",
		"upstream_tls_mode: must be none, starttls or implicit",
		"bare_newlines: must be reject or convert",
		"max_command_line: must be 64..4096",
		"max_text_line: must be at least max_command_line",
		"max_message_size: must not be negative",
		"max_recipients: must be 1..100000",
		"max_messages: must be positive",
		"max_errors: must be positive",
		"max_connections: must be positive",
		"read_timeout: must be positive and at most 1h",
		"session_timeout: must be positive and at most 24h",
		"session_timeout: must not be shorter than read_timeout",
		`commands[2]: "SMUGGLE" is not an SMTP verb`,
		`commands[1]: "MAIL" listed twice`,
		"commands: QUIT must be allowed",
		"commands: EHLO or HELO must be allowed",
		"hide_capabilities[0]: must be one EHLO keyword",
		"hide_capabilities[1]: must be one EHLO keyword",
		`allow_clients[0]: "not a cidr" is not a CIDR`,
	)
}

// The settings that only make sense together. Each of these is a
// configuration an operator would read as protected and is not.
func TestTheSMTPSettingsThatContradictEachOther(t *testing.T) {
	// STARTTLS with nothing to present, and no verb to begin it with.
	refuses(t, mailConfig("smtp", `        tls_mode: starttls
        commands: [EHLO, QUIT]
        require_auth: true
`, false),
		"tls_mode: starttls needs the listener's tls section",
		"commands: tls_mode starttls needs STARTTLS in commands",
		"require_auth: needs AUTH in commands",
	)
	// Required TLS on a listener that offers none.
	refuses(t, mailConfig("smtp", `        tls_mode: none
        require_tls: true
`, false),
		"require_tls: nothing can satisfy it with tls_mode: none")
	// An upstream TLS section that is never used.
	refuses(t, mailConfig("smtp", `        tls_mode: none
        upstream_tls_mode: none
        upstream_tls: {ca_file: /ca.pem}
`, false),
		"upstream_tls: set with upstream_tls_mode: none")
}

// The two SMTP warnings: a session in the clear, and the verbs a
// prober uses to find out who exists.
func TestTheSMTPWarningsAboutClearSessionsAndProbes(t *testing.T) {
	advises(t, mailConfig("smtp", `        tls_mode: none
        commands: [EHLO, MAIL, RCPT, DATA, QUIT, VRFY, EXPN]
`, false),
		"VRFY and EXPN let a prober test whether an address exists",
		"none carries every password and every message in clear",
	)
}

// syslogConfig is one syslog relay, with or without a certificate.
func syslogConfig(section string, withTLS bool) string {
	tls := ""
	if withTLS {
		tls = `      tls:
        certificates:
          - {cert_file: /c.pem, key_file: /k.pem}
`
	}
	return `
version: 1
server:
  listeners:
    - name: records
      address: "127.0.0.1:1514"
      kind: syslog
` + tls + `      syslog:
` + section + `
upstreams:
  - name: collector
    endpoints: [{address: "10.0.0.9:514"}]
`
}

// Every enumerated setting and every numeric bound on a syslog relay.
func TestEveryBoundOnASyslogListener(t *testing.T) {
	refuses(t, syslogConfig(`        upstream: collector
        framing: whatever
        upstream_framing: whatever
        tls_mode: whenever
        upstream_tls_mode: whenever
        hostname: invent
        allow_facilities: [not-a-facility, mail]
        deny_facilities: [MAIL]
        min_severity: louder
        allow_senders: ["not a cidr"]
        deny_patterns: ["("]
        redact:
          - {pattern: "("}
          - {name: twice, pattern: "a"}
          - {name: twice, pattern: "b"}
        max_message_bytes: 10
        rate_limit: -1
        max_senders: -1
        max_connections: -1
        queue: -1`, false),
		"framing: must be octet_counting, non_transparent or auto",
		"upstream_framing: must be octet_counting or non_transparent",
		"tls_mode: must be none or implicit",
		"upstream_tls_mode: must be none or implicit",
		"hostname: must be keep, observed or annotate",
		`allow_facilities[0]: "not-a-facility" is not a facility`,
		`"mail" is in allow_facilities and deny_facilities`,
		`min_severity: "louder" is not a severity`,
		`allow_senders[0]: "not a cidr" is not a CIDR`,
		"deny_patterns[0]:",
		"redact[0].name: required",
		"redact[0].pattern:",
		`redact[2].name: "twice" is used twice`,
		"max_message_bytes: must be 480..1048576",
		"rate_limit: must not be negative",
		"max_senders: must be 1..1048576",
		"max_connections: must be at least 1",
		"queue: must be 1..1048576",
	)
	refuses(t, syslogConfig(`        upstream: collector
        tls_mode: implicit`, false),
		"tls_mode: implicit needs the listener's tls section")
	refuses(t, syslogConfig(`        upstream: collector
        redact: [{name: card}]`, false),
		"redact[0].pattern: required")
}

// The syslog warnings, which are all about the same thing: on a
// datagram transport with no credential, every record is as true as its
// sender says it is.
func TestTheSyslogWarningsAboutAnUnauthenticatedTransport(t *testing.T) {
	advises(t, syslogConfig(`        upstream: collector
        upstream_framing: non_transparent
        hostname: keep`, false),
		"non_transparent delimits on line endings",
		"hostname: keep takes the sender's word",
		"allow_senders: empty with udp on",
		"rate_limit: unset with udp on",
	)
	advises(t, syslogConfig(`        upstream: collector
        tls_mode: none
        udp: false
        allow_senders: ["10.0.0.0/8"]
        rate_limit: 100`, true),
		"tls_mode: none with a tls section")
}

// tftpConfig is one tftp relay.
func tftpConfig(section string) string {
	return `
version: 1
server:
  listeners:
    - name: boot
      address: "127.0.0.1:1069"
      kind: tftp
      tftp:
` + section + `
upstreams:
  - name: images
    endpoints: [{address: "10.0.0.9:69"}]
`
}

// Every enumerated setting and every numeric bound on a tftp relay.
func TestEveryBoundOnATFTPListener(t *testing.T) {
	refuses(t, tftpConfig(`        upstream: images
        mode: sideways
        learn: {enabled: true, interval: 1s, max_subjects: 2}
        operations: [sideways]
        modes: [smoke]
        allow_path_classes: [whatever, plain, control]
        directories: ["", "boot\r"]
        filenames: ["["]
        deny_filenames: [""]
        max_depth: -1
        max_filename_bytes: -1
        max_transfer_bytes: -1
        max_block_size: 2
        max_window_size: -1
        max_transfers: -1
        max_transfers_per_client: -1
        default_action: perhaps
        deny_response: shout
        transfer_timeout: 48h
        idle_timeout: 2h
        rate_limit: -1
        rate_burst: -1`),
		"mode: must be reverse or forward",
		"learn.file: required when learning is enabled",
		"learn.interval: must be between 10s and 24h",
		"learn.max_subjects: must be between 16 and 1000000",
		`operations[0]: "sideways" must be read or write`,
		`modes[0]: "smoke" must be octet, netascii or mail`,
		`allow_path_classes[0]: "whatever" must be absolute, backslash, drive`,
		"allow_path_classes[1]: plain is every ordinary path",
		`allow_path_classes[2]: "control" can never be allowed`,
		"directories[0]: empty; the server's own directory",
		"directories[1]:",
		"filenames[0]:",
		"deny_filenames[0]: empty",
		"max_depth: must be between 0 and 64",
		"max_filename_bytes: must be between 0 and",
		"max_transfer_bytes: must be between 0 and",
		"max_block_size: must be between",
		"max_window_size: must be between 0 and",
		"max_transfers: must be between 0 and 65536",
		"max_transfers_per_client: must be between 0 and 65536",
		"default_action: must be deny or allow",
		"deny_response: must be error or drop",
		"transfer_timeout: must be between 1s and 24h0m0s",
		"idle_timeout: must be between 1s and 1h0m0s",
		"rate_limit: must be between 0 and 1048576",
		"rate_burst: must be between 0 and 1048576",
	)
	refuses(t, tftpConfig(`        upstream: images
        learn: {enabled: true, file: relative/path.json}`),
		"learn.file: must be an absolute path")
	refuses(t, tftpConfig(`        upstream: images
        transfer_timeout: 10s
        idle_timeout: 30s`),
		"idle_timeout: longer than transfer_timeout")
}

func TestEveryMistakeInATFTPRule(t *testing.T) {
	refuses(t, tftpConfig(`        upstream: images
        rules:
          - name: "not a name!"
            action: perhaps
            operations: [sideways]
            modes: [smoke]
            allow_path_classes: [whatever]
            directories: [""]
            deny_directories: [""]
            filenames: ["["]
            deny_filenames: [""]
            max_transfer_bytes: -1
            max_block_size: 2
            max_window_size: -1
          - {name: twice, action: deny}
          - {name: twice, action: deny}`),
		`name: "not a name!" is not a valid name`,
		"action: must be allow, deny or observe",
		"rules[0].operations[0]:",
		"rules[0].modes[0]:",
		"rules[0].allow_path_classes[0]:",
		"rules[0].directories[0]: empty",
		"rules[0].deny_directories[0]: empty",
		"rules[0].filenames[0]:",
		"rules[0].deny_filenames[0]: empty",
		"rules[0].max_transfer_bytes: must be between 0 and",
		"rules[0].max_block_size: must be between",
		"rules[0].max_window_size: must be between 0 and",
		`name: duplicate "twice"`,
	)
}

// The TFTP warnings. This protocol has no credential of any kind, so
// each of these is a bound that is the only thing standing between a
// twenty-octet request and whatever it asked for.
func TestTheTFTPWarningsAboutAProtocolWithNoCredential(t *testing.T) {
	advises(t, tftpConfig(`        upstream: images
        learn: {enabled: true, file: /var/lib/xproxy/tftp.json}
        operations: [read, write]
        modes: [octet, mail]
        allow_path_classes: [traversal]
        default_action: allow
        deny_response: drop
        rate_burst: 10`),
		"learn is enabled without enforce",
		"allow_clients: empty",
		"operations: write allows a client to put files onto the server",
		"modes: mail is obsolete",
		"traversal allows a .. element",
		"directories: empty",
		"max_transfer_bytes: 0 leaves a transfer unbounded",
		"max_window_size: 0 leaves RFC 7440's window unbounded",
		"default_action allow with no rules",
		"deny_response: drop makes a refused client retransmit",
		"rate_burst: a burst without a rate_limit bounds nothing",
	)
}

// A relay told to speak TLS to its upstream and given no upstream_tls
// section at all, which is the ordinary way to ask for TLS with the
// system roots and nothing customised.
//
// Both of these crashed the validator: the syslog and ftp sections
// guarded the upstream TLS check on the mode rather than on the
// pointer, so "not none" with no section dereferenced nil. A
// configuration is operator input, and the answer to bad input is a
// sentence, never a stack trace -- the more so because a reload
// validates inside the running process.
func TestTLSToTheUpstreamWithNoSectionOfItsOwn(t *testing.T) {
	for _, yaml := range []string{
		syslogConfig(`        upstream: collector
        upstream_tls_mode: implicit
        udp: false
        allow_senders: ["10.0.0.0/8"]
        rate_limit: 100`, false),
		`
version: 1
server:
  listeners:
    - name: files
      address: "127.0.0.1:1021"
      kind: ftp
      ftp:
        upstream: files
        upstream_tls_mode: implicit
        allow_clients: ["10.0.0.0/8"]
upstreams:
  - name: files
    endpoints: [{address: "10.0.0.9:21"}]
`,
	} {
		if _, err := ParseWith([]byte(yaml), false); err != nil {
			t.Errorf("did not load: %v", err)
		}
	}
}

// mqttConfig is one mqtt listener and a broker behind it.
func mqttConfig(section string) string {
	return `
version: 1
server:
  listeners:
    - name: bus
      address: "127.0.0.1:1883"
      kind: mqtt
      mqtt:
` + section + `
upstreams:
  - name: broker
    endpoints: [{address: "10.0.0.9:1883"}]
`
}

// Every enumerated setting and every numeric bound on an mqtt listener.
func TestEveryBoundOnAnMQTTListener(t *testing.T) {
	refuses(t, mqttConfig(`        upstream: broker
        learn: {enabled: true, interval: 1s, max_subjects: 2}
        tls_mode: whenever
        upstream_tls_mode: whenever
        versions: ["3.1.1", "3.1.1", "9.9"]
        action: shout
        max_client_id: -1
        client_id_pattern: "("
        max_packet_size: 10
        max_topic_length: -1
        max_topic_levels: -1
        max_payload_bytes: -1
        max_qos: 7
        max_subscriptions: -1
        max_connections: -1
        connect_timeout: 20m
        idle_timeout: 48h
        keep_alive_max: 24h
        publish_allow: ["a/#/b"]
        publish_deny: [""]
        subscribe_allow: ["a/+x"]
        allow_clients: ["not a cidr"]`),
		"learn.file: required when learning is enabled",
		"learn.interval: must be between 10s and 24h",
		"learn.max_subjects: must be between 16 and 1000000",
		"tls_mode: must be implicit or none",
		"upstream_tls_mode: must be none or implicit",
		"versions[2]: must be 3.1.1 or 5.0",
		`versions[1]: "3.1.1" listed twice`,
		"action: must be disconnect or drop",
		"max_client_id: must be 1..65535",
		"client_id_pattern:",
		"max_packet_size: must be 1024..268435460",
		"max_topic_length: must be 1..65535",
		"max_topic_levels: must be 1..1000",
		"max_payload_bytes: must be between 0 and 268435455",
		"max_qos: must be 0, 1 or 2",
		"max_subscriptions: must be positive",
		"max_connections: must be positive",
		"connect_timeout: must be positive and at most 10m",
		"idle_timeout: must be positive and at most 24h",
		"keep_alive_max: must be 0 (any) or at most",
		"# is only allowed as the last level",
		"publish_deny[0]: \"\" is not a topic filter: empty",
		"a wildcard takes a whole level or none of it",
		`allow_clients[0]: "not a cidr" is not a CIDR`,
	)
	refuses(t, mqttConfig(`        upstream: broker
        versions: ["5.0"]
        tls_mode: implicit`),
		"tls_mode: implicit needs the listener's tls section")
	refuses(t, mqttConfig(`        upstream: broker
        versions: ["5.0"]
        upstream_tls_mode: none
        upstream_tls: {ca_file: /ca.pem}`),
		"upstream_tls: set with upstream_tls_mode: none")
}

// A topic rule is the MQTT policy. One that does not load as written is
// a bound on equipment that is not there.
func TestEveryMistakeInAnMQTTTopicRule(t *testing.T) {
	refuses(t, mqttConfig(`        upstream: broker
        versions: ["5.0"]
        topics:
          - filters: ["a/#/b"]
            max_payload_bytes: -1
            min_qos: 2
            max_qos: 1
          - {name: empty, filters: []}
          - {name: dup, filters: ["x/y"], max_qos: 7}
          - {name: dup, filters: ["x/z"], allow_retain: false}
          - {name: idle, filters: ["x/w"]}`),
		"topics[0].name: required",
		"topics[0].filters[0]:",
		"topics[0].max_payload_bytes: must be between 0 and 268435455",
		"topics[0]: min_qos 2 is above max_qos 1",
		"topics[1].filters: required",
		"topics[2].max_qos: must be 0, 1 or 2",
		`topics[3].name: duplicate "dup"`,
		"topics[4]: sets no bound",
	)
}

// Sparkplug B is where MQTT commands equipment, and the wildcard rule
// is where a subscription turns into a copy of the whole bus.
func TestTheMQTTSparkplugAndWildcardChecks(t *testing.T) {
	refuses(t, mqttConfig(`        upstream: broker
        versions: ["5.0"]
        allow_wildcard_subscribe: false
        subscribe_allow: ["plant/+/temperature"]
        sparkplug:
          enabled: true
          allow_message_types: [NOPE]
          command_clients: ["not a cidr"]
          max_nodes: -1`),
		"subscribe_allow[0]:",
		"allow_wildcard_subscribe: false refuses outright",
		"allow_message_types[0]: \"NOPE\" is not a Sparkplug B message type",
		"command_clients[0]: \"not a cidr\" is not a network in CIDR form",
		"sparkplug.max_nodes: must be between 0 and 1048576",
	)
	advises(t, mqttConfig(`        upstream: broker
        versions: ["3.1.1"]
        tls_mode: none
        learn: {enabled: true, file: /var/lib/xproxy/mqtt.json}
        sparkplug: {enabled: true}`),
		"tls_mode: none carries every credential",
		"learn is enabled without enforce",
		"no topic policy",
		"sparkplug.command_clients is empty",
		"sparkplug is enabled and sets nothing",
	)
}

// ftpConfig is one ftp listener and a server behind it.
func ftpConfig(section string) string {
	return `
version: 1
server:
  listeners:
    - name: files
      address: "127.0.0.1:1021"
      kind: ftp
      ftp:
` + section + `
upstreams:
  - name: archive
    endpoints: [{address: "10.0.0.9:21"}]
`
}

// Every enumerated setting and every numeric bound on an ftp listener.
func TestEveryBoundOnAnFTPListener(t *testing.T) {
	refuses(t, ftpConfig(`        upstream: archive
        tls_mode: whenever
        upstream_tls_mode: whenever
        commands: [STOR, STOR, DANCE]
        allow_paths: ["", "/home/{name}"]
        deny_paths: ["/etc/{whoever}"]
        allow_extensions: ["", "tar.gz"]
        deny_extensions: ["*.exe"]
        max_file_bytes: -1
        data_address: "not an address"
        data_ports: "70000-1"
        data_timeout: -1s
        max_command_line: 10
        max_errors: -1
        max_connections: -1
        allow_clients: ["not a cidr"]`),
		"tls_mode: must be none, starttls or implicit",
		"upstream_tls_mode: must be none, starttls or implicit",
		`commands[2]: "DANCE" is not a command this proxy can read the effect of`,
		`commands[1]: "STOR" listed twice`,
		"commands: USER is required",
		"commands: QUIT is required",
		"allow_paths[0]: must be a path",
		"allow_paths[1]: {user} is the only substitution here",
		"deny_paths[0]: {user} is the only substitution here",
		"allow_extensions[0]:",
		"allow_extensions[1]:",
		"deny_extensions[0]:",
		"max_file_bytes: must not be negative",
		`data_address: "not an address" is not an address`,
		"data_ports: must be 1..65535 with low no higher than high",
		"data_timeout: must be positive",
		"max_command_line: must be 512..1048576",
		"max_errors: must be at least 1",
		"max_connections: must be at least 1",
		`allow_clients[0]: "not a cidr" is not a CIDR`,
	)
	refuses(t, ftpConfig(`        upstream: archive
        data_ports: "nonsense"`),
		`data_ports: must be written "low-high"`)
	refuses(t, ftpConfig(`        upstream: archive
        tls_mode: starttls`),
		`tls_mode: "starttls" needs the listener's tls section`)
}

// The FTP warnings, which are the protocol's two old hazards: a data
// connection the client names, and a password with nothing over it.
func TestTheFTPWarningsAboutDataConnectionsAndPasswords(t *testing.T) {
	advises(t, ftpConfig(`        upstream: archive
        tls_mode: none
        allow_active: true
        data_ports: "50000-50004"
        mfa: {file: /var/lib/xproxy/mfa.json}`),
		"allow_active: PORT and EPRT ask the proxy to connect to an address the client names",
		"ports for concurrent transfers",
		"the code crosses the network in clear beside the password",
	)
}
