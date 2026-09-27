package redis

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/deception"
	"github.com/rom/xproxy/internal/proxy"
	wire "github.com/rom/xproxy/internal/respwire"
)

// A server that is not there.
//
// See internal/deception for why this exists at all. What is specific to Redis
// is that the attack on it is a script rather than a person, and the script is
// always the same one. An exposed instance with no password is found by a
// scanner, and what arrives next is:
//
//	INFO                            what is this, and what version
//	CONFIG GET dir                  where does it write
//	CONFIG GET dbfilename           what does it write
//	CONFIG SET dir /var/spool/cron  point that somewhere that executes
//	CONFIG SET dbfilename root
//	SET x "\n* * * * * curl ...\n"  the payload, as a value
//	SAVE                            write the file
//
// A refusal stops that at the first step, and tells its author to try the next
// address. Answering it collects the whole chain -- the directory, the file
// name, and the payload -- in the security log, which is the difference between
// knowing that somebody scanned the estate and knowing what they intended to
// run on it.
//
// So the tripwires here are not a list an operator has to think of. The
// remote-code-execution chain and its neighbours are built in, because nothing
// legitimate sends CONFIG SET or MODULE LOAD to a fabricated cache.
//
// Two things the fabrication will not pretend. It does not pretend to run Lua
// (EVAL) or to load a module: both answer the error the real server answers
// when it cannot, which is convincing and is not a claim that code ran. And it
// holds no state -- a value is a function of the key name and the clock -- so a
// visitor that wrote a payload and read it back gets what it wrote for the
// length of one reply and nothing is kept.

// cacheProfile is a fabricated server's identity and shape.
type cacheProfile struct {
	version string
	// prefix is how this sort of instance names its keys, which is the part of
	// the fabrication a visitor reads most closely.
	prefix string
	// kind names the value shape, which is what makes a session store's values
	// look unlike a queue's.
	kind string
	keys int
	// memory is used_memory in mebibytes, roughly: the gauge drifts around it.
	memory int
}

// The built-in profiles. All three are deliberately ordinary, and the versions
// are ones in wide use rather than the newest: a decoy claiming a version
// released last week is a decoy nobody believes on an estate that patches
// quarterly.
var cacheProfiles = map[string]cacheProfile{
	"generic-cache": {version: "7.2.4", prefix: "cache:", kind: "json", keys: 64, memory: 48},
	"session-store": {version: "7.0.15", prefix: "session:", kind: "session", keys: 256, memory: 180},
	"queue":         {version: "6.2.14", prefix: "queue:", kind: "job", keys: 32, memory: 24},
}

// DefaultProfile is the profile a section that names none gets.
const DefaultProfile = "generic-cache"

// Profiles are the shapes a fabricated server can have, for validation.
func Profiles() []string {
	out := make([]string, 0, len(cacheProfiles))
	for name := range cacheProfiles {
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}

// The tripwires that need no configuring: the remote-code-execution chain and
// its neighbours. A subcommand is named where the subcommand is what matters --
// CONFIG GET is reconnaissance and CONFIG SET is the exploit -- and the bare
// name where the whole command is.
var builtInTripwires = []string{
	"CONFIG SET", "MODULE", "SLAVEOF", "REPLICAOF", "DEBUG",
	"EVAL", "EVALSHA", "FUNCTION", "SCRIPT", "MIGRATE", "SHUTDOWN",
	"SAVE", "BGSAVE", "BGREWRITEAOF", "FLUSHALL", "FLUSHDB", "ACL",
}

// The synthetic addresses the gauges live at. deception.Values answers by
// address, so each gauge is one, and the bands below give each its own range.
const (
	addrClients   = 1
	addrBlocked   = 2
	addrMemoryPct = 3
	addrHitRate   = 4
	addrExpired   = 5
)

// decoy is the fabricated server.
type decoy struct {
	// whole says the listener is a honeypot: every command is answered here
	// and there is no server behind it.
	whole   bool
	profile string
	version string
	prefix  string
	kind    string
	memory  int
	// keys is the fabricated keyspace, sorted, so that KEYS and SCAN list it
	// in an order that does not change between two reads.
	keys []string
	// trip is the command names and "NAME SUB" pairs that raise the event.
	trip        map[string]bool
	requireAuth bool
	started     time.Time
	period      time.Duration
	// runID is INFO's run_id: forty hex characters, stable for the life of the
	// listener, because a run identifier that changed between two INFOs would
	// be a server that had restarted in between.
	runID  string
	values *deception.Values
	policy *deception.Policy
	now    func() time.Time
}

// newDecoy builds the fabrication, or nil where the section is absent or off.
func newDecoy(c *config.RedisDeception, name string) (*decoy, error) {
	if c == nil || (c.Enabled != nil && !*c.Enabled) {
		return nil, nil
	}
	p, ok := cacheProfiles[c.Profile]
	if !ok {
		if c.Profile != "" {
			return nil, fmt.Errorf("deception.profile: %q is not a profile", c.Profile)
		}
		p = cacheProfiles[DefaultProfile]
	}
	d := &decoy{
		whole:       c.Mode == "decoy",
		profile:     c.Profile,
		version:     orStr(c.Version, p.version),
		prefix:      p.prefix,
		kind:        p.kind,
		memory:      p.memory,
		requireAuth: c.RequireAuth,
		started:     time.Now(),
		trip:        map[string]bool{},
		now:         time.Now,
	}
	if d.profile == "" {
		d.profile = DefaultProfile
	}
	seed := c.Seed
	if seed == 0 {
		seed = deception.SeedFor(name)
	}
	d.period = c.Period.D()
	if d.period <= 0 {
		d.period = deception.DefaultPeriod
	}
	// One band per gauge, because each has its own range and a client count
	// that drifted across a memory percentage's range would be nonsense.
	d.values = deception.NewValues(seed, d.period, []deception.Band{
		{Lo: addrClients, Hi: addrClients, Shape: deception.ShapeAnalogue, Min: 4, Max: 64},
		{Lo: addrBlocked, Hi: addrBlocked, Shape: deception.ShapeAnalogue, Min: 0, Max: 2},
		{Lo: addrMemoryPct, Hi: addrMemoryPct, Shape: deception.ShapeAnalogue, Min: 80, Max: 120},
		{Lo: addrHitRate, Hi: addrHitRate, Shape: deception.ShapeAnalogue, Min: 82, Max: 99},
		{Lo: addrExpired, Hi: addrExpired, Shape: deception.ShapeCounter, Rate: 17},
	})
	d.runID = hexOf(seed)
	count := c.KeyCount
	if count == 0 {
		count = p.keys
	}
	d.keys = buildKeys(d.prefix, count, seed, c.Keys)
	for _, t := range builtInTripwires {
		d.trip[t] = true
	}
	for i, t := range c.Tripwire {
		norm := normaliseCommand(t)
		if norm == "" {
			return nil, fmt.Errorf("deception.tripwire[%d]: %q is not a command name", i, t)
		}
		d.trip[norm] = true
	}
	d.policy = deception.NewPolicy(nil, c.MaxClients)
	if len(c.Clients) > 0 {
		prefixes, err := decoyPrefixes(c.Clients)
		if err != nil {
			return nil, err
		}
		d.policy = deception.NewPolicy(prefixes, c.MaxClients)
	}
	return d, nil
}

func decoyPrefixes(in []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(in))
	for _, s := range in {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("deception.clients: %q: %w", s, err)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// orStr is the first of two strings that is not empty. The package's own `or`
// is the same idea for integers.
func orStr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// normaliseCommand reads a configured tripwire: a command name, or a name and a
// subcommand. It is upper-cased because Redis matches a command without regard
// to case, and a tripwire that held one spelling would miss the other.
func normaliseCommand(s string) string {
	fields := strings.Fields(strings.ToUpper(s))
	if len(fields) == 0 || len(fields) > 2 {
		return ""
	}
	for _, f := range fields {
		for i := 0; i < len(f); i++ {
			if !nameChar(f[i]) {
				return ""
			}
		}
	}
	return strings.Join(fields, " ")
}

// buildKeys is the fabricated keyspace: the configured names, plus generated
// ones from the profile's pattern, sorted and deduplicated.
//
// It is sorted because KEYS and SCAN answer from it in order, and a keyspace
// that came back in a different order on a second read would be a server whose
// dictionary had been rehashed -- which happens, but not between two commands
// on an idle instance.
func buildKeys(prefix string, count int, seed uint64, extra []string) []string {
	if count < 0 {
		count = 0
	}
	if count > 4096 {
		count = 4096
	}
	out := make([]string, 0, count+len(extra))
	out = append(out, extra...)
	for i := 0; i < count; i++ {
		// The name is derived from the seed, so the same listener holds the same
		// keys after a restart: a visitor that came back to a key it had read
		// and found it gone would have found the decoy.
		out = append(out, prefix+hexOf(seed + uint64(i)*0x9E3779B97F4A7C15)[:12]) //nolint:gosec // an index, bounded above
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// hexOf is forty hexadecimal characters derived from a seed, which is the shape
// of a Redis run identifier.
func hexOf(seed uint64) string {
	var b strings.Builder
	h := seed | 1
	for b.Len() < 40 {
		h ^= h << 13
		h ^= h >> 7
		h ^= h << 17
		b.WriteString(strconv.FormatUint(h&0xFFFFFFFF, 16))
	}
	return b.String()[:40]
}

// admits says whether this client gets the fabrication.
func (d *decoy) admits(ip netip.Addr) bool { return d != nil && d.policy.Admits(ip) }

// tripped says whether a command is one nothing legitimate sends.
func (d *decoy) tripped(c *wire.Command) bool {
	if d == nil || c == nil {
		return false
	}
	if c.Sub != "" && d.trip[c.Name+" "+c.Sub] {
		return true
	}
	return d.trip[c.Name]
}

func modeName(whole bool) string {
	if whole {
		return "decoy"
	}
	return "answer"
}

// DecoyStatus is what this listener's decoy has seen, for the status view.
func (t *server) DecoyStatus() (proxy.DecoyStatus, bool) {
	d := t.decoy
	if d == nil {
		return proxy.DecoyStatus{}, false
	}
	st := proxy.DecoyStatus{
		Listener: t.name, Kind: "redis", Mode: modeName(d.whole),
		Profile: d.profile, Served: d.policy.Served(),
		Tripped: d.policy.Tripped(), Anyone: d.policy.Anyone(),
	}
	for _, c := range d.policy.Clients(32) {
		st.Visitors = append(st.Visitors, proxy.DecoyVisitor{
			ClientIP: c.Addr.String(), FirstSeen: c.FirstSeen, LastSeen: c.LastSeen,
			Frames: c.Frames, Tripped: c.Tripped,
		})
	}
	return st, true
}

// The fabricated replies.
//
// Each is what the real server sends for that command, because a reply of the
// wrong *shape* is what a client library reports and what a scanner fingerprints
// on. An unknown command answers the real error text for the same reason: a
// scanner that sends a nonsense command and gets something other than Redis's
// own wording has found the decoy.

// answer builds the reply to one command, or reports that the fabrication has
// none -- in which case nothing is sent and the caller decides.
func (d *decoy) answer(c *wire.Command, authed bool) ([]byte, bool) {
	if d == nil || c == nil {
		return nil, false
	}
	if d.requireAuth && !authed && c.Name != "AUTH" && c.Name != "HELLO" && c.Name != "QUIT" {
		// The real wording, because a client library switches on the first word
		// and a scanner reads the rest.
		return wire.Error("NOAUTH", "Authentication required."), true
	}
	switch c.Name {
	case "PING":
		if len(c.Args) == 1 {
			return wire.Bulk(c.Args[0]), true
		}
		return wire.Simple("PONG"), true
	case "ECHO":
		if len(c.Args) != 1 {
			return wrongArgs(c), true
		}
		return wire.Bulk(c.Args[0]), true
	case "QUIT":
		return wire.Simple("OK"), true
	case "AUTH":
		return d.auth(c), true
	case "HELLO":
		return d.hello(c)
	case "INFO":
		return wire.BulkString(d.info(sectionOf(c))), true
	case "COMMAND":
		return d.command(c), true
	case "CONFIG":
		return d.config(c), true
	case "SELECT":
		return d.selectDB(c), true
	case "DBSIZE":
		return wire.Int(int64(len(d.keys))), true
	case "KEYS":
		if len(c.Args) != 1 {
			return wrongArgs(c), true
		}
		return wire.Strings(d.matching(string(c.Args[0]), len(d.keys))...), true
	case "SCAN":
		return d.scan(c), true
	case "TYPE":
		if len(c.Args) != 1 {
			return wrongArgs(c), true
		}
		if !d.holds(string(c.Args[0])) {
			return wire.Simple("none"), true
		}
		return wire.Simple(d.typeOf(string(c.Args[0]))), true
	case "GET":
		if len(c.Args) != 1 {
			return wrongArgs(c), true
		}
		key := string(c.Args[0])
		if !d.holds(key) || d.typeOf(key) != "string" {
			return wire.NilBulk(), true
		}
		return wire.BulkString(d.value(key)), true
	case "EXISTS":
		n := 0
		for _, a := range c.Args {
			if d.holds(string(a)) {
				n++
			}
		}
		return wire.Int(int64(n)), true
	case "TTL", "PTTL":
		if len(c.Args) != 1 {
			return wrongArgs(c), true
		}
		if !d.holds(string(c.Args[0])) {
			return wire.Int(-2), true
		}
		// -1 is "no expiry set", which is what a key in a cache that is managed
		// by eviction rather than by TTL reports.
		return wire.Int(-1), true
	case "SET", "SETEX", "PSETEX", "MSET", "GETSET", "RENAME", "EXPIRE", "PERSIST":
		// Accepted and not kept. This is where a payload arrives -- the cron
		// line, the authorized_keys blob -- and the reply is what keeps the
		// visitor going on to SAVE, which is the command that says what they
		// meant to do with it.
		if c.Name == "EXPIRE" || c.Name == "PERSIST" {
			return wire.Int(1), true
		}
		return wire.Simple("OK"), true
	case "SETNX", "DEL", "UNLINK", "APPEND":
		return wire.Int(1), true
	case "INCR", "DECR", "INCRBY", "DECRBY":
		return wire.Int(int64(d.gauge(addrClients))), true
	case "LLEN", "SCARD", "HLEN", "ZCARD", "XLEN":
		return wire.Int(int64(d.gauge(addrBlocked))), true
	case "LPUSH", "RPUSH", "SADD", "HSET", "ZADD", "XADD":
		return wire.Int(1), true
	case "LRANGE", "SMEMBERS", "HKEYS", "HVALS", "ZRANGE":
		if len(c.Args) == 0 || !d.holds(string(c.Args[0])) {
			return wire.Array(), true
		}
		return wire.Strings(d.members(string(c.Args[0]))...), true
	case "LPOP", "RPOP", "SPOP":
		if len(c.Args) == 0 || !d.holds(string(c.Args[0])) {
			return wire.NilBulk(), true
		}
		return wire.BulkString(d.value(string(c.Args[0]))), true
	case "CLIENT":
		return d.client(c), true
	case "TIME":
		now := d.now()
		return wire.Strings(strconv.FormatInt(now.Unix(), 10),
			strconv.Itoa(now.Nanosecond()/1000)), true
	case "LASTSAVE":
		return wire.Int(d.started.Unix()), true
	case "SLOWLOG":
		if c.Sub == "LEN" {
			return wire.Int(0), true
		}
		return wire.Array(), true
	case "MEMORY":
		if c.Sub == "USAGE" {
			return wire.Int(int64(64 + d.gauge(addrClients))), true
		}
		return wire.BulkString("Sam, I detected a few issues in this Redis instance memory implants:\n\n * " +
			"High allocator fragmentation: This instance has an allocator external fragmentation greater " +
			"than 1.1.\n\nI'm here just for mental support. Good luck!"), true
	case "CLUSTER":
		return wire.BulkString("cluster_enabled:0\r\ncluster_state:ok\r\ncluster_slots_assigned:0\r\n"), true
	case "ACL":
		if c.Sub == "WHOAMI" {
			return wire.BulkString("default"), true
		}
		return wire.Strings("user default on nopass sanitize-payload ~* &* +@all"), true
	case "SAVE":
		// The reply that tells the visitor their file was written. Nothing was.
		return wire.Simple("OK"), true
	case "BGSAVE":
		return wire.Simple("Background saving started"), true
	case "BGREWRITEAOF":
		return wire.Simple("Background append only file rewriting started"), true
	case "FLUSHALL", "FLUSHDB":
		// The keyspace is a function rather than a table, so there is nothing to
		// delete and nothing to restore. The reply is the real one.
		return wire.Simple("OK"), true
	case "SLAVEOF", "REPLICAOF":
		// The address the visitor wants this server to replicate from is the
		// intel: it is a host they control. recordDeception logs the arguments.
		return wire.Simple("OK"), true
	case "MODULE":
		if c.Sub == "LIST" {
			return wire.Array(), true
		}
		// Not pretended. A fabrication that answered +OK to MODULE LOAD would
		// be claiming that a shared object had been loaded and code was
		// running, and nothing it said afterwards would be consistent with
		// that. The real failure is convincing and is not a lie about code.
		return wire.Error("ERR", "Error loading the extension. Please check the server logs."), true
	case "EVAL", "EVALSHA", "FCALL", "FCALL_RO":
		// The same: there is no Lua interpreter here, and a reply that implied
		// one would have to keep implying it.
		return wire.Error("NOSCRIPT", "No matching script. Please use EVAL."), true
	case "FUNCTION":
		if c.Sub == "LIST" || c.Sub == "STATS" {
			return wire.Array(), true
		}
		return wire.Error("ERR", "Function not found"), true
	case "SCRIPT":
		if c.Sub == "LOAD" {
			// A SHA is a plausible answer and costs nothing: the script was
			// not kept, and EVALSHA answers NOSCRIPT, which is exactly what a
			// server that had evicted it would say.
			return wire.BulkString(hexOf(uint64(len(c.Args)) + 0x5343)), true
		}
		return wire.Simple("OK"), true
	case "DEBUG":
		return wire.Error("ERR", "DEBUG command not allowed. If the enable-debug-command option is..."), true
	case "MIGRATE":
		return wire.Simple("NOKEY"), true
	case "SHUTDOWN":
		// No reply: the real server closes the connection, and the caller does
		// the same. A reply here would be a server that had not shut down.
		return nil, true
	case "SUBSCRIBE", "PSUBSCRIBE", "MONITOR", "WAIT", "BLPOP", "BRPOP":
		// The commands that would leave the connection waiting. A fabrication
		// has nothing to publish and nothing to block on, so it says so rather
		// than holding a connection open for ever.
		return wire.Error("ERR", "unsupported on this instance"), true
	}
	return unknown(c), true
}

// unknown is Redis's own reply to a command it does not have. The wording is
// exact, including the argument echo, because a scanner that sends a nonsense
// command and reads something else has found the decoy.
func unknown(c *wire.Command) []byte {
	var b strings.Builder
	b.WriteString("unknown command '")
	b.WriteString(wire.Clip(c.Name))
	b.WriteString("', with args beginning with: ")
	for i, a := range c.Args {
		if i >= 3 {
			break
		}
		b.WriteString("'")
		b.WriteString(wire.Clip(string(a)))
		b.WriteString("', ")
	}
	return wire.Error("ERR", b.String())
}

func wrongArgs(c *wire.Command) []byte {
	return wire.Error("ERR", "wrong number of arguments for '"+strings.ToLower(c.Name)+"' command")
}

// auth accepts whatever it is given, because a fabrication that refused would
// be a credential oracle: it would say which passwords are wrong, which is the
// one thing a password list needs.
func (d *decoy) auth(c *wire.Command) []byte {
	if len(c.Args) == 0 {
		return wrongArgs(c)
	}
	if !d.requireAuth {
		// The real reply when no password is set, which is the state a honeypot
		// wants to be in: it is what the scanning is looking for.
		return wire.Error("ERR", "Client sent AUTH, but no password is set. Did you mean AUTH <username> <password>?")
	}
	return wire.Simple("OK")
}

// hello answers the RESP3 handshake. A client that asked for version 3 and got
// a version 2 reply reports a protocol error, so this is the one exchange where
// the reply's *type* has to follow what was asked.
func (d *decoy) hello(c *wire.Command) ([]byte, bool) {
	ver := 2
	if len(c.Args) > 0 {
		v, err := strconv.Atoi(string(c.Args[0]))
		if err != nil {
			return wire.Error("NOPROTO", "unsupported protocol version"), true
		}
		ver = v
	}
	if ver != 2 && ver != 3 {
		return wire.Error("NOPROTO", "unsupported protocol version"), true
	}
	fields := [][]byte{
		wire.BulkString("server"), wire.BulkString("redis"),
		wire.BulkString("version"), wire.BulkString(d.version),
		wire.BulkString("proto"), wire.Int(int64(ver)),
		wire.BulkString("id"), wire.Int(int64(d.gauge(addrClients))),
		wire.BulkString("mode"), wire.BulkString("standalone"),
		wire.BulkString("role"), wire.BulkString("master"),
		wire.BulkString("modules"), wire.Array(),
	}
	if ver == 3 {
		return wire.Map(fields...), true
	}
	return wire.Array(fields...), true
}

// command answers the handshake several client libraries send before anything
// else. An empty table is honest and is what a server with no commands
// introspection compiled in reports; a library treats it as "ask nothing".
func (d *decoy) command(c *wire.Command) []byte {
	switch c.Sub {
	case "COUNT":
		return wire.Int(240)
	case "DOCS":
		return wire.Map()
	case "GETKEYS":
		return wire.Error("ERR", "The command has no key arguments")
	}
	return wire.Array()
}

// config answers the reconnaissance half of the exploit chain, and accepts the
// exploit half.
//
// CONFIG GET dir and dbfilename are the two questions that come before
// everything else, because the attack needs to know where the server writes and
// what it writes. Answering them plausibly -- a real data directory, a real
// dump file name -- is what makes the CONFIG SET that follows arrive, and the
// CONFIG SET is the message worth having.
func (d *decoy) config(c *wire.Command) []byte {
	switch c.Sub {
	case "GET":
		if len(c.Args) < 2 {
			return wrongArgs(c)
		}
		var out []string
		for _, arg := range c.Args[1:] {
			pattern := string(arg)
			for _, kv := range d.configPairs() {
				if match(pattern, kv[0]) {
					out = append(out, kv[0], kv[1])
				}
			}
		}
		return wire.Strings(out...)
	case "SET":
		// Accepted, and recorded. The pair is the whole point of this feature on
		// this protocol: dir plus dbfilename is a path of the visitor's
		// choosing, and knowing which one they chose is knowing what they
		// intended to run.
		return wire.Simple("OK")
	case "RESETSTAT", "REWRITE":
		return wire.Simple("OK")
	}
	return wire.Error("ERR", "Unknown CONFIG subcommand or wrong number of arguments for '"+
		wire.Clip(c.Sub)+"'")
}

// configPairs is the configuration a fabricated server reports. The values are
// the ones a default package install has, because that is what an instance
// nobody has hardened looks like -- which is the instance being impersonated.
func (d *decoy) configPairs() [][2]string {
	return [][2]string{
		{"dir", "/var/lib/redis"},
		{"dbfilename", "dump.rdb"},
		{"appendonly", "no"},
		{"appendfilename", "appendonly.aof"},
		{"maxmemory", "0"},
		{"maxmemory-policy", "noeviction"},
		{"save", "3600 1 300 100 60 10000"},
		{"requirepass", ""},
		{"protected-mode", "no"},
		{"bind", "0.0.0.0"},
		{"port", "6379"},
		{"timeout", "0"},
		{"databases", "16"},
		{"logfile", "/var/log/redis/redis-server.log"},
		{"pidfile", "/var/run/redis/redis-server.pid"},
	}
}

func (d *decoy) selectDB(c *wire.Command) []byte {
	if len(c.Args) != 1 {
		return wrongArgs(c)
	}
	n, err := strconv.Atoi(string(c.Args[0]))
	if err != nil {
		return wire.Error("ERR", "value is not an integer or out of range")
	}
	if n < 0 || n > 15 {
		return wire.Error("ERR", "DB index is out of range")
	}
	return wire.Simple("OK")
}

func (d *decoy) client(c *wire.Command) []byte {
	switch c.Sub {
	case "SETNAME", "SETINFO", "NO-EVICT", "NO-TOUCH", "REPLY":
		return wire.Simple("OK")
	case "GETNAME":
		return wire.NilBulk()
	case "ID":
		return wire.Int(int64(d.gauge(addrClients)))
	case "LIST":
		return wire.BulkString(fmt.Sprintf(
			"id=%d addr=127.0.0.1:6379 laddr=127.0.0.1:6379 fd=8 name= age=%d idle=0 flags=N db=0 "+
				"sub=0 psub=0 ssub=0 multi=-1 watch=0 qbuf=26 qbuf-free=20448 argv-mem=10 "+
				"multi-mem=0 tot-net-in=0 tot-net-out=0 rbs=1024 rbp=0 obl=0 oll=0 omem=0 "+
				"tot-mem=0 events=r cmd=client|list user=default redir=-1 resp=2\n",
			d.gauge(addrClients), int(d.now().Sub(d.started)/time.Second)))
	}
	return wire.Error("ERR", "Unknown CLIENT subcommand or wrong number of arguments")
}

// scan answers a cursor walk of the keyspace, which is what a client that has
// been told KEYS is dangerous uses instead.
//
// The cursor is an index into the sorted list rather than a hash-table position,
// which is a simplification a client cannot see: the contract is that a full
// walk returns every key present throughout, and an index walk of a fixed list
// satisfies that exactly.
func (d *decoy) scan(c *wire.Command) []byte {
	if len(c.Args) == 0 {
		return wrongArgs(c)
	}
	at, err := strconv.Atoi(string(c.Args[0]))
	if err != nil || at < 0 {
		return wire.Error("ERR", "invalid cursor")
	}
	pattern, count := "*", 10
	for i := 1; i+1 < len(c.Args); i += 2 {
		switch strings.ToUpper(string(c.Args[i])) {
		case "MATCH":
			pattern = string(c.Args[i+1])
		case "COUNT":
			if n, err := strconv.Atoi(string(c.Args[i+1])); err == nil && n > 0 {
				// Bounded: COUNT is a number the client chooses, and a
				// fabrication that honoured an enormous one would be building a
				// reply of the client's chosen size. Redis itself treats COUNT
				// as a hint, so clamping it is within the contract.
				count = min(n, 1000)
			}
		}
	}
	if at >= len(d.keys) {
		return wire.Array(wire.BulkString("0"), wire.Array())
	}
	end := min(at+count, len(d.keys))
	next := end
	if next >= len(d.keys) {
		next = 0
	}
	var out []string
	for _, k := range d.keys[at:end] {
		if match(pattern, k) {
			out = append(out, k)
		}
	}
	return wire.Array(wire.BulkString(strconv.Itoa(next)), wire.Strings(out...))
}

// matching is the keys a glob covers, bounded.
func (d *decoy) matching(pattern string, limit int) []string {
	if limit <= 0 || limit > len(d.keys) {
		limit = len(d.keys)
	}
	out := make([]string, 0, limit)
	for _, k := range d.keys {
		if len(out) >= limit {
			break
		}
		if match(pattern, k) {
			out = append(out, k)
		}
	}
	return out
}

// match is a Redis glob.
//
// It is written out rather than handed to path.Match, which is the obvious
// shortcut and the wrong one: path.Match will not let a wildcard cross a slash,
// and a Redis key is an opaque string in which a slash means nothing. A key
// named "cache:img/logo.png" is not matched by "cache:*" under path semantics
// and is under Redis's, so the shortcut would hide a configured key from the KEYS
// that is supposed to list it.
//
// The metacharacters are Redis's own: * for any run, ? for one octet, [...] for
// a set (with ^ to negate and - for a range), and \ to escape the next octet.
// An empty pattern matches nothing, which is what the real server does: the
// pattern has to cover the whole key, and an empty one covers nothing -- and a
// trailing star matching the rest of the key falls out of that same rule rather
// than needing a case of its own.
//
// The recursion is on the pattern rather than on the string, so its depth is
// bounded by the pattern's length.
func match(pattern, s string) bool {
	for len(pattern) > 0 {
		switch pattern[0] {
		case '*':
			// A run of stars is collapsed to one, and this is not an
			// optimisation that can be left out: the pattern comes from the
			// client, each star costs a scan of what is left of the key, and
			// two stars in a row cost that scan twice over. "KEYS" with thirty
			// stars in its pattern would be exponential in the length of every
			// key it is compared against -- one small command, and the single
			// thread that serves everybody is gone. Collapsing makes the extra
			// stars free.
			for len(pattern) > 1 && pattern[1] == '*' {
				pattern = pattern[1:]
			}
			for i := 0; i <= len(s); i++ {
				if match(pattern[1:], s[i:]) {
					return true
				}
			}
			return false
		case '?':
			if len(s) == 0 {
				return false
			}
			pattern, s = pattern[1:], s[1:]
		case '[':
			if len(s) == 0 {
				return false
			}
			rest, ok := matchClass(pattern, s[0])
			if !ok {
				return false
			}
			pattern, s = rest, s[1:]
		case '\\':
			// An escape at the very end of a pattern is a literal backslash,
			// which is what Redis does rather than refusing the pattern.
			if len(pattern) == 1 {
				if len(s) == 0 || s[0] != '\\' {
					return false
				}
				return len(s) == 1
			}
			if len(s) == 0 || s[0] != pattern[1] {
				return false
			}
			pattern, s = pattern[2:], s[1:]
		default:
			if len(s) == 0 || s[0] != pattern[0] {
				return false
			}
			pattern, s = pattern[1:], s[1:]
		}
	}
	return len(s) == 0
}

// matchClass reads a [...] class at the front of a pattern against one octet,
// and returns what is left of the pattern.
//
// An unterminated class is a literal "[", which is what Redis does: a pattern is
// never invalid on this protocol, so there is no error to return and the
// alternative -- matching nothing -- would silently hide keys.
func matchClass(pattern string, c byte) (string, bool) {
	at := 1
	negate := false
	if at < len(pattern) && pattern[at] == '^' {
		negate = true
		at++
	}
	found := false
	closed := false
	for at < len(pattern) {
		if pattern[at] == ']' {
			closed = true
			at++
			break
		}
		lo := pattern[at]
		if lo == '\\' && at+1 < len(pattern) {
			at++
			lo = pattern[at]
		}
		at++
		hi := lo
		// A range, but only where the dash is not the last octet before the
		// closing bracket: "[a-]" has a literal dash, which is Redis's reading.
		if at+1 < len(pattern) && pattern[at] == '-' && pattern[at+1] != ']' {
			at++
			hi = pattern[at]
			if hi == '\\' && at+1 < len(pattern) {
				at++
				hi = pattern[at]
			}
			at++
		}
		if lo > hi {
			lo, hi = hi, lo
		}
		if c >= lo && c <= hi {
			found = true
		}
	}
	if !closed {
		// A literal "[", compared against this octet.
		return pattern[1:], c == '['
	}
	return pattern[at:], found != negate
}

// holds says whether the fabrication has a key. A configured or generated name
// is held; anything else is not, because a server that answered for every key
// anybody named would be a server with an infinite keyspace.
func (d *decoy) holds(key string) bool {
	_, found := slices.BinarySearch(d.keys, key)
	return found
}

// typeOf is the Redis type of a fabricated key, derived from its name so that
// TYPE and the command that follows it agree.
func (d *decoy) typeOf(key string) string {
	if d.kind == "job" && strings.HasSuffix(key[:min(len(key), len(d.prefix))], ":") {
		// A queue's keys are lists, which is what makes LLEN and LRANGE the
		// commands that work on them.
		return "list"
	}
	return "string"
}

// members is the elements of a fabricated list, for LRANGE and its neighbours.
func (d *decoy) members(key string) []string {
	n := 1 + int(d.values.Register(0, addrBlocked))%4
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, d.value(key+":"+strconv.Itoa(i)))
	}
	return out
}

// value is what a fabricated key holds.
//
// Nothing is stored: the value is a function of the key name and the period, so
// a visitor reading the same key twice inside one period sees the same thing and
// the fabrication remembers nothing about who read what.
func (d *decoy) value(key string) string {
	h := hexOf(deception.SeedFor(key))
	switch d.kind {
	case "session":
		return fmt.Sprintf(`{"uid":%d,"csrf":"%s","exp":%d}`,
			1000+int(d.values.Register(0, addrClients)), h[:24], d.now().Add(time.Hour).Unix())
	case "job":
		return fmt.Sprintf(`{"id":"%s","queue":"default","attempts":1}`, h[:16])
	default:
		return fmt.Sprintf(`{"v":1,"etag":"%s"}`, h[:16])
	}
}

// gauge is one of the fabricated numbers, bounded by its band.
func (d *decoy) gauge(addr int) int { return int(d.values.Register(0, addr)) }

// info is the reply every scanner reads first and the one a vulnerability
// database is indexed by.
//
// The fields are the ones a real INFO has in the order it has them, because a
// tool that parses this reads it as sections of key:value lines and an operator
// reading a capture recognises it by shape.
func (d *decoy) info(section string) string {
	now := d.now()
	up := int(now.Sub(d.started) / time.Second)
	if up < 0 {
		up = 0
	}
	// Monotone by construction. A commands counter that went backwards between
	// two INFOs is the tell that ends the pretence, so it is derived from the
	// elapsed time rather than sampled.
	periods := int64(now.Sub(d.started) / d.period)
	if periods < 0 {
		periods = 0
	}
	commands := 1000 + periods*int64(97+d.gauge(addrClients))
	memory := int64(d.memory) << 20 * int64(d.gauge(addrMemoryPct)) / 100
	var b strings.Builder
	want := func(name string) bool { return section == "" || section == strings.ToLower(name) }
	if want("server") {
		fmt.Fprintf(&b, "# Server\r\nredis_version:%s\r\nredis_git_sha1:00000000\r\nredis_git_dirty:0\r\n"+
			"redis_build_id:%s\r\nredis_mode:standalone\r\nos:Linux 5.15.0-91-generic x86_64\r\n"+
			"arch_bits:64\r\nprocess_id:1\r\nrun_id:%s\r\ntcp_port:6379\r\nuptime_in_seconds:%d\r\n"+
			"uptime_in_days:%d\r\nexecutable:/usr/bin/redis-server\r\nconfig_file:/etc/redis/redis.conf\r\n\r\n",
			d.version, d.runID[:16], d.runID, up, up/86400)
	}
	if want("clients") {
		fmt.Fprintf(&b, "# Clients\r\nconnected_clients:%d\r\ncluster_connections:0\r\nmaxclients:10000\r\n"+
			"blocked_clients:%d\r\ntracking_clients:0\r\n\r\n", d.gauge(addrClients), d.gauge(addrBlocked))
	}
	if want("memory") {
		fmt.Fprintf(&b, "# Memory\r\nused_memory:%d\r\nused_memory_human:%.2fM\r\nused_memory_rss:%d\r\n"+
			"used_memory_peak:%d\r\nmaxmemory:0\r\nmaxmemory_policy:noeviction\r\n"+
			"mem_fragmentation_ratio:1.12\r\nmem_allocator:jemalloc-5.3.0\r\n\r\n",
			memory, float64(memory)/(1<<20), memory*112/100, memory*120/100)
	}
	if want("persistence") {
		fmt.Fprintf(&b, "# Persistence\r\nloading:0\r\nrdb_changes_since_last_save:%d\r\n"+
			"rdb_bgsave_in_progress:0\r\nrdb_last_save_time:%d\r\nrdb_last_bgsave_status:ok\r\n"+
			"aof_enabled:0\r\naof_rewrite_in_progress:0\r\n\r\n", periods, d.started.Unix())
	}
	if want("stats") {
		hits := commands * int64(d.gauge(addrHitRate)) / 100
		fmt.Fprintf(&b, "# Stats\r\ntotal_connections_received:%d\r\ntotal_commands_processed:%d\r\n"+
			"instantaneous_ops_per_sec:%d\r\nexpired_keys:%d\r\nevicted_keys:0\r\n"+
			"keyspace_hits:%d\r\nkeyspace_misses:%d\r\npubsub_channels:0\r\n\r\n",
			periods+1, commands, d.gauge(addrClients), d.gauge(addrExpired), hits, commands-hits)
	}
	if want("replication") {
		fmt.Fprintf(&b, "# Replication\r\nrole:master\r\nconnected_slaves:0\r\n"+
			"master_failover_state:no-failover\r\nmaster_replid:%s\r\nmaster_repl_offset:0\r\n\r\n", d.runID)
	}
	if want("keyspace") {
		fmt.Fprintf(&b, "# Keyspace\r\ndb0:keys=%d,expires=0,avg_ttl=0\r\n", len(d.keys))
	}
	return b.String()
}

// sectionOf is the section an INFO asked for, lower-cased, or "" for all of it.
func sectionOf(c *wire.Command) string {
	if len(c.Args) == 0 {
		return ""
	}
	s := strings.ToLower(string(c.Args[0]))
	if s == "all" || s == "everything" || s == "default" {
		return ""
	}
	return s
}

// deceive answers one command as the fabricated server and reports whether it
// did.
//
// It is called only where the command was not going to reach the server: a
// refusal, or a listener that is nothing but a decoy. That is the invariant the
// whole feature rests on -- a command on its way to a real Redis is never
// answered from here -- and it is a test rather than a comment.
//
// The second return value says the connection is finished, which is SHUTDOWN and
// QUIT: the real server closes on both, and a fabrication that stayed open would
// be a server that had not done what it said.
func (se *session) deceive(c *wire.Command, why string) (answered, done bool) {
	t := se.t
	d := t.decoy
	if d == nil || !d.admits(se.ip) {
		return false, false
	}
	reply, ok := d.answer(c, se.authed.Load())
	if !ok {
		return false, false
	}
	if d.requireAuth && c.Name == "AUTH" && len(c.Args) > 0 {
		// The fabrication accepted it, so the connection is authenticated for
		// the rest of its life. Nothing was checked: accepting is what keeps a
		// visitor talking, and refusing would make this a credential oracle.
		se.authed.Store(true)
	}
	t.recordDeception(se, c, why, d.tripped(c))
	if len(reply) > 0 {
		if err := se.writeClient(reply); err != nil {
			return true, true
		}
	}
	return true, c.Name == "SHUTDOWN" || c.Name == "QUIT"
}

// recordDeception notes one fabricated answer where an operator looks.
//
// The arguments of a tripwire command are in the event, because on this protocol
// they are the message: CONFIG SET dir names a directory the visitor chose,
// REPLICAOF names a host they control, and SET carries the payload. They are
// clipped and reduced to one line, because they are somebody else's octets going
// into a log line.
//
// A password is never among them. AUTH's arguments are replaced by the user name
// and the password's length, for the reason the SNMP relay does not log a
// community string: a log holding every credential sprayed at the estate is a
// list of the estate's own credentials as often as not.
func (t *server) recordDeception(se *session, c *wire.Command, why string, tripped bool) {
	d := t.decoy
	d.policy.Record(se.ip, tripped, time.Now())
	t.host.Counters().RedisDeceived.Add(1)
	event := "redis_deceived"
	if tripped {
		t.host.Counters().RedisTripwire.Add(1)
		event = "redis_tripwire"
	}
	attrs := []any{
		"listener", t.name, "client_ip", se.ip.String(), "command", c.String(),
		"reason", why, "mode", modeName(d.whole),
	}
	if arg := argSummary(c); arg != "" {
		attrs = append(attrs, "args", arg)
	}
	t.host.Logs().SecurityEvent(context.Background(), "deceive", event, attrs...)
}

// argSummary is what of a command's arguments goes into the record.
func argSummary(c *wire.Command) string {
	if c.Name == "AUTH" {
		// The one command whose arguments are a credential. The user name is an
		// identity and is kept; the password is measured and discarded.
		switch len(c.Args) {
		case 1:
			return "password of " + strconv.Itoa(len(c.Args[0])) + " octets"
		case 2:
			return "user " + wire.Clip(string(c.Args[0])) + ", password of " +
				strconv.Itoa(len(c.Args[1])) + " octets"
		}
		return ""
	}
	var b strings.Builder
	for i, a := range c.Args {
		if i >= 4 {
			b.WriteString(" ...")
			break
		}
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(wire.Clip(string(a)))
	}
	// One line, because a value carrying a cron entry carries newlines and a log
	// record built out of them would be several records.
	return strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == 0 {
			return ' '
		}
		return r
	}, b.String())
}

// serveDecoy runs a connection on a listener that is nothing but a fabricated
// server.
//
// It is the ordinary command loop with the server taken out: the bounds still
// apply -- the idle timeout, the command count, the reader's own limits -- because
// a honeypot is still a service on a port and a visitor who sends a million
// commands is still a visitor holding resources.
func (t *server) serveDecoy(se *session) {
	max := t.policy.MaxCommands(se.sess())
	for {
		if idle := t.rc.IdleTimeout.D(); idle > 0 {
			_ = se.client.SetReadDeadline(time.Now().Add(idle))
		}
		c, err := se.cliReader.Next()
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				// The same answer the real server gives, because that is what a
				// client library reports -- and because a fabrication that went
				// silent on a malformed command would be one a scanner could
				// find by sending one.
				_ = se.writeClient(wire.Error("ERR", "Protocol error: "+err.Error()))
			}
			return
		}
		se.commands++
		if max > 0 && se.commands > max {
			_ = se.writeClient(wire.Error("ERR", "max number of clients reached"))
			return
		}
		if _, done := se.deceive(c, "decoy"); done {
			return
		}
	}
}

// nameChar is the alphabet a Redis command name is made of: the upper-case
// letters, the digits, and the two separators a few names use.
func nameChar(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
		return true
	}
	return false
}
