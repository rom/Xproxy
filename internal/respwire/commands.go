package respwire

import "sort"

// The command table: which commands exist, where their keys are, and which of
// them lead out of the database.
//
// Redis has no schema and no statement grammar, so this table is the whole of
// what a policy has to reason about. Two things are recorded per command and
// nothing is guessed:
//
// **Where the keys are.** A command's keys sit at positions its own signature
// fixes -- GET takes one at position 1, MSET takes every odd position, ZADD takes
// one and then scores and members. A key prefix policy is the closest this
// protocol has to the database-and-table boundary the SQL kinds leave to GRANT,
// and it is only worth having if it looks at the right argument. So a command
// whose key positions are not in this table reports that it does not know, and
// the policy refuses it when a prefix policy is in force rather than checking
// some argument that happened to be in the right place.
//
// **Whether the subcommand is the whole of what matters.** CONFIG SET is remote
// code execution when pointed at a file; CONFIG GET is a read. A policy that
// could only say CONFIG would have to refuse both or neither, so the commands
// that carry a container verb are marked and the reader folds their first
// argument into the name.

// keySpec says where a command's keys are.
type keySpec struct {
	// firstKey is the 1-based position of the first key among the arguments,
	// counting the command name as 0. Zero means the command takes no keys.
	firstKey int
	// lastKey is the position of the last, or -1 for "to the end of the
	// arguments".
	lastKey int
	// step is the distance between keys, for the commands that interleave them
	// with values: MSET is key, value, key, value.
	step int
}

// commands maps a command name to where its keys are. A name absent from this
// map is one this package cannot locate keys for, which Keys reports rather
// than guessing.
//
// It covers what an application uses plus every command the policy has an
// opinion about, which is what the default allow list and the dangerous set are
// drawn from. A Redis instance has several hundred commands; a relay does not
// need to know them all, it needs to know which ones it is willing to forward.
var commands = map[string]keySpec{
	// Strings.
	"GET": {1, 1, 1}, "GETDEL": {1, 1, 1}, "GETEX": {1, 1, 1}, "SET": {1, 1, 1},
	"SETNX": {1, 1, 1}, "SETEX": {1, 1, 1}, "PSETEX": {1, 1, 1},
	"APPEND": {1, 1, 1}, "STRLEN": {1, 1, 1}, "GETRANGE": {1, 1, 1}, "SETRANGE": {1, 1, 1},
	"INCR": {1, 1, 1}, "DECR": {1, 1, 1}, "INCRBY": {1, 1, 1}, "DECRBY": {1, 1, 1},
	"INCRBYFLOAT": {1, 1, 1}, "GETSET": {1, 1, 1},
	"MGET": {1, -1, 1}, "MSET": {1, -1, 2}, "MSETNX": {1, -1, 2},
	"LCS": {1, 2, 1}, "PUBSUB": {0, 0, 0},

	// Keys.
	"DEL": {1, -1, 1}, "UNLINK": {1, -1, 1}, "EXISTS": {1, -1, 1},
	"EXPIRE": {1, 1, 1}, "PEXPIRE": {1, 1, 1}, "EXPIREAT": {1, 1, 1},
	"PEXPIREAT": {1, 1, 1}, "EXPIRETIME": {1, 1, 1}, "PEXPIRETIME": {1, 1, 1},
	"TTL": {1, 1, 1}, "PTTL": {1, 1, 1}, "PERSIST": {1, 1, 1},
	"TYPE": {1, 1, 1}, "TOUCH": {1, -1, 1}, "OBJECT": {2, 2, 1},
	"RENAME": {1, 2, 1}, "RENAMENX": {1, 2, 1}, "COPY": {1, 2, 1},
	"DUMP": {1, 1, 1}, "RESTORE": {1, 1, 1},

	// Hashes.
	"HGET": {1, 1, 1}, "HSET": {1, 1, 1}, "HSETNX": {1, 1, 1}, "HDEL": {1, 1, 1},
	"HEXISTS": {1, 1, 1}, "HLEN": {1, 1, 1}, "HKEYS": {1, 1, 1}, "HVALS": {1, 1, 1},
	"HGETALL": {1, 1, 1}, "HMGET": {1, 1, 1}, "HMSET": {1, 1, 1},
	"HINCRBY": {1, 1, 1}, "HINCRBYFLOAT": {1, 1, 1}, "HRANDFIELD": {1, 1, 1},
	"HSCAN": {1, 1, 1}, "HSTRLEN": {1, 1, 1},

	// Lists.
	"LPUSH": {1, 1, 1}, "RPUSH": {1, 1, 1}, "LPUSHX": {1, 1, 1}, "RPUSHX": {1, 1, 1},
	"LPOP": {1, 1, 1}, "RPOP": {1, 1, 1}, "LLEN": {1, 1, 1}, "LRANGE": {1, 1, 1},
	"LINDEX": {1, 1, 1}, "LSET": {1, 1, 1}, "LREM": {1, 1, 1}, "LTRIM": {1, 1, 1},
	"LINSERT": {1, 1, 1}, "LPOS": {1, 1, 1}, "LMOVE": {1, 2, 1},
	"RPOPLPUSH": {1, 2, 1}, "BLPOP": {1, -2, 1}, "BRPOP": {1, -2, 1},
	"BRPOPLPUSH": {1, 2, 1}, "BLMOVE": {1, 2, 1},

	// Sets.
	"SADD": {1, 1, 1}, "SREM": {1, 1, 1}, "SMEMBERS": {1, 1, 1}, "SISMEMBER": {1, 1, 1},
	"SMISMEMBER": {1, 1, 1}, "SCARD": {1, 1, 1}, "SPOP": {1, 1, 1},
	"SRANDMEMBER": {1, 1, 1}, "SMOVE": {1, 2, 1}, "SSCAN": {1, 1, 1},
	"SINTER": {1, -1, 1}, "SUNION": {1, -1, 1}, "SDIFF": {1, -1, 1},
	// Sorted sets.
	"ZADD": {1, 1, 1}, "ZREM": {1, 1, 1}, "ZCARD": {1, 1, 1}, "ZSCORE": {1, 1, 1},
	"ZMSCORE": {1, 1, 1}, "ZINCRBY": {1, 1, 1}, "ZRANK": {1, 1, 1},
	"ZREVRANK": {1, 1, 1}, "ZRANGE": {1, 1, 1}, "ZREVRANGE": {1, 1, 1},
	"ZRANGEBYSCORE": {1, 1, 1}, "ZREVRANGEBYSCORE": {1, 1, 1},
	"ZRANGEBYLEX": {1, 1, 1}, "ZREVRANGEBYLEX": {1, 1, 1}, "ZCOUNT": {1, 1, 1},
	"ZLEXCOUNT": {1, 1, 1}, "ZSCAN": {1, 1, 1}, "ZRANDMEMBER": {1, 1, 1},
	"ZPOPMIN": {1, 1, 1}, "ZPOPMAX": {1, 1, 1}, "ZREMRANGEBYRANK": {1, 1, 1},
	"ZREMRANGEBYSCORE": {1, 1, 1}, "ZREMRANGEBYLEX": {1, 1, 1},

	// Bitmaps and HyperLogLog.
	"SETBIT": {1, 1, 1}, "GETBIT": {1, 1, 1}, "BITCOUNT": {1, 1, 1},
	"BITPOS": {1, 1, 1}, "BITFIELD": {1, 1, 1}, "BITFIELD_RO": {1, 1, 1},
	"PFADD": {1, 1, 1}, "PFCOUNT": {1, -1, 1},

	// Streams.
	"XADD": {1, 1, 1}, "XLEN": {1, 1, 1}, "XRANGE": {1, 1, 1},
	"XREVRANGE": {1, 1, 1}, "XDEL": {1, 1, 1}, "XTRIM": {1, 1, 1},
	"XACK": {1, 1, 1}, "XPENDING": {1, 1, 1}, "XINFO": {2, 2, 1},
	"XAUTOCLAIM": {1, 1, 1}, "XCLAIM": {1, 1, 1},

	// Geospatial.
	"GEOADD": {1, 1, 1}, "GEOPOS": {1, 1, 1}, "GEODIST": {1, 1, 1},
	"GEOHASH": {1, 1, 1}, "GEOSEARCH": {1, 1, 1},

	// Transactions and connection, which take no keys at all.
	"MULTI": {0, 0, 0}, "EXEC": {0, 0, 0}, "DISCARD": {0, 0, 0},
	"UNWATCH": {0, 0, 0}, "WATCH": {1, -1, 1},
	"PING": {0, 0, 0}, "ECHO": {0, 0, 0}, "QUIT": {0, 0, 0},
	"SELECT": {0, 0, 0}, "SWAPDB": {0, 0, 0}, "AUTH": {0, 0, 0},
	"HELLO": {0, 0, 0}, "RESET": {0, 0, 0}, "COMMAND": {0, 0, 0},
	"DBSIZE": {0, 0, 0}, "TIME": {0, 0, 0}, "LASTSAVE": {0, 0, 0},
	"INFO": {0, 0, 0}, "WAIT": {0, 0, 0},

	// Pub/sub, whose "keys" are channel names rather than keys: the prefix
	// policy applies to them too, which is what an operator wants, but they are
	// recorded here so a reader knows where they are.
	"PUBLISH": {1, 1, 1}, "SPUBLISH": {1, 1, 1},
	"SUBSCRIBE": {1, -1, 1}, "UNSUBSCRIBE": {1, -1, 1},
	"SSUBSCRIBE": {1, -1, 1}, "SUNSUBSCRIBE": {1, -1, 1},
	"PSUBSCRIBE": {1, -1, 1}, "PUNSUBSCRIBE": {1, -1, 1},

	// The administrative and dangerous ones. Their key positions are recorded
	// too, so that a listener which *allows* one still gets its prefix policy
	// applied: an operator who allows RESTORE has not agreed to allow it on
	// every key.
	"KEYS": {0, 0, 0}, "SCAN": {0, 0, 0}, "RANDOMKEY": {0, 0, 0},
	"FLUSHALL": {0, 0, 0}, "FLUSHDB": {0, 0, 0},
	"CONFIG": {0, 0, 0}, "CLIENT": {0, 0, 0}, "CLUSTER": {0, 0, 0},
	"ACL": {0, 0, 0}, "SCRIPT": {0, 0, 0}, "FUNCTION": {0, 0, 0},
	"MODULE": {0, 0, 0}, "DEBUG": {0, 0, 0}, "MEMORY": {0, 0, 0},
	"LATENCY": {0, 0, 0}, "SLOWLOG": {0, 0, 0}, "MONITOR": {0, 0, 0},
	"SHUTDOWN": {0, 0, 0}, "SAVE": {0, 0, 0}, "BGSAVE": {0, 0, 0},
	"BGREWRITEAOF": {0, 0, 0}, "REPLICAOF": {0, 0, 0}, "SLAVEOF": {0, 0, 0},
	"REPLCONF": {0, 0, 0}, "PSYNC": {0, 0, 0}, "SYNC": {0, 0, 0},
	"FAILOVER":     {0, 0, 0},
	"GEORADIUS_RO": {1, 1, 1}, "GEORADIUSBYMEMBER_RO": {1, 1, 1},
	"SINTERSTORE": {1, 1, 1}, "SUNIONSTORE": {1, 1, 1}, "SDIFFSTORE": {1, 1, 1},
	"BITOP": {2, -1, 1}, "PFMERGE": {1, -1, 1}, "PFDEBUG": {0, 0, 0},
	"XGROUP": {2, 2, 1}, "XSETID": {1, 1, 1},
}

// XREAD and XREADGROUP are deliberately in neither table.
//
// Their keys come after a STREAMS token whose position depends on which options
// preceded it -- COUNT, BLOCK, GROUP, NOACK -- and after the token the streams and
// their identifiers are interleaved in two halves rather than alternating. Locating
// them means parsing the option list, and a table entry that guessed a position
// would hand a key prefix policy an option value to check.
//
// So Keys reports that it does not know, which is what the policy needs: the
// command is refused where a prefix policy is in force, and allowed where one is
// not. Listing it with a made-up position would have been the silent version of
// the same decision, with the prefix policy passing whatever it was meant to stop.

// unlocatable are commands this package knows exist and cannot say where the keys
// are, because their key positions depend on an option that may or may not be
// present.
//
// Recording them here rather than leaving them out is the point. Left out, they
// would be *unknown* commands -- which a read-only listener refuses outright and
// which a validator would not let an operator name. Listed with a made-up
// position, a key prefix policy would check the wrong argument, which is the
// silent failure: a policy that passes exactly what it was meant to stop. Listed
// here, Keys reports that it does not know, so the command is refused where a
// prefix policy is in force and allowed where one is not -- and the refusal names
// the reason.
//
// Each entry is a specific reason rather than a shrug:
//
//	XREAD, XREADGROUP     the keys follow a STREAMS token whose position depends
//	                      on COUNT, BLOCK, GROUP and NOACK, and after it the
//	                      streams and their identifiers are two halves rather
//	                      than alternating pairs.
//	SORT, SORT_RO         a STORE option adds a destination key at the end, and
//	                      BY and GET take key *patterns* rather than keys.
//	GEORADIUS,            STORE and STOREDIST each add a key at the end. The _RO
//	GEORADIUSBYMEMBER     variants have neither, which is why they stay above.
//	ZUNIONSTORE,          a destination, then a numkeys count, then that many
//	ZINTERSTORE,          source keys: two different mechanisms in one command.
//	ZDIFFSTORE
//	MIGRATE               the key is the third argument -- unless the KEYS option
//	                      is used, in which case the third is an empty string and
//	                      the keys are at the end.
var unlocatable = map[string]bool{
	"XREAD": true, "XREADGROUP": true,
	"SORT": true, "SORT_RO": true,
	"GEORADIUS": true, "GEORADIUSBYMEMBER": true,
	"ZUNIONSTORE": true, "ZINTERSTORE": true, "ZDIFFSTORE": true,
	"MIGRATE": true,
}

// numkeyCommands declare their own key count in an argument, at the position
// given: LMPOP numkeys key [key ...], EVAL script numkeys key [key ...].
//
// These are read rather than assumed because the count is the *client's* number
// and it decides which arguments are keys. A relay that assumed a fixed position
// would check a prefix policy against a Lua script's text or a timeout.
var numkeyCommands = map[string]int{
	"EVAL": 2, "EVALSHA": 2, "EVAL_RO": 2, "EVALSHA_RO": 2,
	"FCALL": 2, "FCALL_RO": 2,
	"LMPOP": 1, "ZMPOP": 1, "ZUNION": 1, "ZINTER": 1, "ZDIFF": 1,
	"ZINTERCARD": 1, "SINTERCARD": 1,
	"BLMPOP": 2, "BZMPOP": 2,
}

// containerCommands take a subcommand that is the whole of what matters.
var containerCommands = map[string]bool{
	"CONFIG": true, "CLIENT": true, "CLUSTER": true, "ACL": true,
	"SCRIPT": true, "FUNCTION": true, "MODULE": true, "DEBUG": true,
	"MEMORY": true, "LATENCY": true, "SLOWLOG": true, "OBJECT": true,
	"COMMAND": true, "XGROUP": true, "XINFO": true, "PUBSUB": true,
}

// takesSub says whether a command's first argument is a subcommand.
func takesSub(name string) bool { return containerCommands[name] }

// Known says whether this package has the command in its table at all.
//
// A command it does not know is not necessarily dangerous -- Redis gains commands
// every release and a module adds its own -- but it is one whose keys cannot be
// located, which is what the policy needs to decide about.
func Known(name string) bool {
	if _, ok := commands[name]; ok {
		return true
	}
	if _, ok := numkeyCommands[name]; ok {
		return true
	}
	return unlocatable[name]
}

// Keys returns the keys a command operates on, and whether the positions are
// known.
//
// The second value is the one to act on. `false` means this package cannot say
// where the keys are, and a relay with a key prefix policy must refuse the
// command rather than check the wrong argument: a prefix policy enforced against
// a Lua script's text or a timeout value is a policy that passes whatever it was
// meant to stop.
func Keys(c *Command) (keys []string, known bool) {
	if unlocatable[c.Name] {
		return nil, false
	}
	if n, ok := numkeyCommands[c.Name]; ok {
		return numberedKeys(c, n)
	}
	spec, ok := commands[c.Name]
	if !ok {
		return nil, false
	}
	if spec.firstKey == 0 {
		return nil, true // no keys, which is knowing where they are
	}
	step := spec.step
	if step < 1 {
		step = 1
	}
	// Positions count the command name as 0, so argument i is position i+1.
	last := spec.lastKey
	switch {
	case last == -1:
		last = len(c.Args)
	case last < 0:
		// -2 means "all but the last N", which BLPOP uses: the final argument
		// is a timeout rather than a key.
		last = len(c.Args) + last + 1
	}
	for pos := spec.firstKey; pos <= last && pos <= len(c.Args); pos += step {
		keys = append(keys, Clip(string(c.Args[pos-1])))
	}
	return keys, true
}

// numberedKeys reads a command whose key count is an argument.
func numberedKeys(c *Command, at int) (keys []string, known bool) {
	if at > len(c.Args) {
		return nil, false
	}
	n, err := atoiBytes(c.Args[at-1])
	if err != nil || n < 0 {
		// The count is not a number, or is negative. Redis refuses the command;
		// a relay that guessed a count would check a prefix policy against
		// arguments that are not keys.
		return nil, false
	}
	if at+n > len(c.Args) {
		// The count says more keys than there are arguments. One of the two is
		// wrong and there is no way to tell which, so neither is believed.
		return nil, false
	}
	for i := 0; i < n; i++ {
		keys = append(keys, Clip(string(c.Args[at+i])))
	}
	return keys, true
}

func atoiBytes(b []byte) (int, error) {
	if len(b) == 0 || len(b) > 19 {
		return 0, ErrProtocol
	}
	n := 0
	neg := false
	for i, c := range b {
		if i == 0 && c == '-' {
			neg = true
			continue
		}
		if c < '0' || c > '9' {
			return 0, ErrProtocol
		}
		n = n*10 + int(c-'0')
		if n > MaxElements {
			return 0, ErrTooMany
		}
	}
	if neg {
		return -n, nil
	}
	return n, nil
}

// DefaultCommands is the allow list a listener uses when the configuration names
// none: what an application does to a cache, and nothing else.
//
// Every absence is deliberate and the package doc says why each one is dangerous.
// The shape to notice is that "administrative" and "remote code execution" are
// nearer each other here than on any other protocol in this project: CONFIG SET
// with dir and dbfilename writes a file wherever the server can write, which
// pointed at an authorized_keys or a cron directory is a shell.
func DefaultCommands() []string {
	return []string{
		// Strings.
		"GET", "GETDEL", "GETEX", "SET", "SETNX", "SETEX", "PSETEX", "APPEND",
		"STRLEN", "GETRANGE", "SETRANGE", "INCR", "DECR", "INCRBY", "DECRBY",
		"INCRBYFLOAT", "GETSET", "MGET", "MSET", "MSETNX",
		// Keys, minus the ones that enumerate or move them.
		"DEL", "UNLINK", "EXISTS", "EXPIRE", "PEXPIRE", "EXPIREAT", "PEXPIREAT",
		"EXPIRETIME", "PEXPIRETIME", "TTL", "PTTL", "PERSIST", "TYPE", "TOUCH",
		"RENAME", "RENAMENX", "COPY",
		// Hashes.
		"HGET", "HSET", "HSETNX", "HDEL", "HEXISTS", "HLEN", "HKEYS", "HVALS",
		"HGETALL", "HMGET", "HMSET", "HINCRBY", "HINCRBYFLOAT", "HRANDFIELD",
		"HSCAN", "HSTRLEN",
		// Lists.
		"LPUSH", "RPUSH", "LPUSHX", "RPUSHX", "LPOP", "RPOP", "LLEN", "LRANGE",
		"LINDEX", "LSET", "LREM", "LTRIM", "LINSERT", "LPOS", "LMOVE",
		"RPOPLPUSH", "BLPOP", "BRPOP", "BLMOVE", "BRPOPLPUSH",
		// Sets.
		"SADD", "SREM", "SMEMBERS", "SISMEMBER", "SMISMEMBER", "SCARD", "SPOP",
		"SRANDMEMBER", "SMOVE", "SSCAN", "SINTER", "SUNION", "SDIFF",
		"SINTERCARD",
		// Sorted sets.
		"ZADD", "ZREM", "ZCARD", "ZSCORE", "ZMSCORE", "ZINCRBY", "ZRANK",
		"ZREVRANK", "ZRANGE", "ZREVRANGE", "ZRANGEBYSCORE", "ZREVRANGEBYSCORE",
		"ZRANGEBYLEX", "ZREVRANGEBYLEX", "ZCOUNT", "ZLEXCOUNT", "ZSCAN",
		"ZRANDMEMBER", "ZPOPMIN", "ZPOPMAX", "ZREMRANGEBYRANK",
		"ZREMRANGEBYSCORE", "ZREMRANGEBYLEX",
		// Bitmaps and HyperLogLog.
		"SETBIT", "GETBIT", "BITCOUNT", "BITPOS", "BITFIELD", "BITFIELD_RO",
		"PFADD", "PFCOUNT",
		// Streams.
		"XADD", "XLEN", "XRANGE", "XREVRANGE", "XDEL", "XTRIM", "XACK",
		"XPENDING", "XAUTOCLAIM", "XCLAIM", "XREAD", "XREADGROUP",
		// Geospatial.
		"GEOADD", "GEOPOS", "GEODIST", "GEOHASH", "GEOSEARCH",
		// Transactions.
		"MULTI", "EXEC", "DISCARD", "WATCH", "UNWATCH",
		// Connection. AUTH and HELLO have to be here or nothing authenticates.
		"PING", "ECHO", "QUIT", "SELECT", "AUTH", "HELLO", "RESET", "COMMAND",
		// Pub/sub for messages, not for the pattern forms: PSUBSCRIBE '*'
		// receives every message on the instance, which is every value
		// published, and is the pub/sub equivalent of MONITOR.
		"PUBLISH", "SUBSCRIBE", "UNSUBSCRIBE",
	}
}

// dangerous is the set whose refusal is never shadowed.
//
// Each is a way out of the database, a way to lose all of it, or a way to stop
// the thread that serves everybody. Refusing these in monitor mode too is the
// judgement the mysql kind makes about replication and the tds kind about
// xp_cmdshell: forwarding a command that writes a file wherever the server can
// write, and writing down that it was noticed, is not a trial of a policy.
//
// KEYS is in the set on different grounds and they are worth separating. It is
// not an escape; it is O(n) on the single thread that serves every client, so one
// KEYS * on a large instance stops the whole estate for as long as it takes. A
// relay in monitor mode that forwarded it would cause the outage it was installed
// to prevent, and the shadow report would record that it had noticed.
var dangerous = map[string]bool{
	"CONFIG": true, "MODULE": true, "DEBUG": true, "SCRIPT": true,
	"FUNCTION": true, "ACL": true, "CLIENT": true, "CLUSTER": true,
	"EVAL": true, "EVALSHA": true, "EVAL_RO": true, "EVALSHA_RO": true,
	"FCALL": true, "FCALL_RO": true,
	"REPLICAOF": true, "SLAVEOF": true, "REPLCONF": true, "PSYNC": true,
	"SYNC": true, "FAILOVER": true,
	"FLUSHALL": true, "FLUSHDB": true, "SHUTDOWN": true,
	"MIGRATE": true, "RESTORE": true, "DUMP": true,
	"MONITOR": true, "SLOWLOG": true, "LATENCY": true, "MEMORY": true,
	"SAVE": true, "BGSAVE": true, "BGREWRITEAOF": true,
	"KEYS": true, "RANDOMKEY": true,
	"SWAPDB": true, "PFDEBUG": true,
}

// Dangerous says whether refusing this command is a decision monitor mode must
// not shadow. The name is expected upper-cased, as the reader returns it.
func Dangerous(name string) bool { return dangerous[name] }

// DangerousCommands is the set, sorted, for a document and a warning.
func DangerousCommands() []string {
	out := make([]string, 0, len(dangerous))
	for c := range dangerous {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// writing says whether a command can change data.
//
// A read-only listener is the commonest thing an operator wants in front of a
// cache -- a reporting service, a dashboard, anything that should not be able to
// evict somebody else's session -- and it is only worth having if the set is
// right. A command missing from this set would be a write that a read-only
// listener allowed.
var writing = map[string]bool{
	"SET": true, "SETNX": true, "SETEX": true, "PSETEX": true,
	"GETSET": true, "GETDEL": true, "GETEX": true, "APPEND": true,
	"SETRANGE": true, "INCR": true, "DECR": true, "INCRBY": true,
	"DECRBY": true, "INCRBYFLOAT": true, "MSET": true, "MSETNX": true,
	"DEL": true, "UNLINK": true, "EXPIRE": true, "PEXPIRE": true,
	"EXPIREAT": true, "PEXPIREAT": true, "PERSIST": true, "RENAME": true,
	"RENAMENX": true, "COPY": true, "RESTORE": true, "MIGRATE": true,
	"HSET": true, "HSETNX": true, "HDEL": true, "HMSET": true,
	"HINCRBY": true, "HINCRBYFLOAT": true,
	"LPUSH": true, "RPUSH": true, "LPUSHX": true, "RPUSHX": true,
	"LPOP": true, "RPOP": true, "LSET": true, "LREM": true, "LTRIM": true,
	"LINSERT": true, "LMOVE": true, "RPOPLPUSH": true, "BLPOP": true,
	"BRPOP": true, "BLMOVE": true, "BRPOPLPUSH": true, "LMPOP": true,
	"BLMPOP": true,
	"SADD":   true, "SREM": true, "SPOP": true, "SMOVE": true,
	"SINTERSTORE": true, "SUNIONSTORE": true, "SDIFFSTORE": true,
	"ZADD": true, "ZREM": true, "ZINCRBY": true, "ZPOPMIN": true,
	"ZPOPMAX": true, "ZREMRANGEBYRANK": true, "ZREMRANGEBYSCORE": true,
	"ZREMRANGEBYLEX": true, "ZUNIONSTORE": true, "ZINTERSTORE": true,
	"ZDIFFSTORE": true, "ZMPOP": true, "BZMPOP": true,
	"SETBIT": true, "BITFIELD": true, "BITOP": true,
	"PFADD": true, "PFMERGE": true,
	"XADD": true, "XDEL": true, "XTRIM": true, "XACK": true,
	"XAUTOCLAIM": true, "XCLAIM": true, "XGROUP": true, "XSETID": true,
	"XREADGROUP": true,
	"GEOADD":     true, "GEORADIUS": true, "GEORADIUSBYMEMBER": true,
	"SORT": true, "FLUSHALL": true, "FLUSHDB": true, "SWAPDB": true,
	// A script can do anything the connection can, so a read-only listener that
	// allowed one would have a read-only setting that was decorative. The _RO
	// variants are the server's own promise that the script does not write, and
	// they are treated as reads.
	"EVAL": true, "EVALSHA": true, "FCALL": true,
	// Publishing is not a write to a key, but it delivers to every subscriber,
	// which on a read-only listener is a side effect the operator did not ask
	// for.
	"PUBLISH": true, "SPUBLISH": true,
	// These change the server rather than the data, which is more than a write.
	"CONFIG": true, "MODULE": true, "REPLICAOF": true, "SLAVEOF": true,
	"SHUTDOWN": true, "SCRIPT": true, "FUNCTION": true, "ACL": true,
	"CLIENT": true, "CLUSTER": true, "DEBUG": true, "FAILOVER": true,
	"SAVE": true, "BGSAVE": true, "BGREWRITEAOF": true,
}

// Writes says whether a command can change data or the server.
//
// A command this package does not know counts as a write, which is the direction
// a classifier has to be wrong in: Redis gains commands every release and a
// module adds its own, and one it has never heard of must not pass a read-only
// listener because nobody has written it down yet.
func Writes(name string) bool {
	if writing[name] {
		return true
	}
	return !Known(name)
}

// CommandNames is every command a configuration may name, sorted, for a
// validation error.
func CommandNames() []string {
	seen := make(map[string]bool, len(commands))
	out := make([]string, 0, len(commands))
	for c := range commands {
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	for c := range numkeyCommands {
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	for c := range unlocatable {
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	sort.Strings(out)
	return out
}
