package inspection

import (
	"strconv"
	"time"

	"github.com/tnldotdev/tnl/internal/observability/inspection"
)

type respMode uint8

const (
	respValue respMode = iota
	respLine
	respBulkBody
	respBulkCR
	respBulkLF
)

// RESP is consumed incrementally. only a command's first bulk string is kept;
// arguments and all reply bodies are discarded as bytes arrive. the stack,
// numeric lines, command name, frame size, and outstanding replies are bounded.
type redisSummaryFrame struct {
	stack        [9]int
	depth        int
	mode         respMode // zero expects the next value's type byte.
	kind, top    byte
	started      bool
	line         [24]byte
	n            int
	cr           bool
	remaining    int
	capture      bool
	verbSeen     bool
	command      [64]byte
	commandN     int
	bytes, nodes int
	errorCode    [9]byte
	errorN       int
	errorEnd     bool
}

func (f *redisSummaryFrame) finishValue() bool {
	for f.depth > 0 {
		f.stack[f.depth-1]--
		if f.stack[f.depth-1] > 0 {
			return false
		}
		f.depth--
	}
	return true
}

func (f *redisSummaryFrame) feed(data []byte, client bool, m *Observer, done func(*redisSummaryFrame)) {
	for _, b := range data {
		if m.stopped {
			return
		}
		f.bytes++
		if f.bytes > 1<<20 {
			m.stopped = true
			return
		}
		complete := false
		switch f.mode {
		case respValue:
			f.nodes++
			if f.nodes > 1024 {
				m.stopped = true
				return
			}
			f.kind = b
			f.n = 0
			f.cr = false
			if !f.started {
				f.top = b
				f.started = true
				if client && b != '*' {
					m.stopped = true
					return
				}
			}
			if client && f.depth > 0 && b != '$' {
				m.stopped = true
				return
			}
			switch b {
			case '+', '-', ':', ',', '(', '#', '_', '$', '!', '=', '*', '~', '>', '%', '|':
				f.mode = respLine
			default:
				m.stopped = true
				return
			}
		case respLine:
			if f.cr {
				if b != '\n' {
					m.stopped = true
					return
				}
				f.cr = false
				f.mode = respValue
				switch f.kind {
				case '$', '!', '=', '*', '~', '>', '%', '|':
					n, err := strconv.Atoi(string(f.line[:f.n]))
					clear(f.line[:])
					f.n = 0
					if err != nil || n < -1 || n > 1<<20 {
						m.stopped = true
						return
					}
					if f.kind == '$' || f.kind == '!' || f.kind == '=' {
						if n == -1 {
							if client {
								m.stopped = true
								return
							}
							complete = f.finishValue()
							break
						}
						f.remaining = n
						f.capture = client && !f.verbSeen
						if f.capture {
							if n == 0 || n > len(f.command) {
								m.stopped = true
								return
							}
							f.verbSeen = true
						}
						f.mode = respBulkBody
						if n == 0 {
							f.mode = respBulkCR
						}
					} else {
						if n > 512 || f.depth == len(f.stack) {
							m.stopped = true
							return
						}
						if client && f.depth == 0 && n <= 0 {
							m.stopped = true
							return
						}
						if f.kind == '%' || f.kind == '|' {
							n *= 2
						}
						if n <= 0 {
							complete = f.finishValue()
						} else {
							f.stack[f.depth] = n
							f.depth++
						}
					}
				default:
					complete = f.finishValue()
				}
			} else if b == '\r' {
				f.cr = true
			} else if b == '\n' {
				m.stopped = true
				return
			} else {
				if f.kind == '-' && f.top == '-' && !f.errorEnd {
					if b >= 'A' && b <= 'Z' && f.errorN < len(f.errorCode) {
						f.errorCode[f.errorN] = b
						f.errorN++
					} else {
						f.errorEnd = true
					}
				}
				switch f.kind {
				case '$', '!', '=', '*', '~', '>', '%', '|':
					if f.n == len(f.line) {
						m.stopped = true
						return
					}
					f.line[f.n] = b
					f.n++
				}
			}
		case respBulkBody:
			if f.capture {
				if b >= 'a' && b <= 'z' {
					b -= 'a' - 'A'
				}
				if !(b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '.' || b == '_' || b == '-') {
					m.stopped = true
					return
				}
				f.command[f.commandN] = b
				f.commandN++
			}
			f.remaining--
			if f.remaining == 0 {
				f.mode = respBulkCR
			}
		case respBulkCR:
			if b != '\r' {
				m.stopped = true
				return
			}
			f.mode = respBulkLF
		case respBulkLF:
			if b != '\n' {
				m.stopped = true
				return
			}
			f.mode = respValue
			complete = f.finishValue()
		}
		if complete {
			done(f)
			*f = redisSummaryFrame{}
		}
	}
}

type redisSummaryParser struct {
	client, server redisSummaryFrame
	pending        []inspection.Summary
}

func (p *redisSummaryParser) feed(client bool, data []byte, m *Observer) {
	if client {
		p.client.feed(data, true, m, func(f *redisSummaryFrame) {
			if !f.verbSeen || len(p.pending) == maxPendingOperations {
				m.stopped = true
				return
			}
			command := string(f.command[:f.commandN])
			switch command {
			case "SUBSCRIBE", "PSUBSCRIBE", "SSUBSCRIBE", "UNSUBSCRIBE", "PUNSUBSCRIBE", "SUNSUBSCRIBE", "MONITOR", "SYNC", "PSYNC", "CLIENT", "QUIT", "MULTI", "EXEC", "DISCARD":
				m.stopped = true
				return
			}
			command = knownRedisCommand(command)
			p.pending = append(p.pending, inspection.Summary{ReceivedAt: time.Now(), Command: command})
		})
	} else {
		p.server.feed(data, false, m, func(f *redisSummaryFrame) {
			if f.top == '>' || f.top == '|' {
				return
			} // push and attributes do not consume a command reply.
			if len(p.pending) == 0 {
				m.stopped = true
				return
			}
			s := p.pending[0]
			p.pending = p.pending[1:]
			if s.Command == "AUTH" || s.Command == "HELLO" || string(f.errorCode[:f.errorN]) == "NOAUTH" {
				return
			}
			s.Result = inspection.ResultOK
			if f.top == '-' || f.top == '!' {
				s.Result = inspection.ResultError
			}
			m.emit(s)
		})
	}
	if m.stopped {
		p.pending = nil
		p.client = redisSummaryFrame{}
		p.server = redisSummaryFrame{}
	}
}

// arbitrary first arguments, module verbs, and misspelled commands must never
// turn into persisted user text. unknown commands share one authored category.
func knownRedisCommand(command string) string {
	switch command {
	case "AUTH", "HELLO", "PING", "ECHO", "SELECT", "RESET", "GET", "SET", "SETNX", "SETEX", "PSETEX", "GETSET", "GETDEL", "GETEX", "MGET", "MSET", "MSETNX", "APPEND", "STRLEN", "GETRANGE", "SETRANGE", "INCR", "INCRBY", "INCRBYFLOAT", "DECR", "DECRBY",
		"DEL", "UNLINK", "EXISTS", "TYPE", "KEYS", "SCAN", "RANDOMKEY", "RENAME", "RENAMENX", "EXPIRE", "PEXPIRE", "EXPIREAT", "PEXPIREAT", "TTL", "PTTL", "EXPIRETIME", "PEXPIRETIME", "PERSIST", "TOUCH", "COPY", "DUMP", "RESTORE", "MOVE", "SORT", "SORT_RO",
		"HGET", "HSET", "HSETNX", "HDEL", "HEXISTS", "HGETALL", "HKEYS", "HVALS", "HLEN", "HMGET", "HMSET", "HINCRBY", "HINCRBYFLOAT", "HSCAN", "HRANDFIELD", "HSTRLEN",
		"LPUSH", "RPUSH", "LPUSHX", "RPUSHX", "LPOP", "RPOP", "BLPOP", "BRPOP", "LLEN", "LINDEX", "LSET", "LRANGE", "LTRIM", "LREM", "LINSERT", "LMOVE", "BLMOVE", "LMPOP", "BLMPOP", "LPOS", "RPOPLPUSH", "BRPOPLPUSH",
		"SADD", "SREM", "SMEMBERS", "SISMEMBER", "SMISMEMBER", "SCARD", "SPOP", "SRANDMEMBER", "SSCAN", "SMOVE", "SUNION", "SUNIONSTORE", "SINTER", "SINTERSTORE", "SINTERCARD", "SDIFF", "SDIFFSTORE",
		"ZADD", "ZREM", "ZCARD", "ZCOUNT", "ZINCRBY", "ZSCORE", "ZMSCORE", "ZRANK", "ZREVRANK", "ZRANGE", "ZREVRANGE", "ZRANGEBYSCORE", "ZREVRANGEBYSCORE", "ZRANGEBYLEX", "ZREVRANGEBYLEX", "ZLEXCOUNT", "ZREMRANGEBYRANK", "ZREMRANGEBYSCORE", "ZREMRANGEBYLEX", "ZPOPMIN", "ZPOPMAX", "BZPOPMIN", "BZPOPMAX", "ZMPOP", "BZMPOP", "ZSCAN", "ZUNION", "ZUNIONSTORE", "ZINTER", "ZINTERSTORE", "ZINTERCARD", "ZDIFF", "ZDIFFSTORE", "ZRANDMEMBER", "ZRANGESTORE",
		"XADD", "XDEL", "XLEN", "XRANGE", "XREVRANGE", "XREAD", "XREADGROUP", "XGROUP", "XINFO", "XACK", "XCLAIM", "XAUTOCLAIM", "XPENDING", "XTRIM", "WATCH", "UNWATCH", "EVAL", "EVALSHA", "EVAL_RO", "EVALSHA_RO", "SCRIPT", "FCALL", "FCALL_RO", "FUNCTION",
		"PUBLISH", "SPUBLISH", "PUBSUB", "BITCOUNT", "BITOP", "BITPOS", "BITFIELD", "BITFIELD_RO", "GETBIT", "SETBIT", "PFADD", "PFCOUNT", "PFMERGE", "GEOADD", "GEODIST", "GEOHASH", "GEOPOS", "GEOSEARCH", "GEOSEARCHSTORE", "GEORADIUS", "GEORADIUSBYMEMBER",
		"INFO", "DBSIZE", "TIME", "LASTSAVE", "SAVE", "BGSAVE", "BGREWRITEAOF", "FLUSHDB", "FLUSHALL", "CONFIG", "ACL", "COMMAND", "SLOWLOG", "LATENCY", "MEMORY", "OBJECT", "WAIT", "WAITAOF", "SWAPDB", "READONLY", "READWRITE", "CLUSTER":
		return command
	default:
		return "UNKNOWN"
	}
}
