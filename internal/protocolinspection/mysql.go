package protocolinspection

import (
	"encoding/binary"
	"time"

	"github.com/tnldotdev/tnl/internal/inspection"
)

type mysqlSummaryFrame struct {
	header            [4]byte
	n, size, position int
	prefix            [32]byte
	limit             int
}

func (f *mysqlSummaryFrame) feed(data []byte, capture func(byte) int, m *Observer, done func(byte, []byte, int)) {
	for len(data) > 0 && !m.stopped {
		if f.n < 4 {
			n := copy(f.header[f.n:], data)
			f.n += n
			data = data[n:]
			if f.n < 4 {
				return
			}
			f.size = int(f.header[0]) | int(f.header[1])<<8 | int(f.header[2])<<16
			// continuation packets can wrap sequences and need a separate logical
			// framing budget. stop observation, leaving the copy path untouched.
			if f.size == 0 || f.size == 1<<24-1 {
				m.stopped = true
				return
			}
		}
		n := min(len(data), f.size-f.position)
		if f.position == 0 && len(data) > 0 {
			f.limit = capture(data[0])
		}
		limit := f.limit
		if f.position < limit {
			copy(f.prefix[f.position:limit], data[:min(n, limit-f.position)])
		}
		f.position += n
		data = data[n:]
		if f.position != f.size {
			return
		}
		done(f.header[3], f.prefix[:min(limit, f.size)], f.size)
		*f = mysqlSummaryFrame{}
	}
}

type mysqlSummaryCall struct {
	inspection.Summary
	command byte
}

type mysqlSummaryParser struct {
	client, server      mysqlSummaryFrame
	deprecate           bool
	pending             []mysqlSummaryCall
	sequence            byte
	phase               byte // 0 response, 1 columns, 2 metadata EOF, 3 rows, 4 prepare, 5 prepare EOF.
	columns, parameters int
	metadataRemaining   int
}

func (p *mysqlSummaryParser) feed(client bool, data []byte, m *Observer) {
	if client {
		p.client.feed(data, func(byte) int { return 1 }, m, func(seq byte, b []byte, size int) { p.request(seq, b, size, m) })
	} else {
		p.server.feed(data, p.capture, m, func(seq byte, b []byte, size int) { p.response(seq, b, size, m) })
	}
	if m.stopped {
		p.pending = nil
		p.client = mysqlSummaryFrame{}
		p.server = mysqlSummaryFrame{}
	}
}

func (p *mysqlSummaryParser) capture(first byte) int {
	if first == 0xff {
		return 9
	} // error number, marker, and SQLSTATE only.
	if p.phase == 0 {
		if len(p.pending) > 0 && p.pending[0].command == 0x16 {
			return 12
		}
		return 23
	}
	if first == 0xfe {
		return 23
	} // EOF/OK terminator counters and status.
	return 1 // column definitions and rows are never retained.
}

func (p *mysqlSummaryParser) request(seq byte, b []byte, size int, m *Observer) {
	if seq != 0 {
		m.stopped = true
		return
	}
	operation := inspection.Operation("")
	switch b[0] {
	case 3:
		operation = inspection.OperationQuery
	case 0x17:
		if size < 10 {
			m.stopped = true
			return
		}
		operation = inspection.OperationExecute
	case 0x16, 0x0e, 0x02, 0x1a, 0x1f, 0x1b:
	case 0x19, 0x18, 1:
		return // close, long data, and quit have no reply.
	default:
		m.stopped = true
		return
	}
	if len(p.pending) == maxPendingOperations {
		m.stopped = true
		return
	}
	if len(p.pending) == 0 {
		p.sequence = 1
	}
	p.pending = append(p.pending, mysqlSummaryCall{Summary: inspection.Summary{ReceivedAt: time.Now(), Operation: operation}, command: b[0]})
}

func (p *mysqlSummaryParser) response(seq byte, b []byte, size int, m *Observer) {
	if len(p.pending) == 0 || seq != p.sequence {
		m.stopped = true
		return
	}
	p.sequence++
	call := &p.pending[0]
	if b[0] == 0xff {
		if size < 3 {
			m.stopped = true
			return
		}
		call.MySQLErrorCode = binary.LittleEndian.Uint16(b[1:3])
		if len(b) >= 9 && b[3] == '#' {
			call.SQLState = string(b[4:9])
		}
		p.finish(inspection.ResultError, m)
		return
	}
	switch p.phase {
	case 0:
		if call.command == 0x16 {
			if size < 12 || b[0] != 0 {
				m.stopped = true
				return
			}
			p.columns, p.parameters = int(binary.LittleEndian.Uint16(b[5:7])), int(binary.LittleEndian.Uint16(b[7:9]))
			if p.columns > 256 || p.parameters > 256 {
				m.stopped = true
				return
			}
			p.prepareNext(m)
			return
		}
		if b[0] == 0 {
			affected, pos, ok := mysqlSummaryInteger(b, 1)
			if !ok {
				m.stopped = true
				return
			}
			_, pos, ok = mysqlSummaryInteger(b, pos)
			if !ok || pos+4 > len(b) {
				m.stopped = true
				return
			}
			call.Rows = min(inspection.MaxCount, call.Rows+int64(min(affected, inspection.MaxCount)))
			p.endResult(binary.LittleEndian.Uint16(b[pos:]), m)
			return
		}
		if b[0] == 0xfb {
			m.stopped = true
			return
		} // LOCAL INFILE is opaque.
		if status, ok := mysqlSummaryEnd(b, size, p.deprecate); ok {
			p.endResult(status, m)
			return
		}
		columns, pos, ok := mysqlSummaryInteger(b, 0)
		if !ok || pos != size || columns == 0 || columns > 256 {
			m.stopped = true
			return
		}
		p.columns = int(columns)
		p.phase = 1
		call.ResultSets = min(call.ResultSets+1, inspection.MaxCount)
	case 1:
		p.columns--
		if p.columns == 0 {
			p.phase = 3
			if !p.deprecate {
				p.phase = 2
			}
		}
	case 2:
		if _, ok := mysqlSummaryEnd(b, size, false); !ok {
			m.stopped = true
			return
		}
		p.phase = 3
	case 3:
		if status, ok := mysqlSummaryEnd(b, size, p.deprecate); ok {
			p.endResult(status, m)
		} else {
			call.Rows = min(call.Rows+1, inspection.MaxCount)
		}
	case 4:
		p.metadataRemaining--
		if p.metadataRemaining == 0 {
			if !p.deprecate {
				p.phase = 5
			} else {
				p.prepareNext(m)
			}
		}
	case 5:
		if _, ok := mysqlSummaryEnd(b, size, false); !ok {
			m.stopped = true
			return
		}
		p.prepareNext(m)
	}
}

func (p *mysqlSummaryParser) prepareNext(m *Observer) {
	if p.parameters > 0 {
		p.metadataRemaining = p.parameters
		p.parameters = 0
		p.phase = 4
	} else if p.columns > 0 {
		p.metadataRemaining = p.columns
		p.columns = 0
		p.phase = 4
	} else {
		p.finish(inspection.ResultOK, m)
	}
}

func (p *mysqlSummaryParser) endResult(status uint16, m *Observer) {
	if status&8 != 0 {
		p.phase = 0
	} else {
		p.finish(inspection.ResultOK, m)
	}
}

func (p *mysqlSummaryParser) finish(result inspection.Result, m *Observer) {
	call := p.pending[0]
	p.pending = p.pending[1:]
	p.phase = 0
	p.sequence = 1
	if call.Operation != "" {
		call.Result = result
		m.emit(call.Summary)
	}
}

func mysqlSummaryInteger(b []byte, pos int) (uint64, int, bool) {
	if pos >= len(b) {
		return 0, pos, false
	}
	marker := b[pos]
	pos++
	if marker < 0xfb {
		return uint64(marker), pos, true
	}
	n := 0
	switch marker {
	case 0xfc:
		n = 2
	case 0xfd:
		n = 3
	case 0xfe:
		n = 8
	default:
		return 0, pos, false
	}
	if pos+n > len(b) {
		return 0, pos, false
	}
	var value uint64
	for i := 0; i < n; i++ {
		value |= uint64(b[pos+i]) << (8 * i)
	}
	return value, pos + n, true
}

func mysqlSummaryEnd(b []byte, size int, deprecate bool) (uint16, bool) {
	if b[0] != 0xfe {
		return 0, false
	}
	if !deprecate {
		if size != 5 {
			return 0, false
		}
		return binary.LittleEndian.Uint16(b[3:5]), true
	}
	if size < 7 || size >= 1<<24-1 {
		return 0, false
	}
	_, pos, ok := mysqlSummaryInteger(b, 1)
	if !ok {
		return 0, false
	}
	_, pos, ok = mysqlSummaryInteger(b, pos)
	if !ok || pos+4 > len(b) {
		return 0, false
	}
	return binary.LittleEndian.Uint16(b[pos:]), true
}
