package inspection

import (
	"encoding/binary"
	"time"

	"github.com/tnldotdev/tnl/internal/observability/inspection"
)

// no frontend payload is captured, including startup and password messages.
type pgSummaryFrame struct {
	startup    bool
	header     [5]byte
	n          int
	size       int
	position   int
	kind       byte
	state      [5]byte
	stateN     int
	stateValid bool
	field      byte
	fieldStart bool
	number     int64
	ready      byte
	auth       [4]byte
}

func (f *pgSummaryFrame) feed(data []byte, client bool, m *Observer, done func(*pgSummaryFrame)) {
	for len(data) > 0 && !m.stopped {
		want := 5
		if f.startup {
			want = 4
		}
		if f.n < want {
			n := copy(f.header[f.n:want], data)
			f.n += n
			data = data[n:]
			if f.n < want {
				return
			}
			length := binary.BigEndian.Uint32(f.header[1:])
			f.kind = f.header[0]
			if f.startup {
				length = binary.BigEndian.Uint32(f.header[:4])
				f.kind = 0
			}
			if length < 4 || length > 64<<20 {
				m.stopped = true
				return
			}
			f.size = int(length) - 4
			f.fieldStart = true
		}
		n := min(len(data), f.size-f.position)
		if !client {
			for _, b := range data[:n] {
				switch f.kind {
				case 'E':
					if f.fieldStart {
						f.field = b
						f.fieldStart = false
						f.stateN = 0
					} else if b == 0 {
						f.fieldStart = true
						if f.field == 'C' {
							f.stateValid = f.stateN == 5
						}
					} else if f.field == 'C' {
						if f.stateN < len(f.state) {
							f.state[f.stateN] = b
						}
						f.stateN++
					}
				case 'C':
					if b >= '0' && b <= '9' {
						f.number = min(inspection.MaxCount, f.number*10+int64(b-'0'))
					} else if b != 0 {
						f.number = 0
					}
				case 'Z':
					f.ready = b
				case 'R':
					if f.position < 4 {
						f.auth[f.position] = b
					}
				}
				f.position++
			}
		} else {
			f.position += n
		}
		data = data[n:]
		if f.position != f.size {
			return
		}
		done(f)
		*f = pgSummaryFrame{}
	}
}

type pgSummaryCall struct {
	inspection.Summary
	group       uint64
	currentRows int64
}

type postgresSummaryParser struct {
	client, server       pgSummaryFrame
	authenticated, ready bool
	group, serverGroup   uint64
	pending              []pgSummaryCall
}

func (p *postgresSummaryParser) feed(client bool, data []byte, m *Observer) {
	if client {
		p.client.feed(data, true, m, func(f *pgSummaryFrame) { p.request(f, m) })
	} else {
		p.server.feed(data, false, m, func(f *pgSummaryFrame) { p.response(f, m) })
	}
	if m.stopped {
		p.pending = nil
		p.client = pgSummaryFrame{}
		p.server = pgSummaryFrame{}
	}
}

func (p *postgresSummaryParser) request(f *pgSummaryFrame, m *Observer) {
	if !p.ready {
		return
	}
	switch f.kind {
	case 'Q', 'E':
		if len(p.pending) == maxPendingOperations {
			m.stopped = true
			return
		}
		operation := inspection.OperationExecute
		if f.kind == 'Q' {
			operation = inspection.OperationQuery
		}
		p.pending = append(p.pending, pgSummaryCall{Summary: inspection.Summary{ReceivedAt: time.Now(), Operation: operation}, group: p.group})
		if f.kind == 'Q' {
			p.group++
		}
	case 'S':
		p.group++
	case 'P', 'B', 'D', 'C', 'H', 'X':
	default:
		m.stopped = true
	}
}

func (p *postgresSummaryParser) response(f *pgSummaryFrame, m *Observer) {
	if !p.ready {
		if f.kind == 'R' && f.size == 4 && binary.BigEndian.Uint32(f.auth[:]) == 0 {
			p.authenticated = true
		}
		if f.kind == 'Z' && f.size == 1 && p.authenticated {
			p.ready = true
		}
		return
	}
	if f.kind == 'G' || f.kind == 'H' || f.kind == 'W' {
		m.stopped = true
		return
	}
	switch f.kind {
	case 'Z', 'D', 'C', 'I', 'E', 's', 'T', '1', '2', '3', 'n', 't', 'N', 'A', 'S', 'K':
	default:
		m.stopped = true
		return
	}
	if f.kind == 'Z' {
		if f.size != 1 || f.ready != 'I' && f.ready != 'T' && f.ready != 'E' {
			m.stopped = true
			return
		}
		p.serverGroup++
		for len(p.pending) > 0 && p.pending[0].group <= p.serverGroup {
			call := p.pending[0]
			p.pending = p.pending[1:]
			if call.Operation == inspection.OperationQuery {
				if call.Result == "" {
					call.Result = inspection.ResultOK
				}
				m.emit(call.Summary)
			}
		}
		return
	}
	if len(p.pending) == 0 {
		return
	}
	call := &p.pending[0]
	// a Parse/Bind-only group can fail without an execution. never attach its
	// ErrorResponse (or any row/completion) to a pipelined later group.
	if call.group != p.serverGroup+1 {
		return
	}
	switch f.kind {
	case 'D':
		call.Rows = min(call.Rows+1, inspection.MaxCount)
		call.currentRows = min(call.currentRows+1, inspection.MaxCount)
	case 'C':
		// command tags report affected rows even when no DataRow was sent.
		if call.currentRows == 0 {
			call.Rows = min(call.Rows+f.number, inspection.MaxCount)
		}
		call.currentRows = 0
		call.ResultSets = min(call.ResultSets+1, inspection.MaxCount)
		if call.Operation == inspection.OperationExecute {
			call.Result = inspection.ResultOK
			m.emit(call.Summary)
			p.pending = p.pending[1:]
		}
	case 's', 'I':
		if call.Operation == inspection.OperationExecute {
			call.Result = inspection.ResultOK
			m.emit(call.Summary)
			p.pending = p.pending[1:]
		}
	case 'E':
		call.Result = inspection.ResultError
		if f.stateValid {
			call.SQLState = string(f.state[:])
		}
		group := call.group
		if call.Operation == inspection.OperationExecute {
			m.emit(call.Summary)
			p.pending = p.pending[1:]
		}
		// after an extended-query error the target ignores messages until Sync.
		for len(p.pending) > 0 && p.pending[0].group == group && p.pending[0].Operation == inspection.OperationExecute {
			p.pending = p.pending[1:]
		}
	}
}
