package publisher

import (
	"encoding/binary"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/inspection"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

const (
	mysqlMaxPayload                   = 1<<24 - 1
	mysqlMaxColumns                   = 256
	mysqlMaxPending                   = 32
	mysqlClientCapture                = 16
	mysqlServerCapture                = 64
	mysqlClientCompress               = 1 << 5
	mysqlClientDeprecateEOF           = 1 << 24
	mysqlClientZstdCompression        = 1 << 26
	mysqlServerMoreResults     uint16 = 1 << 3
)

type mysqlCall struct {
	operation         inspection.Operation
	responseSequence  byte
	started           time.Time
	rows              int64
	resultSets        int
	prepared          bool
	prepareColumns    int
	prepareParameters int
}

type mysqlPhase uint8

const (
	mysqlPhaseStart mysqlPhase = iota
	mysqlPhaseColumns
	mysqlPhaseColumnEOF
	mysqlPhaseRows
	mysqlPhasePrepareParameters
	mysqlPhasePrepareParameterEOF
	mysqlPhasePrepareColumns
	mysqlPhasePrepareColumnEOF
)

type mysqlInspector struct {
	mu              sync.Mutex
	client          mysqlFrame
	server          mysqlFrame
	observe         func(DatabaseObservation)
	deprecateEOF    bool
	disabled        bool
	serverSequence  byte
	commandSequence byte
	phase           mysqlPhase
	columns         int
	pending         []mysqlCall
	completed       []DatabaseObservation
}

func newMySQLInspector(clientFlags uint32, observe func(DatabaseObservation)) *mysqlInspector {
	return &mysqlInspector{
		client: mysqlFrame{limit: mysqlClientCapture}, server: mysqlFrame{limit: mysqlServerCapture},
		observe: observe, deprecateEOF: clientFlags&mysqlClientDeprecateEOF != 0,
		disabled:       clientFlags&(mysqlClientCompress|mysqlClientZstdCompression) != 0,
		serverSequence: 1,
	}
}

func (m *mysqlInspector) clientBytes(data []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.disabled {
		m.client.feed(data, m.onClientPacket)
		if m.client.broken {
			m.stopLocked()
		}
	}
}

func (m *mysqlInspector) serverBytes(data []byte) {
	m.mu.Lock()
	if !m.disabled {
		m.server.feed(data, m.onServerPacket)
		if m.server.broken {
			m.stopLocked()
		}
	}
	completed := m.completed
	m.completed = nil
	m.mu.Unlock()
	for _, observation := range completed {
		m.observe(observation)
	}
}

func (m *mysqlInspector) onClientPacket(sequence byte, data []byte, _ int64, frames int) {
	if sequence != 0 || len(data) == 0 {
		m.stopLocked()
		return
	}
	m.commandSequence = byte(frames)
	command := data[0]
	switch command {
	case 0x16: // COM_STMT_PREPARE
		m.add(mysqlCall{prepared: true, started: time.Now()})
	case 0x17: // COM_STMT_EXECUTE
		if len(data) < 5 {
			m.stopLocked()
			return
		}
		m.add(mysqlCall{started: time.Now(), operation: "execute"})
	case 0x03: // COM_QUERY
		m.add(mysqlCall{started: time.Now(), operation: "query"})
	case 0x19: // COM_STMT_CLOSE, with no server response.
		if len(data) < 5 {
			m.stopLocked()
		}
	case 0x18: // COM_STMT_SEND_LONG_DATA has no server response.
	case 0x01: // COM_QUIT has no server response.
	case 0x0e, 0x02, 0x1a, 0x1f, 0x1b: // PING, INIT_DB, STMT_RESET, RESET_CONNECTION, SET_OPTION.
		m.add(mysqlCall{started: time.Now()})
	default:
		m.stopLocked() // an unknown response would desynchronize later executions.
	}
}

func (m *mysqlInspector) add(call mysqlCall) {
	if len(m.pending) >= mysqlMaxPending {
		m.stopLocked()
		return
	}
	call.responseSequence = m.commandSequence
	if len(m.pending) == 0 {
		m.serverSequence = call.responseSequence
	}
	m.pending = append(m.pending, call)
}

func (m *mysqlInspector) stopLocked() {
	m.disabled = true
	m.pending = nil
}

func (m *mysqlInspector) onServerPacket(sequence byte, data []byte, size int64, frames int) {
	if len(m.pending) == 0 {
		m.stopLocked()
		return
	}
	if sequence != m.serverSequence || len(data) == 0 {
		m.stopLocked()
		return
	}
	m.serverSequence += byte(frames)
	call := &m.pending[0]
	if data[0] == 0xff {
		if size < 3 || len(data) < 3 {
			m.stopLocked()
			return
		}
		code := binary.LittleEndian.Uint16(data[1:3])
		state := ""
		if len(data) >= 9 && data[3] == '#' {
			state = inspection.SQLStateOrEmpty(string(data[4:9]))
		}
		m.finish("error", code, state)
		return
	}
	switch m.phase {
	case mysqlPhaseStart:
		m.startResponse(call, data, size)
	case mysqlPhaseColumns, mysqlPhasePrepareParameters, mysqlPhasePrepareColumns:
		m.columnDefinition(call)
	case mysqlPhaseColumnEOF, mysqlPhasePrepareParameterEOF, mysqlPhasePrepareColumnEOF:
		m.metadataEnd(call, data, size)
	case mysqlPhaseRows:
		m.resultRow(call, data, size)
	}
}

func (m *mysqlInspector) startResponse(call *mysqlCall, data []byte, size int64) {
	if call.operation == "" && !call.prepared && data[0] == 0xfe {
		if _, ok := mysqlTerminator(data, size, m.deprecateEOF); ok {
			m.finish(inspection.ResultOK, 0, "")
			return
		}
	}
	if call.prepared {
		m.prepareResponse(call, data, size)
		return
	}
	if data[0] == 0x00 {
		m.okResult(data)
		return
	}
	if data[0] == 0xfb {
		m.stopLocked() // LOCAL INFILE has a separate client upload exchange.
		return
	}
	columns, next, ok := mysqlLenEnc(data, 0)
	if !ok || next != int(size) || columns == 0 || columns > mysqlMaxColumns {
		m.stopLocked()
		return
	}
	call.resultSets++
	m.columns = int(columns)
	m.phase = mysqlPhaseColumns
}

func (m *mysqlInspector) prepareResponse(call *mysqlCall, data []byte, size int64) {
	if data[0] != 0 || size < 12 || len(data) < 12 {
		m.stopLocked()
		return
	}
	call.prepareColumns = int(binary.LittleEndian.Uint16(data[5:7]))
	call.prepareParameters = int(binary.LittleEndian.Uint16(data[7:9]))
	if call.prepareColumns > mysqlMaxColumns || call.prepareParameters > mysqlMaxColumns {
		m.stopLocked()
		return
	}
	m.advancePrepare(call)
}

func (m *mysqlInspector) columnDefinition(call *mysqlCall) {
	switch m.phase {
	case mysqlPhaseColumns:
		m.columns--
		if m.columns == 0 {
			m.phase = mysqlPhaseRows
			if !m.deprecateEOF {
				m.phase = mysqlPhaseColumnEOF
			}
		}
	case mysqlPhasePrepareParameters:
		call.prepareParameters--
		if call.prepareParameters == 0 {
			m.phase = mysqlPhasePrepareParameterEOF
			if m.deprecateEOF {
				m.advancePrepare(call)
			}
		}
	case mysqlPhasePrepareColumns:
		call.prepareColumns--
		if call.prepareColumns == 0 {
			m.phase = mysqlPhasePrepareColumnEOF
			if m.deprecateEOF {
				m.finishPrepare()
			}
		}
	}
}

func (m *mysqlInspector) metadataEnd(call *mysqlCall, data []byte, size int64) {
	if _, ok := mysqlTerminator(data, size, false); !ok {
		m.stopLocked()
		return
	}
	switch m.phase {
	case mysqlPhaseColumnEOF:
		m.phase = mysqlPhaseRows
	case mysqlPhasePrepareParameterEOF:
		m.advancePrepare(call)
	default:
		m.finishPrepare()
	}
}

func (m *mysqlInspector) resultRow(call *mysqlCall, data []byte, size int64) {
	if status, ok := mysqlTerminator(data, size, m.deprecateEOF); ok {
		if status&mysqlServerMoreResults != 0 {
			m.phase = mysqlPhaseStart
		} else {
			m.finish(inspection.ResultOK, 0, "")
		}
		return
	}
	call.rows++
}

func (m *mysqlInspector) advancePrepare(call *mysqlCall) {
	if call.prepareParameters > 0 {
		m.phase = mysqlPhasePrepareParameters
		return
	}
	if call.prepareColumns > 0 {
		m.phase = mysqlPhasePrepareColumns
		return
	}
	m.finishPrepare()
}

func (m *mysqlInspector) finishPrepare() {
	m.pending = m.pending[1:]
	m.phase = mysqlPhaseStart
	m.nextResponseSequence()
}

func (m *mysqlInspector) okResult(data []byte) {
	if len(data) < 7 {
		m.stopLocked()
		return
	}
	affected, pos, ok := mysqlLenEnc(data, 1)
	if !ok {
		m.stopLocked()
		return
	}
	_, pos, ok = mysqlLenEnc(data, pos)
	if !ok || pos+4 > len(data) {
		m.stopLocked()
		return
	}
	if affected > 0 && affected <= uint64(^uint64(0)>>1)-uint64(m.pending[0].rows) {
		m.pending[0].rows += int64(affected)
	}
	status := binary.LittleEndian.Uint16(data[pos:])
	if status&mysqlServerMoreResults != 0 {
		m.phase = mysqlPhaseStart
	} else {
		m.finish("ok", 0, "")
	}
}

func (m *mysqlInspector) finish(result inspection.Result, code uint16, state string) {
	call := m.pending[0]
	m.pending = m.pending[1:]
	m.phase = mysqlPhaseStart
	m.nextResponseSequence()
	if call.operation == "" || call.prepared {
		return
	}
	m.completed = append(m.completed, DatabaseObservation{
		Protocol: controlv1.Mysql, ReceivedAt: call.started, Operation: call.operation,
		Result: result, SQLState: state, MySQLErrorCode: code, Rows: call.rows,
		ResultSets: call.resultSets,
		Duration:   time.Since(call.started),
	})
}

func (m *mysqlInspector) nextResponseSequence() {
	m.serverSequence = 1
	if len(m.pending) != 0 {
		m.serverSequence = m.pending[0].responseSequence
	}
}

func mysqlLenEnc(data []byte, start int) (uint64, int, bool) {
	if start >= len(data) {
		return 0, start, false
	}
	switch marker := data[start]; {
	case marker <= 0xfa:
		return uint64(marker), start + 1, true
	case marker == 0xfc:
		if start+3 > len(data) {
			return 0, start, false
		}
		return uint64(binary.LittleEndian.Uint16(data[start+1:])), start + 3, true
	case marker == 0xfd:
		if start+4 > len(data) {
			return 0, start, false
		}
		return uint64(data[start+1]) | uint64(data[start+2])<<8 | uint64(data[start+3])<<16, start + 4, true
	case marker == 0xfe:
		if start+9 > len(data) {
			return 0, start, false
		}
		return binary.LittleEndian.Uint64(data[start+1:]), start + 9, true
	default:
		return 0, start, false
	}
}

func mysqlTerminator(data []byte, size int64, deprecateEOF bool) (uint16, bool) {
	if len(data) == 0 || data[0] != 0xfe || size >= mysqlMaxPayload {
		return 0, false
	}
	if !deprecateEOF {
		if size != 5 || len(data) < 5 {
			return 0, false
		}
		return binary.LittleEndian.Uint16(data[3:5]), true
	}
	_, pos, ok := mysqlLenEnc(data, 1)
	if !ok {
		return 0, false
	}
	_, pos, ok = mysqlLenEnc(data, pos)
	if !ok || pos+4 > len(data) {
		return 0, false
	}
	return binary.LittleEndian.Uint16(data[pos:]), true
}
