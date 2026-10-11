package publisher

import (
	"encoding/binary"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgproto3"
	projectconfig "github.com/tnldotdev/tnl/internal/config"
)

const (
	maxPostgresInspectionFrame = 1 << 30
	maxPostgresCapturedFrame   = 16 << 10
	maxPostgresStatement       = 8 << 10
	maxPostgresPending         = 32
)

type DatabaseObservation struct {
	ReceivedAt         time.Time
	Operation          string
	Result             string
	SQLState           string
	Rows               int64
	Statement          string
	StatementTruncated bool
	Duration           time.Duration
}

// postgresInspectionConn observes copies after TLS termination. writes remain
// unchanged; the observer has fixed limits and never waits for local storage.
type postgresInspectionConn struct {
	net.Conn
	observer *postgresInspector
}

func (c *postgresInspectionConn) Write(data []byte) (int, error) {
	c.observer.clientBytes(data)
	n, err := c.Conn.Write(data)
	if err != nil || n != len(data) {
		c.observer.stop()
	}
	return n, err
}

func (c *postgresInspectionConn) Read(data []byte) (int, error) {
	n, err := c.Conn.Read(data)
	if n > 0 {
		c.observer.serverBytes(data[:n])
	}
	return n, err
}

type postgresInspectionFrame struct {
	startup bool
	header  [5]byte
	read    int
	left    int
	kind    byte
	body    []byte
	broken  bool
}

func (f *postgresInspectionFrame) feed(data []byte, onFrame func(byte, []byte)) {
	for len(data) > 0 && !f.broken {
		if f.left == 0 {
			needed := 5
			if f.startup {
				needed = 4
			}
			count := min(len(data), needed-f.read)
			copy(f.header[f.read:], data[:count])
			f.read += count
			data = data[count:]
			if f.read < needed {
				return
			}
			lengthBytes := f.header[1:5]
			if f.startup {
				lengthBytes = f.header[:4]
			}
			length := binary.BigEndian.Uint32(lengthBytes)
			if length < 4 || length > maxPostgresInspectionFrame || f.startup && (length < 8 || length > 10_000) {
				f.broken = true
				return
			}
			f.kind = f.header[0]
			f.left = int(length) - 4
			if !f.startup && f.left <= maxPostgresCapturedFrame &&
				(f.kind == 'Q' || f.kind == 'P' || f.kind == 'B' || f.kind == 'E' || f.kind == 'C' || f.kind == 'Z') {
				f.body = make([]byte, 0, f.left)
			} else {
				f.body = nil
			}
			if f.left == 0 {
				f.complete(onFrame)
			}
			continue
		}
		count := min(len(data), f.left)
		if f.body != nil {
			f.body = append(f.body, data[:count]...)
		}
		f.left -= count
		data = data[count:]
		if f.left == 0 {
			f.complete(onFrame)
		}
	}
}

func (f *postgresInspectionFrame) complete(onFrame func(byte, []byte)) {
	if !f.startup {
		onFrame(f.kind, f.body)
	}
	f.startup = false
	f.read = 0
	f.body = nil
}

type postgresInspectionCall struct {
	operation string
	statement string
	truncated bool
	started   time.Time
	rows      int64
	group     uint64
}

type postgresInspectionStatement struct {
	text      string
	truncated bool
}

type postgresInspector struct {
	mu          sync.Mutex
	client      postgresInspectionFrame
	server      postgresInspectionFrame
	ready       bool
	broken      bool
	clientGroup uint64
	serverGroup uint64
	pending     []postgresInspectionCall
	statements  map[string]postgresInspectionStatement
	portals     map[string]postgresInspectionStatement
	mode        projectconfig.RequestInspectionMode
	observe     func(DatabaseObservation)
}

func newPostgresInspector(observe func(DatabaseObservation), mode projectconfig.RequestInspectionMode) *postgresInspector {
	return &postgresInspector{
		client: postgresInspectionFrame{startup: true}, mode: mode, observe: observe,
		clientGroup: 1,
		statements:  make(map[string]postgresInspectionStatement), portals: make(map[string]postgresInspectionStatement),
	}
}

func (m *postgresInspector) stop() {
	m.mu.Lock()
	m.broken = true
	m.pending = nil
	m.mu.Unlock()
}

func (m *postgresInspector) clientBytes(data []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.broken {
		return
	}
	m.client.feed(data, m.onClientFrame)
	if m.client.broken {
		m.broken = true
		m.pending = nil
	}
}

func (m *postgresInspector) serverBytes(data []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.broken {
		return
	}
	m.server.feed(data, m.onServerFrame)
	if m.server.broken {
		m.broken = true
		m.pending = nil
	}
}

func (m *postgresInspector) onClientFrame(kind byte, data []byte) {
	if !m.ready {
		return
	}
	switch kind {
	case 'S':
		m.clientGroup++
	case 'P':
		var message pgproto3.Parse
		if data != nil && message.Decode(data) == nil {
			if len(m.statements) >= maxPostgresPending {
				clear(m.statements)
			}
			statement := postgresInspectionStatement{}
			if m.mode == projectconfig.RequestInspectionDetailed {
				statement.text, statement.truncated = boundedPostgresStatement(message.Query)
			}
			m.statements[message.Name] = statement
		} else {
			clear(m.statements)
		}
	case 'B':
		var message pgproto3.Bind
		if data != nil && message.Decode(data) == nil {
			if len(m.portals) >= maxPostgresPending {
				clear(m.portals)
			}
			m.portals[message.DestinationPortal] = m.statements[message.PreparedStatement]
		} else {
			clear(m.portals)
		}
	case 'C':
		var message pgproto3.Close
		if data != nil && message.Decode(data) == nil {
			if message.ObjectType == 'S' {
				delete(m.statements, message.Name)
			} else {
				delete(m.portals, message.Name)
			}
		}
	case 'E', 'Q':
		if len(m.pending) >= maxPostgresPending {
			m.broken = true
			m.pending = nil
			return
		}
		call := postgresInspectionCall{started: time.Now(), operation: "execute", group: m.clientGroup}
		if kind == 'Q' {
			m.clientGroup++ // a simple query has its own ReadyForQuery response.
			call.operation = "query"
			var message pgproto3.Query
			if data != nil && message.Decode(data) == nil && m.mode == projectconfig.RequestInspectionDetailed {
				call.statement, call.truncated = boundedPostgresStatement(message.String)
			}
		} else {
			var message pgproto3.Execute
			if data != nil && message.Decode(data) == nil {
				call.statement = m.portals[message.Portal].text
				call.truncated = m.portals[message.Portal].truncated
			}
		}
		m.pending = append(m.pending, call)
	}
}

func boundedPostgresStatement(statement string) (string, bool) {
	if len(statement) <= maxPostgresStatement {
		return statement, false
	}
	end := maxPostgresStatement
	for end > 0 && !utf8.RuneStart(statement[end]) {
		end--
	}
	return statement[:end], true
}

func (m *postgresInspector) onServerFrame(kind byte, data []byte) {
	if kind == 'Z' {
		if !m.ready {
			m.ready = true
			return
		}
		m.serverGroup++
		for len(m.pending) > 0 && m.pending[0].group <= m.serverGroup {
			if m.pending[0].operation == "query" {
				m.emit("ok", "")
			} else {
				m.pending = m.pending[1:] // an execution without a terminal response is unknown.
			}
		}
		return
	}
	if !m.ready || len(m.pending) == 0 {
		return
	}
	switch kind {
	case 'D':
		m.pending[0].rows++
	case 'C':
		var complete pgproto3.CommandComplete
		if data != nil && complete.Decode(data) == nil && m.pending[0].rows == 0 {
			tokens := strings.Fields(string(complete.CommandTag))
			if len(tokens) > 0 {
				if rows, err := strconv.ParseInt(tokens[len(tokens)-1], 10, 64); err == nil && rows >= 0 {
					m.pending[0].rows = rows
				}
			}
		}
		if m.pending[0].operation == "execute" {
			m.emit("ok", "")
		}
	case 'I':
		if m.pending[0].operation == "execute" {
			m.emit("ok", "")
		}
	case 'E':
		var problem pgproto3.ErrorResponse
		if data != nil && problem.Decode(data) == nil {
			group := m.pending[0].group
			m.emit("error", safePostgresSQLState(problem.Code))
			for len(m.pending) > 0 && m.pending[0].group == group {
				m.pending = m.pending[1:] // postgres ignores the rest of this group until Sync.
			}
		}
	}
}

func safePostgresSQLState(code string) string {
	if len(code) != 5 {
		return ""
	}
	for _, value := range code {
		if value < 'A' || value > 'Z' {
			if value < '0' || value > '9' {
				return ""
			}
		}
	}
	return code
}

func (m *postgresInspector) emit(result, sqlState string) {
	call := m.pending[0]
	m.pending = m.pending[1:]
	m.observe(DatabaseObservation{
		ReceivedAt: call.started, Operation: call.operation, Result: result, SQLState: sqlState,
		Rows: call.rows, Statement: call.statement, StatementTruncated: call.truncated,
		Duration: time.Since(call.started),
	})
}
