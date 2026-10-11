package publisher

import (
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgproto3"
	projectconfig "github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/inspection"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

const (
	maxPostgresInspectionFrame = 1 << 30
	maxPostgresCapturedFrame   = 16 << 10
	maxPostgresStatement       = 8 << 10
	maxPostgresPending         = 32
)

type postgresInspectionCall struct {
	operation inspection.Operation
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
	mode        projectconfig.InspectionMode
	observe     func(DatabaseObservation)
	completed   []DatabaseObservation
}

func newPostgresInspector(observe func(DatabaseObservation), mode projectconfig.InspectionMode) *postgresInspector {
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
	if m.broken {
		m.mu.Unlock()
		return
	}
	m.server.feed(data, m.onServerFrame)
	if m.server.broken {
		m.broken = true
		m.pending = nil
	}
	completed := m.completed
	m.completed = nil
	m.mu.Unlock()
	for _, observation := range completed {
		m.observe(observation)
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
			if m.mode == projectconfig.InspectionDetailed {
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
			if data != nil && message.Decode(data) == nil && m.mode == projectconfig.InspectionDetailed {
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
		var ready pgproto3.ReadyForQuery
		if data == nil || ready.Decode(data) != nil ||
			ready.TxStatus != 'I' && ready.TxStatus != 'T' && ready.TxStatus != 'E' {
			m.broken = true
			m.pending = nil
			return
		}
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
			m.emit(inspection.ResultError, inspection.SQLStateOrEmpty(problem.Code))
			for len(m.pending) > 0 && m.pending[0].group == group {
				m.pending = m.pending[1:] // postgres ignores the rest of this group until Sync.
			}
		}
	}
}

func (m *postgresInspector) emit(result inspection.Result, sqlState string) {
	call := m.pending[0]
	m.pending = m.pending[1:]
	m.completed = append(m.completed, DatabaseObservation{
		Protocol:   controlv1.Postgres,
		ReceivedAt: call.started, Operation: call.operation, Result: result, SQLState: sqlState,
		Rows: call.rows, Statement: call.statement, StatementTruncated: call.truncated,
		Duration: time.Since(call.started),
	})
}
