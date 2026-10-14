package publisher

import (
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/tnldotdev/tnl/internal/inspection"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

const (
	maxPostgresInspectionFrame = 1 << 30
	maxPostgresCapturedFrame   = 16 << 10
	maxPostgresPending         = 32
)

type postgresInspectionCall struct {
	operation inspection.Operation
	started   time.Time
	rows      int64
	group     uint64
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
	observe     func(DatabaseObservation)
	completed   []DatabaseObservation
}

func newPostgresInspector(observe func(DatabaseObservation)) *postgresInspector {
	return &postgresInspector{
		client: postgresInspectionFrame{startup: true}, server: postgresInspectionFrame{capture: true},
		observe: observe, clientGroup: 1,
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

func (m *postgresInspector) onClientFrame(kind byte, _ []byte) {
	if !m.ready {
		return
	}
	switch kind {
	case 'S':
		m.clientGroup++
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
		}
		m.pending = append(m.pending, call)
	}
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
		Rows:     call.rows,
		Duration: time.Since(call.started),
	})
}
