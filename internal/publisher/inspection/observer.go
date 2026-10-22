// package protocolinspection observes bounded, body-free protocol summaries.
package protocolinspection

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/observability/inspection"
)

const maxPendingOperations = 32

type protocolParser interface {
	feed(bool, []byte, *Observer)
}

// parsing is synchronous, bounded, and independent of forwarding success. a
// parser that loses attribution permanently disables itself for this visitor.
type Observer struct {
	mu        sync.Mutex
	parser    protocolParser
	protocol  inspection.Protocol
	observe   inspection.Observer
	stopped   bool
	completed []inspection.Summary
}

func New(protocol string, observe inspection.Observer) *Observer {
	if observe == nil {
		return nil
	}
	selected, valid := inspection.ParseProtocol(protocol)
	if !valid || !selected.IsTCP() {
		return nil
	}
	m := &Observer{protocol: selected, observe: observe}
	switch selected {
	case inspection.Postgres:
		m.parser = &postgresSummaryParser{client: pgSummaryFrame{startup: true}, group: 1}
	case inspection.MySQL:
		m.parser = &mysqlSummaryParser{}
	case inspection.Redis:
		m.parser = &redisSummaryParser{}
	default:
		return nil
	}
	return m
}

func (m *Observer) bytes(client bool, data []byte) {
	m.mu.Lock()
	if !m.stopped {
		m.parser.feed(client, data, m)
	}
	completed := m.completed
	m.completed = nil
	m.mu.Unlock()
	for _, summary := range completed {
		m.observe(summary)
	}
}

func (m *Observer) emit(s inspection.Summary) {
	s.Protocol = m.protocol
	s.Duration = time.Since(s.ReceivedAt)
	s.ReceivedAt = s.ReceivedAt.UTC()
	s.Rows = min(max(s.Rows, 0), inspection.MaxCount)
	s.ResultSets = min(max(s.ResultSets, 0), inspection.MaxCount)
	s.SQLState = inspection.SQLStateOrEmpty(s.SQLState)
	m.completed = append(m.completed, s)
}

// MySQLFlags applies the authenticated login's capabilities before copy starts.
func (m *Observer) MySQLFlags(flags uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.parser.(*mysqlSummaryParser)
	if !ok {
		return
	}
	p.deprecate = flags&(1<<24) != 0
	m.stopped = m.stopped || flags&((1<<5)|(1<<26)) != 0
}

type summaryConn struct {
	net.Conn
	monitor *Observer
	client  bool
}

// Wrap preserves write-half-close and observes only reads of decrypted traffic.
func Wrap(c net.Conn, m *Observer, client bool) net.Conn {
	if m == nil {
		return c
	}
	return &summaryConn{Conn: c, monitor: m, client: client}
}

func (c *summaryConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.monitor.bytes(c.client, p[:n])
	}
	return n, err
}

func (c *summaryConn) CloseWrite() error { return closeWrite(c.Conn) }

func closeWrite(connection net.Conn) error {
	if closer, ok := connection.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return errors.ErrUnsupported
}
