//go:build tnl_benchtrace

package stream

import (
	"context"
	"fmt"
	"net"
	"runtime/trace"
	"sync"
)

const connectorBenchTraceEnabled = true
const connectorBenchTraceLimit = 128

type connectorBenchTraceIdentity struct {
	port    int
	id      uint64
	visitor string
}

// preparation retains only the validated visitor identity, never its opening.
// Forward fills the port before arming; unused preparations retire in finish.
// only this diagnostic build retains this bounded metadata.
// events describe byte-copy calls, not query boundaries; framing stays opaque.
var connectorBenchTraces struct {
	sync.Mutex
	next   uint64
	active map[*PreparedConnector]connectorBenchTraceIdentity
}

func connectorBenchTracePrepared(p *PreparedConnector, visitor string) {
	if p == nil || visitor == "" {
		return
	}
	connectorBenchTraces.Lock()
	defer connectorBenchTraces.Unlock()
	if len(connectorBenchTraces.active) >= connectorBenchTraceLimit {
		return
	}
	if _, exists := connectorBenchTraces.active[p]; exists {
		return
	}
	if connectorBenchTraces.active == nil {
		connectorBenchTraces.active = make(map[*PreparedConnector]connectorBenchTraceIdentity, connectorBenchTraceLimit)
	}
	connectorBenchTraces.active[p] = connectorBenchTraceIdentity{visitor: visitor}
}

func connectorBenchTraceRegister(p *PreparedConnector, local net.Conn) {
	if p == nil || local == nil {
		return
	}
	remote, ok := local.RemoteAddr().(*net.TCPAddr)
	if !ok || !remote.IP.IsLoopback() || remote.Port < 1 || remote.Port > 65535 {
		return
	}
	connectorBenchTraces.Lock()
	defer connectorBenchTraces.Unlock()
	identity, ok := connectorBenchTraces.active[p]
	if !ok || identity.id != 0 {
		return
	}
	connectorBenchTraces.next++
	identity.port, identity.id = remote.Port, connectorBenchTraces.next
	connectorBenchTraces.active[p] = identity
}

func connectorBenchTraceUnregister(p *PreparedConnector) {
	connectorBenchTraces.Lock()
	delete(connectorBenchTraces.active, p)
	connectorBenchTraces.Unlock()
}

func connectorBenchTraceLog(p *PreparedConnector, category string, count int, failed bool) bool {
	if !trace.IsEnabled() {
		return false
	}
	connectorBenchTraces.Lock()
	identity, ok := connectorBenchTraces.active[p]
	connectorBenchTraces.Unlock()
	if !ok || identity.id == 0 {
		return false
	}
	// log on the caller after unlocking; never retain bytes, proofs, or addresses.
	trace.Log(context.Background(), category, fmt.Sprintf("port=%d connection=%d visitor_connection_id=%s bytes=%d error=%t", identity.port, identity.id, identity.visitor, count, failed))
	return true
}
