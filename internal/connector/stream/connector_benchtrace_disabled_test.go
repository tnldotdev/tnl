//go:build !tnl_benchtrace

package stream

import (
	"net"
	"testing"
)

type noBenchTraceAddress struct{ net.Conn }

func (noBenchTraceAddress) RemoteAddr() net.Addr { panic("release hook inspected an address") }

func TestConnectorBenchTraceReleaseHooksAreNoops(t *testing.T) {
	if connectorBenchTraceEnabled {
		t.Fatal("release build enabled diagnostic hooks")
	}
	p := &PreparedConnector{}
	local := noBenchTraceAddress{}
	allocations := testing.AllocsPerRun(100, func() {
		connectorBenchTracePrepared(p, "unused-visitor-identity")
		connectorBenchTraceRegister(p, local)
		if connectorBenchTraceLog(p, "unused", 1, false) {
			t.Error("release hook emitted an event")
		}
		connectorBenchTraceUnregister(p)
	})
	if allocations != 0 {
		t.Fatalf("release hooks allocated: %g", allocations)
	}
}
