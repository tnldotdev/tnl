//go:build !tnl_benchtrace

package stream

import "net"

const connectorBenchTraceEnabled = false

func connectorBenchTracePrepared(*PreparedConnector, string)   {}
func connectorBenchTraceRegister(*PreparedConnector, net.Conn) {}
func connectorBenchTraceUnregister(*PreparedConnector)         {}
func connectorBenchTraceLog(*PreparedConnector, string, int, bool) bool {
	return false
}
