package transporttest

import (
	"testing"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
)

// QUICTransport opens one fixture-owned IPv4 socket. a dual-stack wildcard can
// reuse an IPv4 listener's port on macOS and receive no replies. keep the IPv4
// wildcard for separated-container peers; cleanup follows the worker joins.
func QUICTransport(t testing.TB) *muxsession.QUICTransport {
	t.Helper()
	transport, err := muxsession.ListenQUICTransport("udp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := transport.Close(); err != nil {
			t.Error(err)
		}
	})
	return transport
}
