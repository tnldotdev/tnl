package transporttest

import (
	"testing"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
)

// QUICTransport opens one fixture-owned socket. borrowed connections close
// independently; cleanup releases the socket after the fixture's workers stop.
func QUICTransport(t testing.TB) *muxsession.QUICTransport {
	t.Helper()
	transport, err := muxsession.ListenQUICTransport("udp", ":0")
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
