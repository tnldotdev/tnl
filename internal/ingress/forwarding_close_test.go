package ingress

import (
	"context"
	"testing"
	"testing/synctest"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
)

type closingRelayConnector struct{ started, stopping, release chan struct{} }

func (c *closingRelayConnector) Credential() string { return forwardingClusterSecret }
func (c *closingRelayConnector) Connect(ctx context.Context, _ relayTarget) (muxsession.Session, error) {
	close(c.started)
	<-ctx.Done()
	close(c.stopping)
	<-c.release
	return nil, context.Cause(ctx)
}

func TestForwarderCloseJoinsCanceledSetup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		connector := &closingRelayConnector{make(chan struct{}), make(chan struct{}), make(chan struct{})}
		forwarder := newForwarder(connector)
		requestDone := make(chan struct{})
		go func() {
			defer close(requestDone)
			_, _, _ = forwarder.session(t.Context(), relayTarget{relayID: "relay_1"})
		}()
		<-connector.started
		closed := make(chan struct{})
		go func() { defer close(closed); _ = forwarder.Close() }()
		<-connector.stopping
		synctest.Wait()
		select {
		case <-closed:
			t.Error("Close returned before connection setup joined")
		default:
		}
		close(connector.release)
		<-closed
		<-requestDone
	})
}
