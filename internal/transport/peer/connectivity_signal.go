package peer

import (
	"context"
	"errors"
	"io"
	"net"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type connectivitySignal struct {
	message tunnelv1.ConnectorPeerConnectivity
	err     error
}

type connectivityInterrupted struct{ cause error }

func (*connectivityInterrupted) Error() string   { return "direct UDP signaling attempt interrupted" }
func (e *connectivityInterrupted) Unwrap() error { return e.cause }

func connectivitySignalError(err error) error {
	var stream *quic.StreamError
	var network net.Error
	if errors.As(err, &stream) || errors.As(err, &network) && network.Timeout() || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return &connectivityInterrupted{cause: err}
	}
	return connectivityInvalid(err)
}

func connectivityWasInterrupted(err error) bool {
	var interrupted *connectivityInterrupted
	return errors.As(err, &interrupted)
}

// one reader owns signaling for the entire retained session, including rebinds.
// one queued message and transport stream credit bound the authenticated sender.
func readConnectivitySignals(ctx context.Context, connection *quic.Conn, output chan<- connectivitySignal) {
	for {
		message, err := readConnectivitySignal(ctx, connection)
		select {
		case <-ctx.Done():
			return
		case output <- connectivitySignal{message, err}:
		}
		if err != nil && !connectivityWasInterrupted(err) {
			return
		}
	}
}

func writeConnectivitySignal(ctx context.Context, connection *quic.Conn, message tunnelv1.ConnectorPeerConnectivity) (retErr error) {
	out, err := connection.OpenUniStreamSync(ctx)
	if err != nil {
		return err
	}
	stop := interruptOnCancel(ctx, func() error { out.CancelWrite(0); return nil })
	defer stop()
	defer func() {
		if retErr != nil {
			out.CancelWrite(0)
		}
	}()
	if err := tunnelv1.WriteConnectorPeerConnectivity(out, message); err != nil {
		return err
	}
	return out.Close()
}

func readConnectivitySignal(ctx context.Context, connection *quic.Conn) (message tunnelv1.ConnectorPeerConnectivity, retErr error) {
	in, err := connection.AcceptUniStream(ctx)
	if err != nil {
		return message, err
	}
	stop := interruptOnCancel(ctx, func() error { in.CancelRead(0); return nil })
	defer stop()
	defer in.CancelRead(0)
	// an idle peer may never open another stream. once opened, require a bounded
	// frame and EOF without allowing partial input to hold a worker indefinitely.
	if err := in.SetReadDeadline(time.Now().Add(connectivitySetupTimeout)); err != nil {
		return message, err
	}
	message, err = tunnelv1.ReadConnectorPeerConnectivity(in)
	if err != nil {
		return message, connectivitySignalError(err)
	}
	var extra [1]byte
	if n, err := in.Read(extra[:]); n != 0 || !errors.Is(err, io.EOF) {
		return message, connectivitySignalError(errors.Join(tunnelv1.ErrConnectorPeerConnectivity, err))
	}
	return message, nil
}
