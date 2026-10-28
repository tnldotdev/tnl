package peer

import (
	"context"
	"errors"
	"io"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type connectivitySignal struct {
	message tunnelv1.NativePeerConnectivity
	err     error
}

// one dedicated reader owns all signaling streams for the inner connection. a
// one-entry channel bounds queued offers/answers; each stream contains one frame.
func readConnectivitySignals(ctx context.Context, connection *quic.Conn, binding ConnectivityBinding, output chan<- connectivitySignal) {
	var previous uint64
	for {
		message, err := readConnectivitySignal(ctx, connection)
		if err == nil && (message.PairID != binding.PairID || message.DeliveryID != binding.DeliveryID || message.DeliveryGeneration != binding.Generation) {
			err = &ConnectivityError{Code: tunnelv1.Unauthenticated, Cause: tunnelv1.ErrNativePeerConnectivity}
		}
		if err == nil && message.Attempt <= previous {
			err = &ConnectivityError{Code: tunnelv1.InvalidMessage, Cause: tunnelv1.ErrNativePeerConnectivity}
		}
		previous = message.Attempt
		select {
		case <-ctx.Done():
			return
		case output <- connectivitySignal{message, err}:
		}
		if err != nil {
			return
		}
	}
}

func nextConnectivitySignal(ctx context.Context, input <-chan connectivitySignal) (tunnelv1.NativePeerConnectivity, error) {
	select {
	case <-ctx.Done():
		return tunnelv1.NativePeerConnectivity{}, context.Cause(ctx)
	case signal := <-input:
		return signal.message, signal.err
	}
}

func writeConnectivitySignal(ctx context.Context, connection *quic.Conn, message tunnelv1.NativePeerConnectivity) (retErr error) {
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
	if err := tunnelv1.WriteNativePeerConnectivity(out, message); err != nil {
		return err
	}
	return out.Close()
}

func readConnectivitySignal(ctx context.Context, connection *quic.Conn) (message tunnelv1.NativePeerConnectivity, retErr error) {
	in, err := connection.AcceptUniStream(ctx)
	if err != nil {
		return message, err
	}
	stop := interruptOnCancel(ctx, func() error { in.CancelRead(0); return nil })
	defer stop()
	defer in.CancelRead(0)
	// an idle peer need not send another offer. once it opens a stream, bound
	// the entire frame and EOF read independently of its claimed attempt number.
	if err := in.SetReadDeadline(time.Now().Add(connectivitySetupTimeout)); err != nil {
		return message, err
	}
	message, err = tunnelv1.ReadNativePeerConnectivity(in)
	if err != nil {
		return message, &ConnectivityError{Code: tunnelv1.InvalidMessage, Cause: err}
	}
	var extra [1]byte
	if n, err := in.Read(extra[:]); n != 0 || !errors.Is(err, io.EOF) {
		return message, &ConnectivityError{Code: tunnelv1.InvalidMessage, Cause: errors.Join(tunnelv1.ErrNativePeerConnectivity, err)}
	}
	return message, nil
}
