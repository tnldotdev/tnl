package peer

import (
	"bytes"
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type admissionDatagrams struct {
	recordingDatagrams
	in chan []byte
}

func (d admissionDatagrams) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case b := <-d.in:
		return b, nil
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	}
}

func TestPeerAdmissionRejectsDataBeforeSharedDatagramQueues(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	transport := admissionDatagrams{recordingDatagrams{make(chan []byte, 4)}, make(chan []byte, 4)}
	owner, err := NewSharedDatagrams(ctx, transport)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	a, b := sharedBinding(t, 1, RelayA)
	var active atomic.Bool
	b.AdmitPacket = func(p tunnelv1.PeerPacket) bool { return active.Load() || p.Kind != tunnelv1.PeerData }
	carrier, err := owner.Register(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := carrier.Send(ctx, signedFrame(t, b)); err != nil {
		t.Fatal("prepared data entered the egress queue", err)
	}
	if queued, _, _ := owner.QueueStats(); queued != 0 || len(transport.sent) != 0 {
		t.Fatal("prepared data entered the egress queue")
	}
	frame := func(sequence uint64, probe bool) []byte {
		packet := tunnelv1.PeerPacket{Kind: tunnelv1.PeerData, Sender: a.Role, Path: a.Path, Sequence: sequence, Total: 1, Payload: []byte{7}}
		if probe {
			packet.Kind, packet.Total, packet.Payload = tunnelv1.PeerProbe, 16, make([]byte, 16)
		}
		return signedPacket(t, a, packet)
	}
	incoming := func(packet []byte) {
		t.Helper()
		wire, err := a.Delivery.Seal(tunnelv1.PeerDeliveryDatagram, a.Key, packet)
		if err != nil {
			t.Fatal(err)
		}
		transport.in <- wire
	}
	incoming(frame(1, false))
	probe := frame(2, true)
	incoming(probe)
	if got, err := carrier.Receive(ctx); err != nil || !bytes.Equal(got, probe) {
		t.Fatal("prepared data entered the input queue ahead of a probe", err)
	}
	active.Store(true)
	data := frame(3, false)
	incoming(data)
	if got, err := carrier.Receive(ctx); err != nil || !bytes.Equal(got, data) {
		t.Fatal("activation released data admitted while prepared", err)
	}
	if err := carrier.Send(ctx, signedFrame(t, b)); err != nil {
		t.Fatal("active output stayed fenced", err)
	}
}

func TestPeerStreamAuthorityPauseDropsPacketsWithoutRetiringFraming(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	serverTLS, clientTLS := peerTLS(t)
	left, right := sharedTLSPair(t, ctx, serverTLS, clientTLS)
	sender, err := NewSharedStreams(ctx, left)
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	receiver, err := NewSharedStreams(ctx, right)
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	a, b := sharedBinding(t, 1, RelayA)
	var active atomic.Bool
	b.AdmitPacket = func(packet tunnelv1.PeerPacket) bool { return active.Load() || packet.Kind != tunnelv1.PeerData }
	aPair, err := sender.Register(a)
	if err != nil {
		t.Fatal(err)
	}
	bPair, err := receiver.Register(b)
	if err != nil {
		t.Fatal(err)
	}
	out, in := aPair.Carrier(true), bPair.Carrier(false)
	frame := func(binding PairBinding, sequence uint64, probe bool) []byte {
		packet := tunnelv1.PeerPacket{Kind: tunnelv1.PeerData, Sender: binding.Role, Path: binding.Path, Sequence: sequence, Total: 1, Payload: []byte{7}}
		if probe {
			packet.Kind, packet.Total, packet.Payload = tunnelv1.PeerProbe, 16, make([]byte, 16)
		}
		return signedPacket(t, binding, packet)
	}
	check := func(source, destination Carrier, payload []byte) {
		t.Helper()
		if err := source.Send(ctx, payload); err != nil {
			t.Fatal(err)
		}
		if got, err := destination.Receive(ctx); err != nil || !bytes.Equal(got, payload) {
			t.Fatal("retained packet stream lost framing or released paused data", err)
		}
	}
	check(out, in, frame(a, 1, true))
	if err := out.Send(ctx, frame(a, 2, false)); err != nil {
		t.Fatal(err)
	}
	check(out, in, frame(a, 3, true))
	if err := in.Send(ctx, frame(b, 1, false)); err != nil {
		t.Fatal("paused egress retired its stream", err)
	}
	check(in, out, frame(b, 2, true))
	active.Store(true)
	check(out, in, frame(a, 4, false))
	check(in, out, frame(b, 3, false))
}

func TestPeerAdmissionRejectsPreparedStreamIntroductionBeforeQueue(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	serverTLS, clientTLS := peerTLS(t)
	left, right := sharedTLSPair(t, ctx, serverTLS, clientTLS)
	owner, err := NewDispatchedSharedStreams(ctx, right)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	a, b := sharedBinding(t, 1, RelayA)
	var active atomic.Bool
	b.AdmitPacket = func(p tunnelv1.PeerPacket) bool { return active.Load() || p.Kind != tunnelv1.PeerData }
	pair, err := owner.Register(b)
	if err != nil {
		t.Fatal(err)
	}
	defer pair.Close()
	introduce := func(frame []byte) {
		t.Helper()
		out, err := left.OpenStream(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer out.Close()
		in, err := right.AcceptStream(ctx)
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		go func() { defer close(done); owner.AcceptIntroduction(ctx, in) }()
		header, err := a.Delivery.Header()
		if err == nil {
			_, err = out.Write(header[:])
		}
		if err == nil {
			wire, sealErr := a.Delivery.Seal(tunnelv1.PeerDeliveryStream, a.Key, frame)
			err = sealErr
			if err == nil {
				err = tunnelv1.WritePeerDeliveryFrame(out, wire, tunnelv1.PeerDeliveryStream, a.Key)
			}
		}
		if err != nil {
			t.Fatal(err)
		}
		awaitEndpointSignal(t, ctx, done)
	}
	introduce(signedFrame(t, a))
	active.Store(true)
	if len(pair.pending) != 0 || pair.active != nil {
		t.Fatal("prepared stream data gained authority after activation")
	}
	introduce(signedFrame(t, a))
	carrier, err := pair.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := carrier.Receive(ctx); err != nil || !bytes.Equal(got, signedFrame(t, a)) {
		t.Fatal("active stream admission failed", err)
	}
}
