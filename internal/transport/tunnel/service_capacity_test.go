package tunnel

import (
	"context"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func capacitySessions(t *testing.T) (*Session, *Session) {
	t.Helper()
	left, right := newMemoryPair(t)
	client, server := &Session{transport: left, role: tunnelv1.Ingress}, &Session{transport: right, role: tunnelv1.Ingress}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- server.ServeServiceCapacity(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = server.Close()
		if err := await(t, done); err != nil {
			t.Error("capacity reader did not stop cleanly", err)
		}
	})
	return client, server
}

func TestServiceCapacityAcknowledgesOnlyRegisteredStreamOnce(t *testing.T) {
	client, server := capacitySessions(t)
	header := maximumServiceHeader("relay-a")
	var calls atomic.Int32
	release, err := server.RegisterServiceCapacity(t.Context(), header, func(context.Context) error {
		calls.Add(1)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	wrong := header
	wrong.ConnectionAssignmentRevision--
	var rejected *ProtocolError
	if err := client.RequestServiceCapacity(tunnelContext(t), wrong); !errors.As(err, &rejected) || rejected.Code != tunnelv1.StaleConnectionAssignment {
		t.Fatal("capacity request lost the exact live assignment fence", err)
	}
	if calls.Load() != 0 {
		t.Fatal("another assignment consumed capacity")
	}
	for range 2 {
		if err := client.RequestServiceCapacity(tunnelContext(t), header); err != nil {
			t.Fatal("matching stream was not acknowledged", err)
		}
	}
	if calls.Load() != 1 {
		t.Fatal("duplicate request reserved capacity again", calls.Load())
	}
	release()
	for range 2 {
		var rejected *ProtocolError
		if err := client.RequestServiceCapacity(tunnelContext(t), header); !errors.As(err, &rejected) || rejected.Code != tunnelv1.Unavailable {
			t.Fatal("closed visitor did not retain exact unavailable outcome", err)
		}
	}
	if calls.Load() != 1 || client.Err() != nil || server.Err() != nil {
		t.Fatal("closed visitor changed capacity or the healthy physical session", calls.Load(), client.Err(), server.Err())
	}
}

func TestServiceCapacityKeepsRejectedDecision(t *testing.T) {
	client, server := capacitySessions(t)
	header := maximumServiceHeader("relay-a")
	var calls atomic.Int32
	release, err := server.RegisterServiceCapacity(t.Context(), header, func(context.Context) error {
		calls.Add(1)
		return &ProtocolError{Code: tunnelv1.CapacityExceeded}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	for range 2 {
		err := client.RequestServiceCapacity(tunnelContext(t), header)
		var rejected *ProtocolError
		if !errors.As(err, &rejected) || rejected.Code != tunnelv1.CapacityExceeded {
			t.Fatal("capacity rejection was lost", err)
		}
	}
	if calls.Load() != 1 {
		t.Fatal("rejection was retried", calls.Load())
	}
}

func TestServiceCapacityUnregisterCancelsAndJoinsDecision(t *testing.T) {
	client, server := capacitySessions(t)
	header := maximumServiceHeader("relay-a")
	entered, stopped := make(chan struct{}), make(chan struct{})
	release, err := server.RegisterServiceCapacity(t.Context(), header, func(ctx context.Context) error {
		close(entered)
		<-ctx.Done()
		close(stopped)
		return context.Cause(ctx)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	result := make(chan error, 1)
	ctx := tunnelContext(t)
	go func() { result <- client.RequestServiceCapacity(ctx, header) }()
	await(t, entered)
	release()
	select {
	case <-stopped:
	default:
		t.Fatal("unregister returned before the decision joined")
	}
	if err := await(t, result); err == nil {
		t.Fatal("canceled decision was accepted")
	}
}

func TestServiceCapacityNeedsAnUnexpiredDeadline(t *testing.T) {
	client, server := capacitySessions(t)
	header := maximumServiceHeader("relay-a")
	var calls atomic.Int32
	release, err := server.RegisterServiceCapacity(t.Context(), header, func(context.Context) error {
		calls.Add(1)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if err := client.RequestServiceCapacity(t.Context(), header); err == nil {
		t.Fatal("capacity request accepted an unbounded request")
	}
	ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancel()
	if err := client.RequestServiceCapacity(ctx, header); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("capacity request revived an expired request", err)
	}
	if calls.Load() != 0 {
		t.Fatal("expired request reserved capacity")
	}
}

func TestServiceCapacityDoesNotReviveATimedOutReservation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client, server := capacitySessions(t)
		header := maximumServiceHeader("relay-a")
		var calls atomic.Int32
		release, err := server.RegisterServiceCapacity(t.Context(), header, func(ctx context.Context) error {
			calls.Add(1)
			<-ctx.Done()
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		defer release()
		ctx, cancel := context.WithTimeout(t.Context(), time.Millisecond)
		defer cancel()
		if err := client.RequestServiceCapacity(ctx, header); err == nil {
			t.Fatal("timed-out reservation succeeded")
		}
		if err := client.RequestServiceCapacity(tunnelContext(t), header); err == nil || calls.Load() != 1 {
			t.Fatal("a duplicate request revived the timed-out reservation", err, calls.Load())
		}
	})
}

func TestServiceCapacityRegistrationCopiesIngressFacts(t *testing.T) {
	client, server := capacitySessions(t)
	header := maximumServiceHeader("relay-a")
	original := header
	ingress := *header.PublicService
	original.PublicService = &ingress
	release, err := server.RegisterServiceCapacity(t.Context(), header, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	header.PublicService.IngressLeaseRevision++
	if err := client.RequestServiceCapacity(tunnelContext(t), header); err == nil {
		t.Fatal("changing caller-owned metadata changed the registered stream")
	}
	if err := client.RequestServiceCapacity(tunnelContext(t), original); err != nil {
		t.Fatal("changing caller-owned metadata removed the original stream", err)
	}
}

func TestServiceCapacityRejectsMalformedRequestWithoutClosingSession(t *testing.T) {
	client, server := capacitySessions(t)
	stream, err := client.transport.OpenStream(tunnelContext(t))
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	written := tunnelWorker(t, func() { _ = stream.Close() }, func() error {
		_, err := io.WriteString(stream, "\x00\x00\x00\x02{}")
		return err
	})
	frame, err := tunnelv1.ReadReturnFrame(stream)
	if err != nil || frame.Kind != tunnelv1.ReturnRejected || frame.Code != tunnelv1.InvalidMessage {
		t.Fatal("malformed capacity request was not rejected", err, frame)
	}
	if err := await(t, written); err != nil {
		t.Fatal(err)
	}
	header := maximumServiceHeader("relay-a")
	release, err := server.RegisterServiceCapacity(t.Context(), header, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if err := client.RequestServiceCapacity(tunnelContext(t), header); err != nil {
		t.Fatal("a malformed request broke another visitor's capacity request", err)
	}
}

type capacityCloseStream struct {
	muxsession.Stream
	failure error
}

func (s capacityCloseStream) Close() error { return errors.Join(s.Stream.Close(), s.failure) }

type capacityCloseTransport struct {
	muxsession.Session
	openFailure, acceptFailure error
}

func (s capacityCloseTransport) OpenStream(ctx context.Context) (muxsession.Stream, error) {
	stream, err := s.Session.OpenStream(ctx)
	if err == nil && s.openFailure != nil {
		stream = capacityCloseStream{stream, s.openFailure}
	}
	return stream, err
}

func (s capacityCloseTransport) AcceptStream(ctx context.Context) (muxsession.Stream, error) {
	stream, err := s.Session.AcceptStream(ctx)
	if err == nil && s.acceptFailure != nil {
		stream = capacityCloseStream{stream, s.acceptFailure}
	}
	return stream, err
}

func TestServiceCapacityPreservesStreamCloseFailures(t *testing.T) {
	for _, side := range []string{"requester", "reader"} {
		t.Run(side, func(t *testing.T) {
			left, right := newMemoryPair(t)
			failure := errors.New("capacity stream close failed")
			local := capacityCloseTransport{Session: left}
			remote := capacityCloseTransport{Session: right}
			if side == "requester" {
				local.openFailure = failure
			} else {
				remote.acceptFailure = failure
			}
			client := &Session{transport: local, role: tunnelv1.Ingress}
			server := &Session{transport: remote, role: tunnelv1.Ingress}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			served := tunnelWorker(t, cancel, func() error { return server.ServeServiceCapacity(ctx) })
			header := maximumServiceHeader("relay-a")
			release, err := server.RegisterServiceCapacity(t.Context(), header, func(context.Context) error { return nil })
			if err != nil {
				t.Fatal(err)
			}
			defer release()
			err = client.RequestServiceCapacity(tunnelContext(t), header)
			if side == "requester" && !errors.Is(err, failure) || side == "reader" && err != nil {
				t.Fatal("capacity requester lost its cleanup failure", err)
			}
			cancel()
			err = await(t, served)
			if side == "reader" && !errors.Is(err, failure) || side == "requester" && err != nil {
				t.Fatal("capacity reader lost its cleanup failure", err)
			}
		})
	}
}
