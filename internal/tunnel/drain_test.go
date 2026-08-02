package tunnel

import (
	"context"
	"errors"
	"sync"
	"testing"
	"testing/synctest"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestSessionPublisherDrainHandshake(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client, server := newAuthenticatedPair(t)
		ctx := tunnelContext(t)
		started, release := make(chan struct{}), make(chan struct{})
		unblock := sync.OnceFunc(func() { close(release) })
		serverDone := tunnelWorker(t, func() { unblock(); _ = server.Close() }, func() error {
			return server.HandlePublisherDrain(ctx, func(context.Context) error { close(started); <-release; return nil })
		})
		clientDone := tunnelWorker(t, func() { unblock(); _ = client.Close() }, func() error { return client.RequestPublisherDrain(ctx, "request_drain_1") })
		await(t, started)
		synctest.Wait()
		select {
		case err := <-clientDone:
			t.Fatalf("returned before callback completed: %v", err)
		default:
		}
		unblock()
		if err := await(t, serverDone); err != nil {
			t.Fatal(err)
		}
		if err := await(t, clientDone); err != nil {
			t.Fatal(err)
		}
	})
}

func TestSessionPublisherDrainRejectsUnexpectedResponses(t *testing.T) {
	for _, test := range []struct {
		name     string
		response tunnelv1.Message
	}{
		{"mismatched request ID", tunnelv1.Message{Type: tunnelv1.Draining, ProtocolVersion: 1, RequestID: "request_other"}},
		{"unexpected type", tunnelv1.Message{Type: tunnelv1.Drained, ProtocolVersion: 1, RequestID: "request_drain_1"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, server := newAuthenticatedPair(t)
			done := tunnelWorker(t, func() { _ = server.Close() }, func() error {
				request, err := tunnelv1.ReadControl(server.control)
				if err == nil && (request.Type != tunnelv1.Drain || request.RequestID != "request_drain_1") {
					err = errors.New("unexpected drain request")
				}
				if err == nil {
					err = tunnelv1.WriteControl(server.control, test.response)
				}
				return err
			})
			if err := client.RequestPublisherDrain(tunnelContext(t), "request_drain_1"); err == nil {
				t.Fatal("unexpected response accepted")
			}
			if err := await(t, done); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSessionPublisherDrainPreservesProtocolError(t *testing.T) {
	client, server := newAuthenticatedPair(t)
	done := tunnelWorker(t, func() { _ = server.Close() }, func() error {
		request, err := tunnelv1.ReadControl(server.control)
		if err == nil {
			err = tunnelv1.WriteControl(server.control, tunnelv1.Message{Type: tunnelv1.Error, ProtocolVersion: 1, RequestID: request.RequestID, Code: tunnelv1.Internal})
		}
		return err
	})
	err := client.RequestPublisherDrain(tunnelContext(t), "request_drain_1")
	var p *ProtocolError
	if !errors.As(err, &p) || p.Code != tunnelv1.Internal {
		t.Fatalf("drain=%v", err)
	}
	if err := await(t, done); err != nil {
		t.Fatal(err)
	}
}

func TestSessionPublisherDrainCancellationUnblocksRequester(t *testing.T) {
	client, server := newAuthenticatedPair(t)
	sent := make(chan struct{})
	done := tunnelWorker(t, func() { _ = server.Close() }, func() error {
		request, err := tunnelv1.ReadControl(server.control)
		if err == nil {
			err = tunnelv1.WriteControl(server.control, tunnelv1.Message{Type: tunnelv1.Draining, ProtocolVersion: 1, RequestID: request.RequestID})
		}
		if err == nil {
			close(sent)
		}
		return err
	})
	ctx, cancel := context.WithCancel(tunnelContext(t))
	t.Cleanup(cancel)
	requested := tunnelWorker(t, cancel, func() error { return client.RequestPublisherDrain(ctx, "request_drain_1") })
	await(t, sent)
	cancel()
	if err := await(t, requested); !errors.Is(err, context.Canceled) {
		t.Fatalf("drain=%v", err)
	}
	if err := await(t, done); err != nil {
		t.Fatal(err)
	}
}
