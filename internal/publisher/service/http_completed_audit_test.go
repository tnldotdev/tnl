package service

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
)

type completedHTTPPhysicalClose struct {
	net.Conn
	err    error
	closes atomic.Int32
}

func (c *completedHTTPPhysicalClose) Close() error {
	c.closes.Add(1)
	return errors.Join(c.Conn.Close(), c.err)
}

func TestHTTPFrontendPhysicalCloseRetainsOwnerAndIndependentErrors(t *testing.T) {
	cleanup := errors.New("independent HTTP physical close failure")
	for _, test := range []struct {
		name string
		err  error
	}{{"clean", nil}, {"cleanup", cleanup}, {"joined-cancellation", errors.Join(context.Canceled, cleanup)}} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			front, back := net.Pipe()
			defer func() {
				if err := back.Close(); err != nil {
					t.Error(err)
				}
			}()
			physical := &completedHTTPPhysicalClose{Conn: front, err: test.err}
			visitor := &boundVisitor{Conn: physical}
			visitor.http = &httpAdmission{bound: &Bound{boundState: new(boundState)}, visitor: visitor, ctx: ctx, cancel: cancel, state: readyHTTPAdmission{}}
			serving := &httpServingConn{boundVisitor: visitor}
			for range 2 {
				err := serving.Close()
				if test.err == nil && err != nil || test.err != nil && !errors.Is(err, test.err) {
					t.Fatal("frontend physical close lost its independent result", err)
				}
				if ctx.Err() != nil {
					t.Fatal("frontend physical close canceled its owner before result collection")
				}
			}
			err := visitor.Close()
			if test.err == nil && err != nil || test.err != nil && !errors.Is(err, test.err) ||
				ctx.Err() != context.Canceled || physical.closes.Load() != 1 {
				t.Fatal("owner interruption lost cancellation, once-owned cleanup, or its error", err, ctx.Err(), physical.closes.Load())
			}
		})
	}
}

func TestServiceHTTPCompletedVisitorAuditsCloseBeforePublisherStop(t *testing.T) {
	f := newPendingHTTPFixture(t, 1, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusNoContent)
	}))
	events := make(chan serviceaudit.Observation, 2)
	f.source.bound.audit = connectorAuditSink(func(event serviceaudit.Observation) bool {
		events <- event
		return true
	})
	visitor := f.mustOpen(t, 0, pendingHTTPSource(0))
	pendingHTTPResponse(t, visitor.request(t, "/complete"), http.StatusNoContent)
	// the serving owner, not test cancellation or publisher shutdown, closes
	// this finite HTTP response. wait for its actual admission retirement.
	visitor.join(t)
	opened, closed := claimedAwait(t, events), claimedAwait(t, events)
	if opened.EventType != "connection.open" || opened.Outcome != "allowed" ||
		closed.EventType != "connection.close" || closed.Outcome != "closed" || closed.Reason != "closed" ||
		closed.VisitorConnectionID != opened.VisitorConnectionID || closed.RunID != opened.RunID {
		t.Fatal("normal frontend close changed its run-owned audit result", opened.EventType, opened.Outcome, closed.EventType, closed.Outcome, closed.Reason)
	}
}
