package service

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type inFlightCleanupControl struct {
	RunControl
	client  *http.Client
	entered chan context.Context
	failure error
}

func TestServiceCleanupFenceJoinPreservesConcurrentExpiryAndOperationValues(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		type operationKey struct{}
		work := context.WithValue(t.Context(), operationKey{}, "service operation")
		parent := context.WithValue(context.Background(), operationKey{}, "owner")
		fence, expire := context.WithCancelCause(parent)
		defer expire(context.Canceled)
		until := time.Now().Add(10 * time.Second)
		active, join := (RunConfig{ShutdownContext: fence}).cleanupContext(work, until)
		if active.Value(operationKey{}) != "service operation" {
			t.Fatal("cleanup replaced its operation values with the owner's values")
		}
		expire(context.DeadlineExceeded)
		// join may stop the scheduled callback before it runs. it must still
		// observe the winning parent cause and finish its callback ownership.
		if err := join(); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("joining the callback discarded concurrent expiry", err)
		}
		if deadline, _ := active.Deadline(); !deadline.Equal(until) || active.Err() != context.Canceled || context.Cause(active) != context.DeadlineExceeded {
			t.Fatal("cleanup misrepresented standard context deadline/cause behavior", deadline, active.Err(), context.Cause(active))
		}
	})
}

func (c *inFlightCleanupControl) CloseServiceRun(ctx context.Context, service, run string, token credentials.ServiceRunToken) error {
	if service != "svc_0123456789abcdefghijkl" || run != "srun_0123456789abcdefghijkl" || token.String() != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" {
		return ErrPrivateStream
	}
	c.entered <- ctx
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://control.test/close", nil)
	if err != nil {
		return err
	}
	response, err := c.client.Do(request)
	if response != nil {
		_ = response.Body.Close()
	}
	return errors.Join(err, c.failure)
}

func TestServiceCleanupFenceInterruptsInFlightExactRunClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		owned, peer := net.Pipe()
		defer owned.Close()
		defer peer.Close()
		transport := &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) { return owned, nil }}
		defer transport.CloseIdleConnections()
		received, peerJoined := make(chan struct{}), make(chan struct{})
		go func() {
			defer close(peerJoined)
			defer peer.Close()
			reader := bufio.NewReader(peer)
			request, err := http.ReadRequest(reader)
			if err != nil {
				t.Error(err)
				return
			}
			_ = request.Body.Close()
			close(received)
			// the request arrived, but no remote cleanup acknowledgement is
			// returned. cancellation must physically close the owned transport.
			_, _ = io.Copy(io.Discard, reader)
		}()
		fence, expire := context.WithCancelCause(context.WithoutCancel(t.Context()))
		defer expire(context.Canceled)
		start := time.Now()
		until := start.Add(10 * time.Second)
		cleanupFailure := errors.New("independent close failure")
		control := &inFlightCleanupControl{client: &http.Client{Transport: transport}, entered: make(chan context.Context, 1), failure: cleanupFailure}
		preparation := &runPreparation{attempted: true, known: true,
			config: RunConfig{Control: control, ServiceID: "svc_0123456789abcdefghijkl", ShutdownContext: fence,
				ShutdownDeadline: func() time.Time { return until }},
			preparation: controlv1.ServiceRunPreparation{ServiceRunId: "srun_0123456789abcdefghijkl", RunToken: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}
		done := make(chan error, 1)
		go func() { done <- preparation.close(t.Context()) }()
		active := <-control.entered
		<-received
		time.Sleep(time.Second)
		expired := make(chan struct{})
		timer := time.AfterFunc(2*time.Second, func() {
			defer close(expired)
			expire(context.DeadlineExceeded)
		})
		defer timer.Stop()
		err := <-done
		<-expired
		<-peerJoined
		if time.Since(start) != 3*time.Second || !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, cleanupFailure) {
			t.Fatal("in-flight cleanup did not interrupt and join at the narrowed expiry", time.Since(start), err)
		}
		if !strings.Contains(err.Error(), "service run cleanup is unconfirmed") {
			t.Fatal("an interrupted request became confirmed remote cleanup", err)
		}
		if deadline, _ := active.Deadline(); !deadline.Equal(until) || active.Err() != context.Canceled || context.Cause(active) != context.DeadlineExceeded {
			t.Fatal("in-flight context did not retain standard deadline/cause behavior", deadline, active.Err(), context.Cause(active))
		}
	})
}
