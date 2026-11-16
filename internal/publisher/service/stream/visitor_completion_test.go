package stream

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/testutil/visitorfixture"
)

type completionAdmission struct{ stopped atomic.Int32 }

func (*completionAdmission) CheckUse(ctx context.Context) (time.Time, error) {
	return time.Now().Add(time.Minute), context.Cause(ctx)
}
func (*completionAdmission) SetupDeadline() time.Time { return time.Now().Add(time.Minute) }
func (*completionAdmission) FinishSetup() error       { return nil }
func (a *completionAdmission) Stop()                  { a.stopped.Add(1) }

type completionCloseConn struct {
	net.Conn
	entered, finished chan struct{}
	release           <-chan struct{}
	err               error
	once              sync.Once
}

func (c *completionCloseConn) Close() error {
	c.once.Do(func() {
		close(c.entered)
		_ = c.Conn.Close()
		<-c.release
		close(c.finished)
	})
	return c.err
}

func TestVisitorFinishJoinsSetupCloseAndErrorsBeforeStoppingAdmission(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const hostname = "service.example.test"
		certificate := visitorfixture.Certificate(t, hostname)
		raw, visitor := net.Pipe()
		defer visitor.Close()
		closeRelease, finishRelease := make(chan struct{}), make(chan struct{})
		releaseClose := sync.OnceFunc(func() { close(closeRelease) })
		releaseFinish := sync.OnceFunc(func() { close(finishRelease) })
		defer releaseClose()
		defer releaseFinish()
		cleanup, finishing := errors.New("physical cleanup failed"), errors.New("joined delivery failed")
		wire := &completionCloseConn{Conn: raw, entered: make(chan struct{}), finished: make(chan struct{}),
			release: closeRelease, err: cleanup}
		admission := &completionAdmission{}
		finishEntered := make(chan struct{})
		var calls atomic.Int32
		endpoint := Stream{Protocol: config.ProtocolPostgres, Hostname: hostname, Target: "127.0.0.1:1",
			TLS: &tls.Config{Certificates: []tls.Certificate{certificate}}, Visitor: ConnectorVisitor{Admission: admission},
			FinishVisitor: func(result error) error {
				calls.Add(1)
				select {
				case <-wire.finished:
				default:
					t.Error("delivery finishing raced a setup close callback")
				}
				if !errors.Is(result, context.Canceled) || !errors.Is(result, cleanup) {
					t.Error("delivery finishing did not receive the joined operation and cleanup causes", result)
				}
				if admission.stopped.Load() != 0 {
					t.Error("admission stopped before the delivery owner entered")
				}
				close(finishEntered)
				<-finishRelease
				return finishing
			}}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- endpoint.Forward(ctx, wire) }()
		synctest.Wait()
		cancel()
		<-wire.entered
		if calls.Load() != 0 || admission.stopped.Load() != 0 {
			t.Fatal("setup cancellation skipped its physical callback join")
		}
		releaseClose()
		<-finishEntered
		synctest.Wait()
		if admission.stopped.Load() != 0 {
			t.Fatal("admission stopped while delivery finishing was still running")
		}
		select {
		case err := <-done:
			t.Fatal("forwarding returned before the delivery owner joined", err)
		default:
		}
		releaseFinish()
		if err := <-done; !errors.Is(err, context.Canceled) || !errors.Is(err, cleanup) || !errors.Is(err, finishing) {
			t.Fatal("delivery finishing replaced an independent failure", err)
		}
		cancel()
		time.Sleep(time.Second)
		synctest.Wait()
		if calls.Load() != 1 || admission.stopped.Load() != 1 {
			t.Fatal("delivery or admission work restarted after return", calls.Load(), admission.stopped.Load())
		}
	})
}

func TestVisitorFinishJoinsEnteredHTTPTargetWorkAndCleanup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const hostname = "service.example.test"
		certificate := visitorfixture.Certificate(t, hostname)
		raw, visitor := net.Pipe()
		defer visitor.Close()
		closeRelease, workerRelease := make(chan struct{}), make(chan struct{})
		releaseClose := sync.OnceFunc(func() { close(closeRelease) })
		releaseWorker := sync.OnceFunc(func() { close(workerRelease) })
		defer releaseClose()
		defer releaseWorker()
		operation, cleanup := errors.New("frontend failed"), errors.New("entered target cleanup failed")
		workerCanceled, workerJoined := make(chan struct{}), make(chan struct{})
		var target *completionCloseConn
		var finishes atomic.Int32
		endpoint := Stream{Protocol: config.ProtocolHTTP, Hostname: hostname, Target: "127.0.0.1:1",
			TLS: &tls.Config{Certificates: []tls.Certificate{certificate}},
			Visitor: HTTPVisitor{Frontend: visitorFrontendFunc(func(_ context.Context, _ *tls.Conn, selected HTTPTarget) error {
				conn, peer := net.Pipe()
				target = &completionCloseConn{Conn: conn, entered: make(chan struct{}), finished: make(chan struct{}),
					release: closeRelease, err: cleanup}
				selected.track(target)
				done, entered := selected.enter()
				if !entered {
					t.Error("HTTP target work was not admitted")
					return operation
				}
				go func() {
					defer done()
					defer peer.Close()
					defer close(workerJoined)
					<-selected.lifetime.Done()
					close(workerCanceled)
					<-workerRelease
				}()
				return operation
			})},
			FinishVisitor: func(result error) error {
				finishes.Add(1)
				select {
				case <-workerJoined:
				default:
					t.Error("delivery finishing raced entered HTTP target work")
				}
				select {
				case <-target.finished:
				default:
					t.Error("delivery finishing raced target physical cleanup")
				}
				if !errors.Is(result, operation) || !errors.Is(result, cleanup) {
					t.Error("delivery finishing lost the frontend or target cleanup failure", result)
				}
				return nil
			}}
		done := make(chan error, 1)
		go func() { done <- endpoint.Forward(t.Context(), raw) }()
		client := tls.Client(visitor, &tls.Config{RootCAs: visitorfixture.Roots(t, certificate), ServerName: hostname})
		if err := client.HandshakeContext(t.Context()); err != nil {
			t.Fatal(err)
		}
		<-workerCanceled
		synctest.Wait()
		if finishes.Load() != 0 {
			t.Fatal("delivery finishing skipped the target close join")
		}
		releaseClose()
		<-target.finished
		synctest.Wait()
		if finishes.Load() != 0 {
			t.Fatal("delivery finishing skipped the target worker join")
		}
		releaseWorker()
		if err := <-done; !errors.Is(err, operation) || !errors.Is(err, cleanup) || finishes.Load() != 1 {
			t.Fatal("HTTP delivery completion lost a cause or did not join exactly once", err, finishes.Load())
		}
	})
}
