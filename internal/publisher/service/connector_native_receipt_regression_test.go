package service

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	quic "github.com/quic-go/quic-go"
	connectorstream "github.com/tnldotdev/tnl/internal/connector/stream"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/peer"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// the local client has already half-closed its request, but has not consumed
// the response. this gate blocks an actual PreparedConnector return-copy write,
// not the publisher's stream, its QUIC window, or either packet carrier.
type nativeReceiptLocalConn struct {
	net.Conn
	request *bytes.Reader
	ctx     context.Context
	entered chan struct{}
	release <-chan struct{}
	once    sync.Once
}

func (c *nativeReceiptLocalConn) Read(p []byte) (int, error) { return c.request.Read(p) }
func (c *nativeReceiptLocalConn) Write(p []byte) (int, error) {
	c.once.Do(func() { close(c.entered) })
	select {
	case <-c.release:
		return c.Conn.Write(p)
	case <-c.ctx.Done():
		return 0, context.Cause(c.ctx)
	}
}
func (*nativeReceiptLocalConn) CloseWrite() error { return nil }

func TestConnectorNativeDrainKeepsPacketCarriersUntilReturnCopyJoins(t *testing.T) {
	for _, scenario := range []struct {
		name        string
		retire      bool
		latePublish bool
	}{
		{name: "retain_carriers_control"},
		{name: "run_drain_retires_carriers", retire: true},
		{name: "completion_precedes_drain_publication", retire: true, latePublish: true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				target, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer target.Close()
				payload := bytes.Repeat([]byte("native final response\n"), 8192)
				targetDone := make(chan error, 1)
				targetJoined := make(chan struct{})
				go func() {
					defer close(targetJoined)
					conn, err := target.Accept()
					if err != nil {
						targetDone <- err
						return
					}
					defer conn.Close()
					request, err := io.ReadAll(conn)
					if err != nil || string(request) != "one request" {
						targetDone <- errors.Join(err, errors.New("native request or its half-close changed"))
						return
					}
					_, err = conn.Write(payload)
					targetDone <- err
				}()
				bound, publisher, verification, opening, _ := connectorPeerFixture(t, target.Addr().String())
				binding := publisher.bindingSnapshot()
				paths, _ := connectorRebindPacketPaths(t, ctx, bound, binding)
				packets, err := peer.New(ctx, peer.Config{
					Key: binding.sessionKey, Role: 0, Binding: binding.revision(), Paths: paths,
				})
				if err != nil {
					t.Fatal(err)
				}
				defer packets.Close()
				served := make(chan error, 1)
				peerJoined := make(chan struct{})
				go func() { defer close(peerJoined); served <- publisher.Serve(ctx) }()
				defer func() {
					cancel()
					publisher.Close()
					<-peerJoined
					_ = target.Close()
					<-targetJoined
				}()
				<-publisher.ready
				transport := &quic.Transport{Conn: packets}
				defer transport.Close()
				trust := verification.Clone()
				trust.NextProtos = []string{muxsession.ALPN}
				connection, err := transport.Dial(ctx, packets.RemoteAddr(), trust, tunnel.ConnectorQUICConfig())
				if err != nil {
					t.Fatal(err)
				}
				inner, err := muxsession.AdoptQUIC(connection)
				if err != nil {
					t.Fatal(err)
				}
				defer inner.Close()
				control := connectorControl(t, ctx, inner)
				entry := opening("N")
				prepared, err := connectorstream.PrepareConnector(ctx, ctx, inner, connectorstream.Run{
					ServiceID: entry.ServiceID, ServiceRunID: entry.ServiceRunID, RunNumber: entry.RunNumber,
					Protocol: "tcp", TrustRevision: int64(entry.MetadataRevision), ValidUntil: binding.until,
					Endpoint:   &controlv1.ServiceEndpoint{Hostname: verification.ServerName, Port: int(bound.prepared.servicePort)},
					ServiceTLS: verification,
				}, entry)
				if err != nil {
					t.Fatal(err)
				}
				defer prepared.Close()
				local, visitor := net.Pipe()
				defer local.Close()
				defer visitor.Close()
				released := make(chan struct{})
				release := sync.OnceFunc(func() { close(released) })
				defer release()
				gate := &nativeReceiptLocalConn{Conn: local, request: bytes.NewReader([]byte("one request")),
					ctx: ctx, entered: make(chan struct{}), release: released}
				copied := make(chan error, 1)
				copyJoined := make(chan struct{})
				go func() {
					defer close(copyJoined)
					err := prepared.Forward(ctx, gate)
					if err == nil {
						// model the existing generic completion message only after the
						// real connector copy owner has joined both directions.
						err = control.Complete(ctx, entry.VisitorConnectionID, entry.DeliveryGeneration)
					}
					copied <- err
				}()
				defer func() { release(); cancel(); _ = visitor.Close(); <-copyJoined }()
				received := make(chan []byte, 1)
				readJoined := make(chan struct{})
				go func() { defer close(readJoined); data, _ := io.ReadAll(visitor); received <- data }()
				defer func() { _ = visitor.Close(); <-readJoined }()
				<-gate.entered
				if err := <-targetDone; err != nil {
					t.Fatal("target failed before drain", err)
				}
				until := time.Now().Add(time.Second)
				completedBeforeDrain := false
				var beforeDrain chan struct{}
				if scenario.latePublish {
					// no new visitor can arrive in this one-stream fixture. observe
					// the existing worker without closing drain admission first.
					beforeDrain = make(chan struct{})
					go func() { bound.visitorWorkers.Wait(); close(beforeDrain) }()
					observation := time.NewTimer(time.Until(until) / 2)
					select {
					case <-beforeDrain:
						completedBeforeDrain = true
						t.Logf("publisher worker returned before drain publication with %s of the original bound left", time.Until(until))
					case <-observation.C:
					}
					observation.Stop()
					bound.mu.Lock()
					retained := bound.reservedStreams == 1 && len(publisher.streams) == 1
					bound.mu.Unlock()
					if !retained {
						t.Error("normal completion released admission or capacity before the return copy joined")
					}
				}
				if err := bound.startDrain(until); err != nil {
					t.Fatal(err)
				}
				drained := make(chan error, 1)
				go func() { drained <- bound.joinDrain() }()
				synctest.Wait()
				early := false
				// QUIC packet pacing owns timers even over the in-memory carriers.
				// spend only half the original drain bound while observing whether
				// the publisher join completes with local return delivery still held.
				observation := time.NewTimer(time.Until(until) / 2)
				select {
				case err := <-drained:
					if err != nil {
						t.Fatal("native drain reached its deadline before local delivery", err)
					}
					early = true
					if scenario.retire {
						// this is Publish's current ordering: joinDrain, then stopPeers,
						// which closes the exact inner QUIC session and packet endpoint.
						t.Logf("retiring carriers at %s before original drain expiry", time.Until(until))
						publisher.Close()
						t.Logf("peer close returned at %s before original drain expiry", time.Until(until))
						synctest.Wait()
					}
				case <-observation.C:
				}
				observation.Stop()
				releasedBeforeDeadline := time.Now().Before(until)
				release()
				data := <-received
				copyErr := <-copied
				if !early {
					if err := <-drained; err != nil {
						t.Fatal("native receipt exceeded the original drain deadline", err)
					}
				}
				if beforeDrain != nil {
					<-beforeDrain
				}
				if scenario.retire && (early || completedBeforeDrain) {
					t.Error("run retired native packet carriers before the connector return copy joined")
				}
				if copyErr != nil || !bytes.Equal(data, payload) {
					t.Errorf("native final delivery: received=%d want=%d copy_error=%v", len(data), len(payload), copyErr)
				}
				publisher.Close()
				bound.mu.Lock()
				active, pending, admissions := bound.reservedStreams, bound.connectorPending, len(publisher.streams)
				bound.mu.Unlock()
				if active != 0 || pending != 0 || admissions != 0 {
					t.Error("receipt completion did not join and release its exact admission and capacity", active, pending, admissions)
				}
				t.Logf("publisher_join_before_local_copy=%t elapsed=%s received=%d want=%d", early, time.Since(until.Add(-time.Second)), len(data), len(payload))
				if !releasedBeforeDeadline {
					t.Fatal("local delivery was not released before the original drain expiry")
				}
			})
		})
	}
}
