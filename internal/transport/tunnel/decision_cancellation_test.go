package tunnel

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type decisionResetStream struct {
	muxsession.Stream
	resets       atomic.Int32
	resetEntered chan struct{}
	resetRelease chan struct{}
}

func (s *decisionResetStream) Reset(code uint32) error {
	s.resets.Add(1)
	err := s.Stream.Reset(code)
	close(s.resetEntered)
	<-s.resetRelease
	return err
}

func decisionPromotion() tunnelv1.AdmissionHeader {
	h := internalForwardingHeader().Admission()
	h.Kind, h.RelayID, h.RelayRunID, h.RelayLeaseRevision = tunnelv1.PublisherPromotion, "", "", 0
	return h
}

func TestReturnDecisionCancellationAndJoin(t *testing.T) {
	for _, kind := range []string{"promotion", "accept", "reject", "forward_rejection", "end"} {
		for _, contention := range []string{"own_write", "data_writer", "responder"} {
			for _, preCanceled := range []bool{false, true} {
				name := kind + "/" + contention + map[bool]string{false: "/after_entry", true: "/pre_canceled"}[preCanceled]
				t.Run(name, func(t *testing.T) {
					synctest.Test(t, func(t *testing.T) {
						local, remote := net.Pipe()
						defer local.Close()
						defer remote.Close()
						wire := &decisionResetStream{Stream: &memoryStream{Conn: local}, resetEntered: make(chan struct{}), resetRelease: make(chan struct{})}
						release := sync.OnceFunc(func() { close(wire.resetRelease) })
						defer release()
						reply := &replyStream{Stream: wire, accepted: true, confirmed: true, promotion: decisionPromotion()}
						var prior <-chan error
						if contention != "own_write" {
							prior = tunnelWorker(t, func() { _ = local.Close() }, func() error {
								if contention == "responder" {
									return reply.respond(t.Context(), tunnelv1.StreamResponse{Type: tunnelv1.StreamRejected, Code: tunnelv1.Unavailable})
								}
								_, err := reply.Write([]byte("TLS bytes"))
								return err
							})
							synctest.Wait()
						}
						ctx, cancel := context.WithCancel(t.Context())
						defer cancel()
						if preCanceled {
							cancel()
						}
						result := tunnelWorker(t, func() { _ = local.Close() }, func() error {
							switch kind {
							case "promotion":
								return reply.promote(ctx, reply.promotion)
							case "accept":
								return reply.respond(ctx, tunnelv1.StreamResponse{Type: tunnelv1.StreamAccepted})
							case "reject":
								return reply.respond(ctx, tunnelv1.StreamResponse{Type: tunnelv1.StreamRejected, Code: tunnelv1.Unavailable})
							case "end":
								return reply.end(ctx)
							default:
								return reply.forwardRejection(ctx, tunnelv1.Unavailable)
							}
						})
						synctest.Wait()
						if !preCanceled {
							cancel()
							synctest.Wait()
							select {
							case <-wire.resetEntered:
							default:
								t.Fatal("cancellation did not interrupt this stream")
							}
							select {
							case <-result:
								t.Fatal("decision returned before its cancellation callback joined")
							default:
							}
						}
						release()
						if err := await(t, result); !errors.Is(err, context.Canceled) {
							t.Fatal("lost cancellation", err)
						}
						wantResets := int32(1)
						if preCanceled {
							wantResets = 0
						}
						if wire.resets.Load() != wantResets {
							t.Fatal("unexpected stream cleanup", wire.resets.Load())
						}
						_ = local.Close()
						if prior != nil {
							if err := await(t, prior); err == nil {
								t.Fatal("blocked writer survived stream cancellation")
							}
						}
					})
				})
			}
		}
	}
}

func TestReturnDecisionRealCancellationKeepsSibling(t *testing.T) {
	for _, transport := range []string{"quic", "tls_yamux"} {
		for _, decision := range []string{"promotion", "rejection", "end"} {
			t.Run(transport+"/"+decision, func(t *testing.T) {
				client, server := realTunnelPair(t, transport)
				_, publisher := realVisitorPair(t, client, server)
				reply := publisher.(*replyStream)
				wire := &promotionWriteSignal{Stream: reply.Stream, entered: make(chan struct{})}
				reply.Stream = wire
				reply.promotion = decisionPromotion()
				written := tunnelWorker(t, func() { _ = publisher.Close() }, func() error {
					_, err := publisher.Write(bytes.Repeat([]byte("x"), 16<<20))
					return err
				})
				await(t, wire.entered)
				ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
				defer cancel()
				var err error
				switch decision {
				case "rejection":
					err = reply.forwardRejection(ctx, tunnelv1.Unavailable)
				case "end":
					err = reply.end(ctx)
				default:
					err = reply.promote(ctx, reply.promotion)
				}
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("decision ignored contended writer deadline", err)
				}
				if err := await(t, written); err == nil {
					t.Fatal("blocked writer was not interrupted")
				}
				if client.Err() != nil || server.Err() != nil {
					t.Fatal("decision cancellation closed the session")
				}
				sibling, peer := realVisitorPair(t, client, server)
				if _, err := sibling.Write([]byte("ping")); err != nil {
					t.Fatal(err)
				}
				var ping [4]byte
				if _, err := io.ReadFull(peer, ping[:]); err != nil || string(ping[:]) != "ping" {
					t.Fatal("healthy sibling failed", err)
				}
			})
		}
	}
}
