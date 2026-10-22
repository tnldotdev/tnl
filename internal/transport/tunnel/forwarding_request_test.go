package tunnel

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type responseCountingStream struct {
	muxsession.Stream
	bytes     atomic.Int64
	deadlines atomic.Int64
	closes    atomic.Int64
}

func (s *responseCountingStream) Write(p []byte) (int, error) {
	n, err := s.Stream.Write(p)
	s.bytes.Add(int64(n))
	return n, err
}
func (s *responseCountingStream) SetDeadline(at time.Time) error {
	s.deadlines.Add(1)
	return s.Stream.SetDeadline(at)
}
func (s *responseCountingStream) Close() error {
	s.closes.Add(1)
	return s.Stream.Close()
}

func TestForwardingRequestCopiesShareOneResponder(t *testing.T) {
	for _, private := range []bool{false, true} {
		for _, reject := range []bool{false, true} {
			name := "public/accept"
			if private {
				name = "private/accept"
			}
			if reject {
				name += "/reject"
			}
			t.Run(name, func(t *testing.T) {
				client, server := newMemoryPair(t)
				ctx := tunnelContext(t)
				peer, err := client.OpenStream(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer peer.Close()
				wrote := tunnelWorker(t, func() { _ = client.Close() }, func() error {
					if private {
						return tunnelv1.WriteServiceForwardingHeader(peer, maximumServiceHeader("relay", true))
					}
					return tunnelv1.WriteInternalForwardingHeader(peer, maximumPublicHeader("relay"))
				})
				incoming, err := (&Session{transport: server}).AcceptInternalForwardingStream(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if err := await(t, wrote); err != nil {
					t.Fatal(err)
				}
				counted := &responseCountingStream{Stream: incoming.Stream}
				incoming.response.stream = counted
				request := incoming.Request()
				var copiedAccept func() error
				var copiedReject func(tunnelv1.ErrorCode) error
				switch value := request.(type) {
				case *IncomingPublicForwardingStream:
					if private {
						t.Fatal("private request dispatched as public")
					}
					copy := *value
					copiedAccept, copiedReject = copy.Accept, copy.Reject
				case *IncomingServiceForwardingStream:
					if !private {
						t.Fatal("public request dispatched as private")
					}
					copy := *value
					copiedAccept, copiedReject = copy.Accept, copy.Reject
				default:
					t.Fatal("missing concrete forwarding request")
				}
				response := tunnelv1.StreamResponse{Type: tunnelv1.StreamAccepted}
				if reject {
					response = tunnelv1.StreamResponse{Type: tunnelv1.StreamRejected, Code: tunnelv1.Unavailable}
				}
				read := tunnelWorker(t, func() { _ = client.Close() }, func() error {
					got, err := tunnelv1.ReadStreamResponse(peer)
					if err != nil {
						return err
					}
					if got != response {
						return errors.New("wrong response")
					}
					if !reject {
						var payload [4]byte
						if _, err := io.ReadFull(peer, payload[:]); err != nil {
							return err
						}
						if string(payload[:]) != "body" {
							return errors.New("duplicate response corrupted visitor bytes")
						}
					}
					return nil
				})
				if reject {
					err = incoming.Reject(tunnelv1.Unavailable)
				} else {
					err = copiedAccept()
				}
				if err != nil {
					t.Fatal(err)
				}
				// competing responses from the legacy wrapper and concrete value
				// copies must all observe the first response without writing again.
				var group sync.WaitGroup
				for range 16 {
					group.Go(func() { _ = copiedAccept() })
					group.Go(func() { _ = copiedReject(tunnelv1.Internal) })
					group.Go(func() { _ = incoming.Accept() })
				}
				group.Wait()
				var expected bytes.Buffer
				if err := tunnelv1.WriteStreamResponse(&expected, response); err != nil {
					t.Fatal(err)
				}
				if counted.bytes.Load() != int64(expected.Len()) {
					t.Fatal("response written more than once")
				}
				if reject {
					if counted.closes.Load() != 1 || counted.deadlines.Load() != 0 {
						t.Fatal("rejection cleanup repeated")
					}
				} else {
					if counted.closes.Load() != 0 || counted.deadlines.Load() != 1 {
						t.Fatal("accept deadline reset repeated")
					}
					if _, err := incoming.Stream.Write([]byte("body")); err != nil {
						t.Fatal(err)
					}
				}
				if err := await(t, read); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestServiceForwardingMissingIdentityFieldsFailBeforeDispatch(t *testing.T) {
	for _, field := range []string{"service_id", "service_run_id", "run_number", "publisher_connection_id", "connection_assignment_revision", "relay_service_id", "relay_id", "relay_run_id", "relay_lease_revision", "lease_expires_at", "expires_at"} {
		t.Run(field, func(t *testing.T) {
			client, server := newMemoryPair(t)
			ctx := tunnelContext(t)
			peer, err := client.OpenStream(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			encoded, err := json.Marshal(maximumServiceHeader("relay", true))
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(encoded, &fields); err != nil {
				t.Fatal(err)
			}
			delete(fields, field)
			encoded, err = json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
			wrote := tunnelWorker(t, func() { _ = client.Close() }, func() error {
				if err := binary.Write(peer, binary.BigEndian, uint32(len(encoded))); err != nil {
					return err
				}
				_, err := peer.Write(encoded)
				return err
			})
			read := tunnelWorker(t, func() { _ = client.Close() }, func() error {
				got, err := tunnelv1.ReadStreamResponse(peer)
				if err == nil && (got.Type != tunnelv1.StreamRejected || got.Code != tunnelv1.InvalidMessage) {
					return errors.New("missing private identity was accepted")
				}
				return err
			})
			_, err = (&Session{transport: server}).AcceptInternalForwardingStream(ctx)
			var headerErr *StreamHeaderError
			if !errors.As(err, &headerErr) {
				t.Fatalf("missing field reached dispatch: %v", err)
			}
			if err := await(t, wrote); err != nil {
				t.Fatal(err)
			}
			if err := await(t, read); err != nil {
				t.Fatal(err)
			}
		})
	}
}
