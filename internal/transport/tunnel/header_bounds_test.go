package tunnel

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
	"go.opentelemetry.io/otel/trace"
)

const boundsTraceParent = "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"

// use the actual acknowledged Session open methods: a JSON-only round trip
// misses the forwarding dispatch cap and stream setup/rejection behavior.
func TestSessionMaximumForwardingHeaders(t *testing.T) {
	for _, escaped := range []bool{false, true} {
		t.Run(fmt.Sprintf("escaped=%t", escaped), func(t *testing.T) {
			text := strings.Repeat("r", 256)
			if escaped {
				text = strings.Repeat("\x01", 256)
			}
			public := maximumPublicHeader(text)
			for _, generated := range []bool{true, false} {
				t.Run(fmt.Sprintf("public/generated_ids=%t", generated), func(t *testing.T) {
					h := public
					if generated {
						h.VisitorConnectionID = boundsID(opaqueid.VisitorConnectionPrefix)
						h.PublicURLID = boundsID(opaqueid.PublicURLPrefix)
						h.PublishRunID = boundsID(opaqueid.PublishRunPrefix)
						h.PublisherConnectionID = boundsID(opaqueid.PublisherConnectionPrefix)
						h.RelayRunID = boundsID(opaqueid.RelayRunPrefix)
					}
					client, peer := newHeaderBoundsPair(t, ingressBoundsHello())
					ctx := headerBoundsContext(t)
					want := h
					want.TraceContext = tunnelv1.TraceContext{TraceParent: boundsTraceParent}
					checkMaximumTransfer(t, want, tunnelv1.MaxHeaderBytes,
						func() (net.Conn, error) { return client.OpenInternalForwardingStream(ctx, h) },
						func() (muxsession.Stream, any, func() error, error) {
							v, err := peer.AcceptInternalForwardingStream(ctx)
							if err != nil {
								return nil, nil, nil, err
							}
							if v.PrivateHeader != nil {
								return nil, nil, nil, errors.New("public header dispatched as private")
							}
							return v.Stream, v.Header, v.Accept, nil
						})
				})
			}
			for _, direct := range []bool{false, true} {
				for _, publisher := range []bool{false, true} {
					t.Run(fmt.Sprintf("private/direct=%t/publisher_binding=%t", direct, publisher), func(t *testing.T) {
						h := maximumPrivateHeader(text, direct)
						hello := ingressBoundsHello()
						if publisher {
							hello.Role = tunnelv1.Publisher
							hello.PrivateConnection = &tunnelv1.PrivatePublisherConnectionRef{PrivateServiceID: h.PrivateServiceID, PrivateRunID: h.PrivateRunID,
								RunNumber: h.RunNumber, PublisherConnectionID: h.PublisherConnectionID, ConnectionSlot: h.ConnectionSlot,
								ConnectionAssignmentRevision: h.ConnectionAssignmentRevision, RelayServiceID: h.RelayServiceID}
						}
						client, peer := newHeaderBoundsPair(t, hello)
						ctx := headerBoundsContext(t)
						want := h
						want.TraceContext = tunnelv1.TraceContext{TraceParent: boundsTraceParent}
						checkMaximumTransfer(t, want, tunnelv1.MaxPrivateHeaderBytes,
							func() (net.Conn, error) { return client.OpenPrivateForwardingStream(ctx, h) },
							func() (muxsession.Stream, any, func() error, error) {
								if publisher {
									v, err := peer.AcceptPrivateForwardingStream(ctx)
									if err != nil {
										return nil, nil, nil, err
									}
									return v.Stream, v.Header, v.Accept, nil
								}
								v, err := peer.AcceptInternalForwardingStream(ctx)
								if err != nil {
									return nil, nil, nil, err
								}
								if v.PrivateHeader == nil {
									return nil, nil, nil, errors.New("private header dispatched as public")
								}
								return v.Stream, *v.PrivateHeader, v.Accept, nil
							})
					})
				}
			}
		})
	}
}

func checkMaximumTransfer(t *testing.T, want any, cap int, open func() (net.Conn, error), accept func() (muxsession.Stream, any, func() error, error)) {
	t.Helper()
	wantJSON, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	if len(wantJSON) > cap {
		t.Fatalf("maximum supported header needs %d bytes, cap %d", len(wantJSON), cap)
	}
	t.Logf("maximum header: %d JSON bytes, cap %d", len(wantJSON), cap)
	payload := []byte("\x16\x03\x01opaque visitor bytes\x00\xff")
	done := tunnelWorker(t, func() {}, func() error {
		stream, got, acknowledge, err := accept()
		if err != nil {
			return err
		}
		defer stream.Close()
		gotJSON, err := json.Marshal(got)
		if err != nil {
			return err
		}
		if !bytes.Equal(gotJSON, wantJSON) {
			return errors.New("maximum header or trace context changed")
		}
		if err := acknowledge(); err != nil {
			return err
		}
		received := make([]byte, len(payload))
		if _, err := io.ReadFull(stream, received); err != nil {
			return err
		}
		if !bytes.Equal(received, payload) {
			return errors.New("header consumed following visitor bytes")
		}
		_, err = stream.Write(received)
		return err
	})
	stream, err := open()
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if _, err := stream.Write(payload); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len(payload))
	if _, err := io.ReadFull(stream, reply); err != nil || !bytes.Equal(reply, payload) {
		t.Fatalf("visitor reply changed: %x %v", reply, err)
	}
	if err := await(t, done); err != nil {
		t.Fatal(err)
	}
}

func maximumPublicHeader(text string) tunnelv1.InternalForwardingHeader {
	return tunnelv1.InternalForwardingHeader{ProtocolVersion: 1, Kind: tunnelv1.InternalForwardingStream,
		VisitorConnectionID: text, PublicURLID: text, PublishRunID: text, PublishRunNumber: math.MaxUint64, PublisherConnectionID: text,
		ConnectionSlot: 1, ConnectionAssignmentRevision: math.MaxUint64, RelayServiceID: text, RelayID: text, RelayRunID: text,
		RelayLeaseRevision: math.MaxUint64, PublicUrlExpiresAt: boundsTimestamp(), LeaseExpiresAt: boundsTimestamp(), AccessPending: true}
}

func maximumPrivateHeader(text string, direct bool) tunnelv1.PrivateForwardingHeader {
	h := tunnelv1.PrivateForwardingHeader{PrivateStreamHeader: tunnelv1.PrivateStreamHeader{ProtocolVersion: 1, Kind: tunnelv1.PrivateForwardingStream,
		PrivateServiceID: boundsID(opaqueid.PrivateServicePrefix), PrivateRunID: boundsID(opaqueid.PrivateRunPrefix), RunNumber: math.MaxUint64,
		Connector: &tunnelv1.ConnectorAdmission{SessionID: boundsID(opaqueid.PrivateConnectorSessionPrefix), Subject: tunnelv1.VisitorSubject{Kind: tunnelv1.VisitorHumanDevice, IdentityID: boundsID(opaqueid.IdentityPrefix), DeviceID: boundsID(opaqueid.VisitorDevicePrefix)}, GrantRevision: math.MaxUint64},
		SourceIP:  "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", VisitorConnectionID: boundsID(opaqueid.VisitorConnectionPrefix), PublisherConnectionID: boundsID(opaqueid.PublisherConnectionPrefix),
		ConnectionAssignmentRevision: math.MaxUint64, ExpiresAt: boundsTimestamp()}, ConnectionSlot: 1, RelayServiceID: text, RelayID: text,
		RelayRunID: boundsID(opaqueid.RelayRunPrefix), RelayLeaseRevision: math.MaxUint64, LeaseExpiresAt: boundsTimestamp()}
	if direct {
		h.Connector = nil
		h.Direct = &tunnelv1.DirectAdmission{IngressID: text, IngressRunID: boundsID(opaqueid.IngressRunPrefix), IngressLeaseRevision: math.MaxUint64, DestinationPort: math.MaxUint16}
	}
	return h
}

func boundsID(prefix string) string { return prefix + strings.Repeat("a", 22) }
func boundsTimestamp() time.Time {
	return time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.FixedZone("max", 23*3600+59*60))
}
func ingressBoundsHello() tunnelv1.Message {
	return tunnelv1.Message{Type: tunnelv1.Hello, ProtocolVersion: 1, Role: tunnelv1.Ingress, Credential: "credential"}
}
func headerBoundsContext(t *testing.T) context.Context {
	t.Helper()
	tid, _ := trace.TraceIDFromHex("0123456789abcdef0123456789abcdef")
	sid, _ := trace.SpanIDFromHex("0123456789abcdef")
	return trace.ContextWithSpanContext(tunnelContext(t), trace.NewSpanContext(trace.SpanContextConfig{TraceID: tid, SpanID: sid, TraceFlags: trace.FlagsSampled}))
}

func newHeaderBoundsPair(t *testing.T, hello tunnelv1.Message) (*Session, *Session) {
	t.Helper()
	a, b := newMemoryPair(t)
	ctx := tunnelContext(t)
	type result struct {
		session *Session
		err     error
	}
	accepted := tunnelWorker(t, func() { _ = b.Close() }, func() result {
		s, _, err := Accept(ctx, b, func(_ context.Context, got tunnelv1.Message) error {
			if got.Role != hello.Role || got.Credential != hello.Credential {
				return errors.New("unexpected peer identity")
			}
			return nil
		})
		return result{s, err}
	})
	client, err := Dial(ctx, a, hello)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	server := await(t, accepted)
	if server.err != nil {
		t.Fatal(server.err)
	}
	t.Cleanup(func() { _ = server.session.Close() })
	return client, server.session
}

func TestSessionForwardingBoundsRejectMalformedStreams(t *testing.T) {
	client, peer := newHeaderBoundsPair(t, ingressBoundsHello())
	ctx := tunnelContext(t)
	public, err := json.Marshal(maximumPublicHeader("id"))
	if err != nil {
		t.Fatal(err)
	}
	private, err := json.Marshal(maximumPrivateHeader(strings.Repeat("r", 256), true))
	if err != nil {
		t.Fatal(err)
	}
	framed := func(payload []byte) []byte {
		return append(binary.BigEndian.AppendUint32(nil, uint32(len(payload))), payload...)
	}
	for name, input := range map[string][]byte{
		"public_unknown":    framed(bytes.Replace(public, []byte(`"protocol_version":`), []byte(`"unknown":true,"protocol_version":`), 1)),
		"private_unknown":   framed(bytes.Replace(private, []byte(`"protocol_version":`), []byte(`"unknown":true,"protocol_version":`), 1)),
		"public_bad_trace":  framed(bytes.Replace(public, []byte(`"protocol_version":`), []byte(`"trace_context":{"traceparent":"bad"},"protocol_version":`), 1)),
		"private_bad_trace": framed(bytes.Replace(private, []byte(`"protocol_version":`), []byte(`"trace_context":{"traceparent":"bad"},"protocol_version":`), 1)),
		"public_overcap":    binary.BigEndian.AppendUint32(nil, uint32(tunnelv1.MaxHeaderBytes+1)),
		"private_overcap":   framed(append(bytes.Clone(private), bytes.Repeat([]byte(" "), tunnelv1.MaxPrivateHeaderBytes+1-len(private))...)),
	} {
		t.Run(name, func(t *testing.T) {
			accepted := tunnelWorker(t, func() {}, func() error { _, err := peer.AcceptInternalForwardingStream(ctx); return err })
			stream, err := client.transport.OpenStream(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Close()
			if _, err := stream.Write(input); err != nil {
				t.Fatal(err)
			}
			response, err := tunnelv1.ReadStreamResponse(stream)
			if err != nil || response.Type != tunnelv1.StreamRejected || response.Code != tunnelv1.InvalidMessage {
				t.Fatalf("malformed stream response = %v, %v", response, err)
			}
			var headerErr *StreamHeaderError
			if err := await(t, accepted); !errors.As(err, &headerErr) {
				t.Fatalf("malformed stream not classified: %v", err)
			}
		})
	}
	// one bad header must not retire the authenticated mux session.
	h := maximumPublicHeader(strings.Repeat("r", 256))
	want := h
	want.TraceContext = tunnelv1.TraceContext{TraceParent: boundsTraceParent}
	checkMaximumTransfer(t, want, tunnelv1.MaxHeaderBytes, func() (net.Conn, error) { return client.OpenInternalForwardingStream(headerBoundsContext(t), h) }, func() (muxsession.Stream, any, func() error, error) {
		v, err := peer.AcceptInternalForwardingStream(ctx)
		if err != nil {
			return nil, nil, nil, err
		}
		return v.Stream, v.Header, v.Accept, nil
	})
}
