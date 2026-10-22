package publicapi_test

import (
	"encoding/json"
	"io"
	"time"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

const (
	_ uint32                      = tunnelv1.Version
	_ int                         = tunnelv1.MaxControlBytes
	_ int                         = tunnelv1.MaxHeaderBytes
	_ int                         = tunnelv1.MaxCredentialLen
	_ tunnelv1.MessageType        = tunnelv1.Hello
	_ tunnelv1.MessageType        = tunnelv1.HelloAccepted
	_ tunnelv1.MessageType        = tunnelv1.Ping
	_ tunnelv1.MessageType        = tunnelv1.Pong
	_ tunnelv1.MessageType        = tunnelv1.Drain
	_ tunnelv1.MessageType        = tunnelv1.Draining
	_ tunnelv1.MessageType        = tunnelv1.Drained
	_ tunnelv1.MessageType        = tunnelv1.GoAway
	_ tunnelv1.MessageType        = tunnelv1.Error
	_ tunnelv1.PeerRole           = tunnelv1.Publisher
	_ tunnelv1.PeerRole           = tunnelv1.Ingress
	_ tunnelv1.StreamKind         = tunnelv1.VisitorStream
	_ tunnelv1.StreamKind         = tunnelv1.InternalForwardingStream
	_ tunnelv1.StreamKind         = tunnelv1.PublisherAdmissionStream
	_ tunnelv1.StreamKind         = tunnelv1.IngressAdmissionStream
	_ tunnelv1.StreamKind         = tunnelv1.PrivateVisitorStream
	_ tunnelv1.StreamKind         = tunnelv1.PrivateForwardingStream
	_ tunnelv1.StreamResponseType = tunnelv1.StreamAccepted
	_ tunnelv1.StreamResponseType = tunnelv1.StreamRejected
	_ tunnelv1.ErrorCode          = tunnelv1.InvalidMessage
	_ tunnelv1.ErrorCode          = tunnelv1.Unauthenticated
	_ tunnelv1.ErrorCode          = tunnelv1.StalePublishRunNumber
	_ tunnelv1.ErrorCode          = tunnelv1.StaleConnectionAssignment
	_ tunnelv1.ErrorCode          = tunnelv1.DuplicatePublisherConnection
	_ tunnelv1.ErrorCode          = tunnelv1.DrainingPublisherConnection
	_ tunnelv1.ErrorCode          = tunnelv1.CapacityExceeded
	_ tunnelv1.ErrorCode          = tunnelv1.Unavailable
	_ tunnelv1.ErrorCode          = tunnelv1.Internal
	_ string                      = tunnelv1.VisitorHumanDevice
	_ string                      = tunnelv1.VisitorWorkloadSession
)

// callers can keep the framing functions in typed callback slots, including
// the distinct public/private forwarding results and admission-result alias.
var (
	_ func(io.Writer, tunnelv1.Message) error                                                       = tunnelv1.WriteControl
	_ func(io.Reader) (tunnelv1.Message, error)                                                     = tunnelv1.ReadControl
	_ func(io.Writer, tunnelv1.VisitorStreamHeader) error                                           = tunnelv1.WriteVisitorStreamHeader
	_ func(io.Reader) (tunnelv1.VisitorStreamHeader, error)                                         = tunnelv1.ReadVisitorStreamHeader
	_ func(io.Writer, tunnelv1.InternalForwardingHeader) error                                      = tunnelv1.WriteInternalForwardingHeader
	_ func(io.Reader) (tunnelv1.InternalForwardingHeader, error)                                    = tunnelv1.ReadInternalForwardingHeader
	_ func(io.Reader) (tunnelv1.InternalForwardingHeader, *tunnelv1.PrivateForwardingHeader, error) = tunnelv1.ReadForwardingHeader
	_ func(io.Writer, tunnelv1.StreamResponse) error                                                = tunnelv1.WriteStreamResponse
	_ func(io.Reader) (tunnelv1.StreamResponse, error)                                              = tunnelv1.ReadStreamResponse
	_ func(io.Writer, tunnelv1.AdmissionHeader) error                                               = tunnelv1.WriteAdmissionHeader
	_ func(io.Reader) (tunnelv1.AdmissionHeader, error)                                             = tunnelv1.ReadAdmissionHeader
	_ func(io.Writer, tunnelv1.StreamResponse) error                                                = tunnelv1.WriteAdmissionResult
	_ func(io.Reader) (tunnelv1.StreamResponse, error)                                              = tunnelv1.ReadAdmissionResult
	_ tunnelv1.StreamResponse                                                                       = tunnelv1.AdmissionResult{}
	_ tunnelv1.AdmissionResult                                                                      = tunnelv1.StreamResponse{}
	_ func(io.Writer, tunnelv1.PrivateConnectorSessionHello) error                                  = tunnelv1.WritePrivateConnectorSessionHello
	_ func(io.Reader) (tunnelv1.PrivateConnectorSessionHello, error)                                = tunnelv1.ReadPrivateConnectorSessionHello
	_ func(io.Writer, tunnelv1.PrivateConnectorSessionAccepted) error                               = tunnelv1.WritePrivateConnectorSessionAccepted
	_ func(io.Reader) (tunnelv1.PrivateConnectorSessionAccepted, error)                             = tunnelv1.ReadPrivateConnectorSessionAccepted
	_ func(io.Writer, tunnelv1.PrivateVisitorEntry) error                                           = tunnelv1.WritePrivateVisitorEntry
	_ func(io.Reader) (tunnelv1.PrivateVisitorEntry, error)                                         = tunnelv1.ReadPrivateVisitorEntry
	_ func(io.Writer, tunnelv1.PrivateVisitorAccepted) error                                        = tunnelv1.WritePrivateVisitorAccepted
	_ func(io.Reader) (tunnelv1.PrivateVisitorAccepted, error)                                      = tunnelv1.ReadPrivateVisitorAccepted
	_ func(io.Writer, tunnelv1.PrivateStreamHeader) error                                           = tunnelv1.WritePrivateStreamHeader
	_ func(io.Reader) (tunnelv1.PrivateStreamHeader, error)                                         = tunnelv1.ReadPrivateStreamHeader
	_ func(io.Writer, tunnelv1.PrivateForwardingHeader) error                                       = tunnelv1.WritePrivateForwardingHeader
	_ func(io.Reader) (tunnelv1.PrivateForwardingHeader, error)                                     = tunnelv1.ReadPrivateForwardingHeader
	_ func() ([]byte, error)                                                                        = tunnelv1.NewConnectorSessionNonce
	_ func(tunnelv1.InternalForwardingHeader) tunnelv1.AdmissionHeader                              = tunnelv1.InternalForwardingHeader.Admission
	_ func(tunnelv1.PrivateConnectorSessionHello) tunnelv1.VisitorConnectorClaim                    = tunnelv1.PrivateConnectorSessionHello.Claim
	_ func(tunnelv1.VisitorConnectorClaim) ([]byte, error)                                          = tunnelv1.VisitorConnectorClaim.Digest
	_ json.Unmarshaler                                                                              = (*tunnelv1.VisitorSubject)(nil)
	_ error                                                                                         = tunnelv1.ErrInvalidVisitorSubject
)

// every baseline protocol model remains available as a public type. these
// literals also check the nested admission/subject and promoted-header fields
// used by transports, rather than converting between unrelated lookalike DTOs.
var (
	_ = tunnelv1.Message{Type: tunnelv1.Hello, ProtocolVersion: tunnelv1.Version, Role: tunnelv1.Publisher, PublisherConnection: &tunnelv1.PublisherConnectionRef{ConnectionSlot: 0}, PrivateConnection: &tunnelv1.PrivatePublisherConnectionRef{ConnectionSlot: 1}}
	_ = tunnelv1.TraceContext{TraceParent: "traceparent"}
	_ = tunnelv1.VisitorStreamHeader{TraceContext: tunnelv1.TraceContext{}, Kind: tunnelv1.VisitorStream, ProtocolVersion: tunnelv1.Version, PublishRunNumber: 1, AccessPending: true}
	_ = tunnelv1.InternalForwardingHeader{Kind: tunnelv1.InternalForwardingStream, ConnectionSlot: 1, RelayLeaseRevision: 1, PublicUrlExpiresAt: time.Time{}, LeaseExpiresAt: time.Time{}}
	_ = tunnelv1.AdmissionHeader{Kind: tunnelv1.PublisherAdmissionStream, ProtocolVersion: tunnelv1.Version, PublishRunNumber: 1, ConnectionSlot: 1}
	_ = tunnelv1.PrivateConnectorSessionHello{Subject: tunnelv1.VisitorSubject{Kind: tunnelv1.VisitorHumanDevice, IdentityID: "identity", DeviceID: "device"}, Nonce: []byte{}, Signature: []byte{}}
	_ = tunnelv1.PrivateConnectorSessionAccepted{Subject: tunnelv1.VisitorSubject{Kind: tunnelv1.VisitorWorkloadSession, WorkloadSessionID: "workload"}, ExpiresAt: time.Time{}}
	_ = tunnelv1.PrivateVisitorEntry{TraceContext: tunnelv1.TraceContext{}, Kind: tunnelv1.PrivateVisitorStream, RunNumber: 1}
	_ = tunnelv1.PrivateVisitorAccepted{Subject: tunnelv1.VisitorSubject{}, GrantRevision: 1, ConnectionAssignmentRevision: 1}
	_ = tunnelv1.PrivateStreamHeader{Kind: tunnelv1.PrivateVisitorStream, Connector: &tunnelv1.ConnectorAdmission{Subject: tunnelv1.VisitorSubject{}, GrantRevision: 1}, Direct: &tunnelv1.DirectAdmission{IngressLeaseRevision: 1, DestinationPort: 443}, ExpiresAt: time.Time{}}
	_ = tunnelv1.PrivateForwardingHeader{PrivateStreamHeader: tunnelv1.PrivateStreamHeader{}, RelayLeaseRevision: 1, LeaseExpiresAt: time.Time{}}
	_ = tunnelv1.VisitorConnectorClaim{Subject: tunnelv1.VisitorSubject{}, ServiceID: "service", SessionID: "session", Credential: "credential", Nonce: []byte{}, Signature: []byte{}}
)

type validated interface{ Validate() error }

var (
	_ validated = tunnelv1.Message{}
	_ validated = tunnelv1.PublisherConnectionRef{}
	_ validated = tunnelv1.PrivatePublisherConnectionRef{}
	_ validated = tunnelv1.TraceContext{}
	_ validated = tunnelv1.VisitorSubject{}
	_ validated = tunnelv1.VisitorStreamHeader{}
	_ validated = tunnelv1.InternalForwardingHeader{}
	_ validated = tunnelv1.StreamResponse{}
	_ validated = tunnelv1.AdmissionHeader{}
	_ validated = tunnelv1.PrivateConnectorSessionHello{}
	_ validated = tunnelv1.PrivateConnectorSessionAccepted{}
	_ validated = tunnelv1.PrivateVisitorEntry{}
	_ validated = tunnelv1.PrivateVisitorAccepted{}
	_ validated = tunnelv1.PrivateStreamHeader{}
	_ validated = tunnelv1.PrivateForwardingHeader{}
)
