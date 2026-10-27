// Package tunnelv1 defines messages for publisher connections and visitor streams.
package tunnelv1

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

const (
	Version         = 1
	ALPN            = "tnl-tunnel/1"
	MaxControlBytes = 64 << 10
	// seven 256-byte identifiers may each need six JSON bytes per input byte.
	// include the fixed keys, uint64 counters, timestamps and bounded traceparent.
	MaxHeaderBytes   = 16 << 10
	MaxCredentialLen = 4096
)

type MessageType string

const (
	Hello            MessageType = "hello"
	HelloAccepted    MessageType = "hello_accepted"
	Ping             MessageType = "ping"
	Pong             MessageType = "pong"
	Drain            MessageType = "drain"
	Draining         MessageType = "draining"
	Drained          MessageType = "drained"
	GoAway           MessageType = "goaway"
	Error            MessageType = "error"
	NativeLegRenew   MessageType = "native_leg_renew"
	NativeLegRenewed MessageType = "native_leg_renewed"
)

type PeerRole string

const (
	Publisher       PeerRole = "publisher"
	Ingress         PeerRole = "ingress"
	NativeConnector PeerRole = "native_connector"
)

type ErrorCode string

const (
	InvalidMessage               ErrorCode = "invalid_message"
	Unauthenticated              ErrorCode = "unauthenticated"
	StalePublishRunNumber        ErrorCode = "stale_publish_run_number"
	StaleConnectionAssignment    ErrorCode = "stale_connection_assignment"
	DuplicatePublisherConnection ErrorCode = "duplicate_publisher_connection"
	DrainingPublisherConnection  ErrorCode = "draining"
	CapacityExceeded             ErrorCode = "capacity_exceeded"
	Unavailable                  ErrorCode = "unavailable"
	Internal                     ErrorCode = "internal"
)

// PublisherConnectionRef identifies one assigned publisher connection.
type PublisherConnectionRef struct {
	PublishRunID                 string `json:"publish_run_id"`
	PublicURLID                  string `json:"public_url_id"`
	PublishRunNumber             uint64 `json:"publish_run_number"`
	PublisherConnectionID        string `json:"publisher_connection_id"`
	ConnectionSlot               uint8  `json:"connection_slot"`
	ConnectionAssignmentRevision uint64 `json:"connection_assignment_revision"`
	RelayServiceID               string `json:"relay_service_id"`
}

// ServicePublisherConnectionRef identifies one private run assignment without
// creating or referring to a public URL.
type ServicePublisherConnectionRef struct {
	ServiceID                    string `json:"service_id"`
	ServiceRunID                 string `json:"service_run_id"`
	RunNumber                    uint64 `json:"run_number"`
	PublisherConnectionID        string `json:"publisher_connection_id"`
	ConnectionSlot               uint8  `json:"connection_slot"`
	ConnectionAssignmentRevision uint64 `json:"connection_assignment_revision"`
	RelayServiceID               string `json:"relay_service_id"`
}

func (r ServicePublisherConnectionRef) Validate() error {
	if !opaqueid.Valid(r.ServiceID, opaqueid.ServicePrefix) ||
		!opaqueid.Valid(r.ServiceRunID, opaqueid.ServiceRunPrefix) || r.RunNumber == 0 ||
		!opaqueid.Valid(r.PublisherConnectionID, opaqueid.PublisherConnectionPrefix) || r.ConnectionSlot > 1 ||
		r.ConnectionAssignmentRevision == 0 || !validIdentifier(r.RelayServiceID) {
		return errors.New("tunnelv1: invalid private publisher connection reference")
	}
	return nil
}

// Message is a closed union of control-stream messages.
type Message struct {
	Type                  MessageType                    `json:"type"`
	ProtocolVersion       uint32                         `json:"protocol_version"`
	RequestID             string                         `json:"request_id,omitempty"`
	Role                  PeerRole                       `json:"role,omitempty"`
	Credential            string                         `json:"credential,omitempty"`
	PublisherConnection   *PublisherConnectionRef        `json:"publisher_connection,omitempty"`
	ServiceConnection     *ServicePublisherConnectionRef `json:"service_connection,omitempty"`
	NativePairLegProof    *NativePairLegProof            `json:"native_pair_leg_proof,omitempty"`
	NativePairLegAccepted *NativePairLegAccepted         `json:"native_pair_leg_accepted,omitempty"`
	Code                  ErrorCode                      `json:"code,omitempty"`
}

type StreamKind string

const (
	VisitorStream            StreamKind = "visitor"
	InternalForwardingStream StreamKind = "internal_forward"
	PublisherAdmissionStream StreamKind = "publisher_admission"
	IngressAdmissionStream   StreamKind = "ingress_admission"
	ConnectorVisitorStream   StreamKind = "connector_visitor"
	ServiceForwardingStream  StreamKind = "service_forward"
)

// VisitorStreamHeader identifies one visitor stream opened on a publisher connection.
type VisitorStreamHeader struct {
	Reservation                  StreamReservation `json:"stream_reservation,omitzero"`
	TraceContext                 TraceContext      `json:"trace_context,omitzero"`
	ProtocolVersion              uint32            `json:"protocol_version"`
	Kind                         StreamKind        `json:"kind"`
	VisitorConnectionID          string            `json:"visitor_connection_id"`
	PublicURLID                  string            `json:"public_url_id"`
	PublishRunID                 string            `json:"publish_run_id"`
	PublishRunNumber             uint64            `json:"publish_run_number"`
	PublisherConnectionID        string            `json:"publisher_connection_id"`
	ConnectionAssignmentRevision uint64            `json:"connection_assignment_revision"`
	// AccessPending is trusted ingress state: this visitor has only bounded
	// pending authorization capacity until the publisher authorizes it.
	AccessPending      bool `json:"access_pending,omitempty"`
	ConfirmBeforeBytes bool `json:"confirm_before_bytes,omitempty"`
}

// InternalForwardingHeader identifies one visitor connection sent from ingress to a connected relay.
type InternalForwardingHeader struct {
	Reservation                  StreamReservation `json:"stream_reservation,omitzero"`
	TraceContext                 TraceContext      `json:"trace_context,omitzero"`
	ProtocolVersion              uint32            `json:"protocol_version"`
	IngressRegion                string            `json:"ingress_region,omitempty"`
	Kind                         StreamKind        `json:"kind"`
	VisitorConnectionID          string            `json:"visitor_connection_id"`
	PublicURLID                  string            `json:"public_url_id"`
	PublishRunID                 string            `json:"publish_run_id"`
	PublishRunNumber             uint64            `json:"publish_run_number"`
	PublisherConnectionID        string            `json:"publisher_connection_id"`
	ConnectionSlot               uint8             `json:"connection_slot"`
	ConnectionAssignmentRevision uint64            `json:"connection_assignment_revision"`
	RelayServiceID               string            `json:"relay_service_id"`
	RelayID                      string            `json:"relay_id"`
	RelayRunID                   string            `json:"relay_run_id"`
	RelayLeaseRevision           uint64            `json:"relay_lease_revision"`
	PublicUrlExpiresAt           time.Time         `json:"public_url_expires_at"`
	LeaseExpiresAt               time.Time         `json:"lease_expires_at"`
	ConfirmBeforeBytes           bool              `json:"confirm_before_bytes,omitempty"`
	AccessPending                bool              `json:"access_pending,omitempty"`
}

type StreamResponseType string

const (
	StreamAccepted StreamResponseType = "accepted"
	StreamRejected StreamResponseType = "rejected"
)

// StreamResponse classifies one local admission decision.
type StreamResponse struct {
	Type StreamResponseType `json:"type"`
	Code ErrorCode          `json:"code,omitempty"`
}

func WriteControl(writer io.Writer, message Message) error {
	if err := message.Validate(); err != nil {
		return err
	}
	return writeJSONFrame(writer, message, MaxControlBytes)
}

func ReadControl(reader io.Reader) (Message, error) {
	payload, err := readFramePayload(reader, MaxControlBytes)
	if err != nil {
		return Message{}, err
	}
	// a native hello cannot smuggle even empty or null publisher credentials
	// and other roles cannot carry even a null native proof.
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(payload, &fields); err != nil {
		return Message{}, err
	}
	var role PeerRole
	if err := json.Unmarshal(fields["role"], &role); err != nil && len(fields["role"]) != 0 {
		return Message{}, err
	}
	if role == NativeConnector {
		for _, name := range []string{"credential", "publisher_connection", "service_connection"} {
			if _, present := fields[name]; present {
				return Message{}, errors.New("tunnelv1: invalid native connector fields")
			}
		}
	} else if _, present := fields["native_pair_leg_proof"]; present {
		return Message{}, errors.New("tunnelv1: native proof on another role")
	}
	if _, present := fields["native_pair_leg_accepted"]; present {
		var kind MessageType
		if err := json.Unmarshal(fields["type"], &kind); err != nil || (kind != HelloAccepted && kind != NativeLegRenewed) || role != "" || bytes.Equal(bytes.TrimSpace(fields["native_pair_leg_accepted"]), []byte("null")) {
			return Message{}, errors.New("tunnelv1: native receipt outside hello_accepted")
		}
	}
	var message Message
	if err := decodeJSONPayload(payload, &message); err != nil {
		return Message{}, err
	}
	if err := message.Validate(); err != nil {
		return Message{}, err
	}
	return message, nil
}

func WriteVisitorStreamHeader(writer io.Writer, header VisitorStreamHeader) error {
	if err := header.Validate(); err != nil {
		return err
	}
	return writeJSONFrame(writer, header, MaxHeaderBytes)
}

func ReadVisitorStreamHeader(reader io.Reader) (VisitorStreamHeader, error) {
	var header VisitorStreamHeader
	if err := readJSONFrame(reader, &header, MaxHeaderBytes); err != nil {
		return VisitorStreamHeader{}, err
	}
	if err := header.Validate(); err != nil {
		return VisitorStreamHeader{}, err
	}
	return header, nil
}

func WriteInternalForwardingHeader(writer io.Writer, header InternalForwardingHeader) error {
	if err := header.Validate(); err != nil {
		return err
	}
	return writeJSONFrame(writer, header, MaxHeaderBytes)
}

func ReadInternalForwardingHeader(reader io.Reader) (InternalForwardingHeader, error) {
	var header InternalForwardingHeader
	if err := readJSONFrame(reader, &header, MaxHeaderBytes); err != nil {
		return InternalForwardingHeader{}, err
	}
	if err := header.Validate(); err != nil {
		return InternalForwardingHeader{}, err
	}
	return header, nil
}

func WriteStreamResponse(writer io.Writer, response StreamResponse) error {
	if err := response.Validate(); err != nil {
		return err
	}
	return writeJSONFrame(writer, response, MaxHeaderBytes)
}

func ReadStreamResponse(reader io.Reader) (StreamResponse, error) {
	var response StreamResponse
	if err := readJSONFrame(reader, &response, MaxHeaderBytes); err != nil {
		return StreamResponse{}, err
	}
	if err := response.Validate(); err != nil {
		return StreamResponse{}, err
	}
	return response, nil
}

func (m Message) Validate() error {
	if m.ProtocolVersion != Version {
		return errors.New("tunnelv1: invalid protocol version")
	}
	if m.PublisherConnection != nil {
		if err := m.PublisherConnection.Validate(); err != nil {
			return err
		}
	}
	if m.ServiceConnection != nil {
		if err := m.ServiceConnection.Validate(); err != nil {
			return err
		}
	}
	if m.RequestID != "" && !validIdentifier(m.RequestID) {
		return errors.New("tunnelv1: invalid request ID")
	}
	switch m.Type {
	case Hello:
		if m.NativePairLegAccepted != nil {
			return errors.New("tunnelv1: native receipt on hello")
		}
		publisherHello := m.Role == Publisher && validCredential(m.Credential) && (m.PublisherConnection != nil) != (m.ServiceConnection != nil) && m.NativePairLegProof == nil
		ingressHello := m.Role == Ingress && validCredential(m.Credential) && m.PublisherConnection == nil && m.ServiceConnection == nil && m.NativePairLegProof == nil
		nativeHello := m.Role == NativeConnector && m.Credential == "" && m.PublisherConnection == nil && m.ServiceConnection == nil && m.NativePairLegProof != nil
		if nativeHello && m.NativePairLegProof.Validate() != nil || (!publisherHello && !ingressHello && !nativeHello) || m.RequestID != "" || m.Code != "" {
			return errors.New("tunnelv1: invalid hello")
		}
	case HelloAccepted:
		if m.RequestID != "" || m.Role != "" || m.Credential != "" || m.PublisherConnection != nil || m.ServiceConnection != nil || m.NativePairLegProof != nil || m.Code != "" ||
			(m.NativePairLegAccepted != nil && m.NativePairLegAccepted.Validate() != nil) {
			return errors.New("tunnelv1: invalid hello_accepted")
		}
	case NativeLegRenew:
		if !validIdentifier(m.RequestID) || m.Role != NativeConnector || m.Credential != "" || m.PublisherConnection != nil || m.ServiceConnection != nil ||
			m.NativePairLegProof == nil || m.NativePairLegProof.Validate() != nil || m.NativePairLegAccepted != nil || m.Code != "" {
			return errors.New("tunnelv1: invalid native leg renewal")
		}
	case NativeLegRenewed:
		if !validIdentifier(m.RequestID) || m.Role != "" || m.Credential != "" || m.PublisherConnection != nil || m.ServiceConnection != nil ||
			m.NativePairLegProof != nil || m.NativePairLegAccepted == nil || m.NativePairLegAccepted.Validate() != nil || m.Code != "" {
			return errors.New("tunnelv1: invalid native leg renewal receipt")
		}
	case Ping, Pong, Drain, Draining, Drained:
		if !validIdentifier(m.RequestID) || m.Role != "" || m.Credential != "" || m.PublisherConnection != nil || m.ServiceConnection != nil || m.NativePairLegProof != nil || m.NativePairLegAccepted != nil || m.Code != "" {
			return fmt.Errorf("tunnelv1: invalid %s", m.Type)
		}
	case GoAway:
		if m.RequestID != "" || m.Role != "" || m.Credential != "" || m.PublisherConnection != nil || m.ServiceConnection != nil || m.NativePairLegProof != nil || m.NativePairLegAccepted != nil || !validErrorCode(m.Code) {
			return errors.New("tunnelv1: invalid goaway")
		}
	case Error:
		if m.Role != "" || m.Credential != "" || m.PublisherConnection != nil || m.ServiceConnection != nil || m.NativePairLegProof != nil || m.NativePairLegAccepted != nil || !validErrorCode(m.Code) {
			return errors.New("tunnelv1: invalid error")
		}
	default:
		return errors.New("tunnelv1: unknown message type")
	}
	return nil
}

func (r PublisherConnectionRef) Validate() error {
	if !validIdentifier(r.PublishRunID) || !validIdentifier(r.PublicURLID) || r.PublishRunNumber == 0 ||
		!validIdentifier(r.PublisherConnectionID) || r.ConnectionSlot > 1 ||
		r.ConnectionAssignmentRevision == 0 || !validIdentifier(r.RelayServiceID) {
		return errors.New("tunnelv1: invalid publisher connection reference")
	}
	return nil
}

func (h VisitorStreamHeader) Validate() error {
	if err := h.Reservation.validatePublicBinding(h.PublicURLID, h.PublishRunID, h.PublishRunNumber, h.VisitorConnectionID); err != nil {
		return err
	}
	if err := h.TraceContext.Validate(); err != nil {
		return err
	}
	if h.ProtocolVersion != Version || h.Kind != VisitorStream || !validIdentifier(h.VisitorConnectionID) ||
		!validIdentifier(h.PublicURLID) || !validIdentifier(h.PublishRunID) || h.PublishRunNumber == 0 ||
		!validIdentifier(h.PublisherConnectionID) || h.ConnectionAssignmentRevision == 0 {
		return errors.New("tunnelv1: invalid visitor stream header")
	}
	return nil
}

func (h InternalForwardingHeader) Validate() error {
	if err := h.Reservation.validatePublicBinding(h.PublicURLID, h.PublishRunID, h.PublishRunNumber, h.VisitorConnectionID); err != nil {
		return err
	}
	if err := h.TraceContext.Validate(); err != nil {
		return err
	}
	if h.ProtocolVersion != Version || h.Kind != InternalForwardingStream || !validIdentifier(h.VisitorConnectionID) ||
		!validIdentifier(h.PublicURLID) || !validIdentifier(h.PublishRunID) || h.PublishRunNumber == 0 ||
		!validIdentifier(h.PublisherConnectionID) || h.ConnectionSlot > 1 || h.ConnectionAssignmentRevision == 0 ||
		!validIdentifier(h.RelayServiceID) || !validIdentifier(h.RelayID) || !validIdentifier(h.RelayRunID) ||
		h.RelayLeaseRevision == 0 || h.PublicUrlExpiresAt.IsZero() || h.LeaseExpiresAt.IsZero() {
		return errors.New("tunnelv1: invalid internal forwarding header")
	}
	if !validForwardingRegion(h.IngressRegion) {
		return errors.New("tunnelv1: invalid ingress region")
	}
	return nil
}

func validForwardingRegion(value string) bool {
	if value == "" || value == "local" {
		return true // older v1 senders omit their region
	}
	if len(value) != 3 {
		return false
	}
	for _, letter := range value {
		if letter < 'a' || letter > 'z' {
			return false
		}
	}
	return true
}

func (r StreamResponse) Validate() error {
	switch r.Type {
	case StreamAccepted:
		if r.Code != "" {
			return errors.New("tunnelv1: accepted stream has an error code")
		}
	case StreamRejected:
		if !validErrorCode(r.Code) {
			return errors.New("tunnelv1: rejected stream requires an error code")
		}
	default:
		return errors.New("tunnelv1: invalid stream response")
	}
	return nil
}

func validCredential(value string) bool {
	return value != "" && len(value) <= MaxCredentialLen && strings.TrimSpace(value) == value
}

func validIdentifier(value string) bool {
	return value != "" && len(value) <= 256 && strings.TrimSpace(value) == value
}

func validErrorCode(code ErrorCode) bool {
	switch code {
	case InvalidMessage, Unauthenticated, StalePublishRunNumber, StaleConnectionAssignment,
		DuplicatePublisherConnection, DrainingPublisherConnection, CapacityExceeded, Unavailable, Internal:
		return true
	default:
		return false
	}
}

func writeJSONFrame(writer io.Writer, value any, limit int) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(payload) == 0 || len(payload) > limit {
		return errors.New("tunnelv1: frame exceeds limit")
	}
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(payload)))
	if _, err := io.Copy(writer, bytes.NewReader(size[:])); err != nil {
		return err
	}
	_, err = io.Copy(writer, bytes.NewReader(payload))
	return err
}

func readJSONFrame(reader io.Reader, value any, limit int) error {
	payload, err := readFramePayload(reader, limit)
	if err != nil {
		return err
	}
	return decodeJSONPayload(payload, value)
}

func decodeJSONPayload(payload []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("tunnelv1: trailing JSON value")
	}
	return nil
}

func readFramePayload(reader io.Reader, limit int) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > uint32(limit) {
		return nil, errors.New("tunnelv1: frame exceeds limit")
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return nil, err
	}
	return payload, nil
}
