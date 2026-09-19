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
)

const (
	Version          = 1
	MaxControlBytes  = 64 << 10
	MaxHeaderBytes   = 1 << 10
	MaxCredentialLen = 4096
)

type MessageType string

const (
	Hello         MessageType = "hello"
	HelloAccepted MessageType = "hello_accepted"
	Ping          MessageType = "ping"
	Pong          MessageType = "pong"
	Drain         MessageType = "drain"
	Draining      MessageType = "draining"
	Drained       MessageType = "drained"
	GoAway        MessageType = "goaway"
	Error         MessageType = "error"
)

type PeerRole string

const (
	Publisher PeerRole = "publisher"
	Ingress   PeerRole = "ingress"
)

type ErrorCode string

const (
	InvalidMessage               ErrorCode = "invalid_message"
	Unauthenticated              ErrorCode = "unauthenticated"
	StaleRouteVersion            ErrorCode = "stale_route_version"
	StaleConnectionAssignment    ErrorCode = "stale_connection_assignment"
	DuplicatePublisherConnection ErrorCode = "duplicate_publisher_connection"
	DrainingPublisherConnection  ErrorCode = "draining"
	CapacityExceeded             ErrorCode = "capacity_exceeded"
	Unavailable                  ErrorCode = "unavailable"
	Internal                     ErrorCode = "internal"
)

// PublisherConnectionRef identifies one assigned publisher connection.
type PublisherConnectionRef struct {
	RouteSessionID               string `json:"route_session_id"`
	RouteID                      string `json:"route_id"`
	RouteVersion                 uint64 `json:"route_version"`
	PublisherConnectionID        string `json:"publisher_connection_id"`
	ConnectionSlot               uint8  `json:"connection_slot"`
	ConnectionAssignmentRevision uint64 `json:"connection_assignment_revision"`
	RelayServiceID               string `json:"relay_service_id"`
}

// Message is a closed union of control-stream messages.
type Message struct {
	Type                MessageType             `json:"type"`
	ProtocolVersion     uint32                  `json:"protocol_version"`
	RequestID           string                  `json:"request_id,omitempty"`
	Role                PeerRole                `json:"role,omitempty"`
	Credential          string                  `json:"credential,omitempty"`
	PublisherConnection *PublisherConnectionRef `json:"publisher_connection,omitempty"`
	Code                ErrorCode               `json:"code,omitempty"`
}

type StreamKind string

const (
	VisitorStream            StreamKind = "visitor"
	InternalForwardingStream StreamKind = "internal_forward"
)

// VisitorStreamHeader identifies one visitor stream opened on a publisher connection.
type VisitorStreamHeader struct {
	ProtocolVersion              uint32     `json:"protocol_version"`
	Kind                         StreamKind `json:"kind"`
	VisitorConnectionID          string     `json:"visitor_connection_id"`
	RouteID                      string     `json:"route_id"`
	RouteSessionID               string     `json:"route_session_id"`
	RouteVersion                 uint64     `json:"route_version"`
	PublisherConnectionID        string     `json:"publisher_connection_id"`
	ConnectionAssignmentRevision uint64     `json:"connection_assignment_revision"`
}

// InternalForwardingHeader identifies one visitor connection sent from ingress to a connected relay.
type InternalForwardingHeader struct {
	ProtocolVersion              uint32     `json:"protocol_version"`
	Kind                         StreamKind `json:"kind"`
	VisitorConnectionID          string     `json:"visitor_connection_id"`
	RouteID                      string     `json:"route_id"`
	RouteSessionID               string     `json:"route_session_id"`
	RouteVersion                 uint64     `json:"route_version"`
	PublisherConnectionID        string     `json:"publisher_connection_id"`
	ConnectionSlot               uint8      `json:"connection_slot"`
	ConnectionAssignmentRevision uint64     `json:"connection_assignment_revision"`
	RelayServiceID               string     `json:"relay_service_id"`
	RelayID                      string     `json:"relay_id"`
	RelayRunID                   string     `json:"relay_run_id"`
	RelayLeaseRevision           uint64     `json:"relay_lease_revision"`
	RouteExpiresAt               time.Time  `json:"route_expires_at"`
	LeaseExpiresAt               time.Time  `json:"lease_expires_at"`
}

type StreamResponseType string

const (
	StreamAccepted StreamResponseType = "accepted"
	StreamRejected StreamResponseType = "rejected"
)

// StreamResponse is sent before PROXY v2 metadata or visitor bytes are written.
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
	var message Message
	if err := readJSONFrame(reader, &message, MaxControlBytes); err != nil {
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
	if m.RequestID != "" && !validIdentifier(m.RequestID) {
		return errors.New("tunnelv1: invalid request ID")
	}
	switch m.Type {
	case Hello:
		publisherHello := m.Role == Publisher && validCredential(m.Credential) && m.PublisherConnection != nil
		ingressHello := m.Role == Ingress && validCredential(m.Credential) && m.PublisherConnection == nil
		if (!publisherHello && !ingressHello) || m.RequestID != "" || m.Code != "" {
			return errors.New("tunnelv1: invalid hello")
		}
	case HelloAccepted:
		if m.RequestID != "" || m.Role != "" || m.Credential != "" || m.PublisherConnection != nil || m.Code != "" {
			return errors.New("tunnelv1: invalid hello_accepted")
		}
	case Ping, Pong, Drain, Draining, Drained:
		if !validIdentifier(m.RequestID) || m.Role != "" || m.Credential != "" || m.PublisherConnection != nil || m.Code != "" {
			return fmt.Errorf("tunnelv1: invalid %s", m.Type)
		}
	case GoAway:
		if m.RequestID != "" || m.Role != "" || m.Credential != "" || m.PublisherConnection != nil || !validErrorCode(m.Code) {
			return errors.New("tunnelv1: invalid goaway")
		}
	case Error:
		if m.Role != "" || m.Credential != "" || m.PublisherConnection != nil || !validErrorCode(m.Code) {
			return errors.New("tunnelv1: invalid error")
		}
	default:
		return errors.New("tunnelv1: unknown message type")
	}
	return nil
}

func (r PublisherConnectionRef) Validate() error {
	if !validIdentifier(r.RouteSessionID) || !validIdentifier(r.RouteID) || r.RouteVersion == 0 ||
		!validIdentifier(r.PublisherConnectionID) || r.ConnectionSlot > 1 ||
		r.ConnectionAssignmentRevision == 0 || !validIdentifier(r.RelayServiceID) {
		return errors.New("tunnelv1: invalid publisher connection reference")
	}
	return nil
}

func (h VisitorStreamHeader) Validate() error {
	if h.ProtocolVersion != Version || h.Kind != VisitorStream || !validIdentifier(h.VisitorConnectionID) ||
		!validIdentifier(h.RouteID) || !validIdentifier(h.RouteSessionID) || h.RouteVersion == 0 ||
		!validIdentifier(h.PublisherConnectionID) || h.ConnectionAssignmentRevision == 0 {
		return errors.New("tunnelv1: invalid visitor stream header")
	}
	return nil
}

func (h InternalForwardingHeader) Validate() error {
	if h.ProtocolVersion != Version || h.Kind != InternalForwardingStream || !validIdentifier(h.VisitorConnectionID) ||
		!validIdentifier(h.RouteID) || !validIdentifier(h.RouteSessionID) || h.RouteVersion == 0 ||
		!validIdentifier(h.PublisherConnectionID) || h.ConnectionSlot > 1 || h.ConnectionAssignmentRevision == 0 ||
		!validIdentifier(h.RelayServiceID) || !validIdentifier(h.RelayID) || !validIdentifier(h.RelayRunID) ||
		h.RelayLeaseRevision == 0 || h.RouteExpiresAt.IsZero() || h.LeaseExpiresAt.IsZero() {
		return errors.New("tunnelv1: invalid internal forwarding header")
	}
	return nil
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
	case InvalidMessage, Unauthenticated, StaleRouteVersion, StaleConnectionAssignment,
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
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > uint32(limit) {
		return errors.New("tunnelv1: frame exceeds limit")
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return err
	}
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
