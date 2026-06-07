// Package workerv1 defines the edge-to-worker wire protocol.
package workerv1

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/tnldotdev/tnl/pkg/protocol/transportv1"
)

const (
	Subprotocol        = "tnl-worker-v1"
	Endpoint           = "/internal/v1/worker"
	MaxControlBytes    = 64 << 10
	MaxDataHeaderBytes = 1 << 10
)

type MessageType string

const (
	Hello          MessageType = "hello"
	HelloAccepted  MessageType = "hello_accepted"
	AttachRoute    MessageType = "attach_route"
	RouteReady     MessageType = "route_ready"
	DetachRoute    MessageType = "detach_route"
	RouteDrained   MessageType = "route_drained"
	WorkerDraining MessageType = "worker_draining"
	Error          MessageType = "error"
)

type ErrorCode string

const (
	InvalidMessage        ErrorCode = "invalid_message"
	StaleRouteVersion     ErrorCode = "stale_route_version"
	RouteCapacityExceeded ErrorCode = "route_capacity_exceeded"
	Internal              ErrorCode = "internal"
)

type RouteRef struct {
	RouteID      string `json:"route_id"`
	RouteVersion uint64 `json:"route_version"`
}

type Message struct {
	Type                    MessageType                    `json:"type"`
	RouteCapacity           int                            `json:"route_capacity,omitempty"`
	Route                   *RouteRef                      `json:"route,omitempty"`
	PublisherTransport      *transportv1.TailcatDescriptor `json:"publisher_transport,omitempty"`
	TailcatDialerPrivateKey string                         `json:"tailcat_dialer_private_key,omitempty"`
	Code                    ErrorCode                      `json:"code,omitempty"`
}

type DataHeader struct {
	RouteID      string `json:"route_id"`
	RouteVersion uint64 `json:"route_version"`
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

func WriteDataHeader(writer io.Writer, header DataHeader) error {
	if err := header.Validate(); err != nil {
		return err
	}
	return writeJSONFrame(writer, header, MaxDataHeaderBytes)
}

func ReadDataHeader(reader io.Reader) (DataHeader, error) {
	var header DataHeader
	if err := readJSONFrame(reader, &header, MaxDataHeaderBytes); err != nil {
		return DataHeader{}, err
	}
	if err := header.Validate(); err != nil {
		return DataHeader{}, err
	}
	return header, nil
}

func (m Message) Validate() error {
	if m.RouteCapacity < 0 {
		return errors.New("workerv1: invalid route capacity")
	}
	if m.Route != nil {
		if err := m.Route.validate(); err != nil {
			return err
		}
	}
	// Message is a closed tagged union; variants reject unrelated fields.
	switch m.Type {
	case Hello:
		if m.RouteCapacity <= 0 || m.Route != nil || m.PublisherTransport != nil || m.TailcatDialerPrivateKey != "" || m.Code != "" {
			return errors.New("workerv1: invalid hello")
		}
	case HelloAccepted, WorkerDraining:
		if m.RouteCapacity != 0 || m.Route != nil || m.PublisherTransport != nil || m.TailcatDialerPrivateKey != "" || m.Code != "" {
			return fmt.Errorf("workerv1: invalid %s", m.Type)
		}
	case AttachRoute:
		if m.Route == nil || m.PublisherTransport == nil || m.TailcatDialerPrivateKey == "" || m.RouteCapacity != 0 || m.Code != "" {
			return errors.New("workerv1: invalid attach_route")
		}
	case RouteReady, DetachRoute, RouteDrained:
		if m.Route == nil || m.RouteCapacity != 0 || m.PublisherTransport != nil || m.TailcatDialerPrivateKey != "" || m.Code != "" {
			return fmt.Errorf("workerv1: invalid %s", m.Type)
		}
	case Error:
		if m.Code != InvalidMessage && m.Code != StaleRouteVersion && m.Code != RouteCapacityExceeded && m.Code != Internal {
			return errors.New("workerv1: invalid error code")
		}
		if m.RouteCapacity != 0 || m.PublisherTransport != nil || m.TailcatDialerPrivateKey != "" {
			return errors.New("workerv1: invalid error")
		}
	default:
		return errors.New("workerv1: unknown message type")
	}
	return nil
}

func (h DataHeader) Validate() error {
	return (&RouteRef{RouteID: h.RouteID, RouteVersion: h.RouteVersion}).validate()
}

func (r *RouteRef) validate() error {
	if r == nil || strings.TrimSpace(r.RouteID) == "" || r.RouteID != strings.TrimSpace(r.RouteID) || r.RouteVersion == 0 {
		return errors.New("workerv1: invalid route reference")
	}
	return nil
}

func writeJSONFrame(writer io.Writer, value any, limit int) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(payload) == 0 || len(payload) > limit {
		return errors.New("workerv1: frame exceeds limit")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if _, err := io.Copy(writer, bytes.NewReader(header[:])); err != nil {
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
		return errors.New("workerv1: frame exceeds limit")
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
		return errors.New("workerv1: trailing JSON value")
	}
	return nil
}
