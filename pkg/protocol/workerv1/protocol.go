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
	Accepted       MessageType = "accepted"
	AttachRoute    MessageType = "attach_route"
	RouteReady     MessageType = "route_ready"
	DetachRoute    MessageType = "detach_route"
	RouteDrained   MessageType = "route_drained"
	WorkerDraining MessageType = "worker_draining"
	Error          MessageType = "error"
)

type ErrorCode string

const (
	InvalidMessage  ErrorCode = "invalid_message"
	StaleAssignment ErrorCode = "stale_assignment"
	AtCapacity      ErrorCode = "at_capacity"
	Internal        ErrorCode = "internal"
)

type RouteRef struct {
	RouteID string `json:"route_id"`
	Version uint64 `json:"version"`
}

type Message struct {
	Type             MessageType                    `json:"type"`
	Capacity         int                            `json:"capacity,omitempty"`
	Route            *RouteRef                      `json:"route,omitempty"`
	Endpoint         *transportv1.TailcatDescriptor `json:"endpoint,omitempty"`
	WorkerPrivateKey string                         `json:"worker_private_key,omitempty"`
	Code             ErrorCode                      `json:"code,omitempty"`
}

type DataHeader struct {
	RouteID string `json:"route_id"`
	Version uint64 `json:"version"`
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
	if m.Capacity < 0 {
		return errors.New("workerv1: invalid capacity")
	}
	if m.Route != nil {
		if err := m.Route.validate(); err != nil {
			return err
		}
	}
	// Message is a closed tagged union; variants reject unrelated fields.
	switch m.Type {
	case Hello:
		if m.Capacity <= 0 || m.Route != nil || m.Endpoint != nil || m.WorkerPrivateKey != "" || m.Code != "" {
			return errors.New("workerv1: invalid hello")
		}
	case Accepted, WorkerDraining:
		if m.Capacity != 0 || m.Route != nil || m.Endpoint != nil || m.WorkerPrivateKey != "" || m.Code != "" {
			return fmt.Errorf("workerv1: invalid %s", m.Type)
		}
	case AttachRoute:
		if m.Route == nil || m.Endpoint == nil || m.WorkerPrivateKey == "" || m.Capacity != 0 || m.Code != "" {
			return errors.New("workerv1: invalid attach_route")
		}
	case RouteReady, DetachRoute, RouteDrained:
		if m.Route == nil || m.Capacity != 0 || m.Endpoint != nil || m.WorkerPrivateKey != "" || m.Code != "" {
			return fmt.Errorf("workerv1: invalid %s", m.Type)
		}
	case Error:
		if m.Code != InvalidMessage && m.Code != StaleAssignment && m.Code != AtCapacity && m.Code != Internal {
			return errors.New("workerv1: invalid error code")
		}
		if m.Capacity != 0 || m.Endpoint != nil || m.WorkerPrivateKey != "" {
			return errors.New("workerv1: invalid error")
		}
	default:
		return errors.New("workerv1: unknown message type")
	}
	return nil
}

func (h DataHeader) Validate() error {
	return (&RouteRef{RouteID: h.RouteID, Version: h.Version}).validate()
}

func (r *RouteRef) validate() error {
	if r == nil || strings.TrimSpace(r.RouteID) == "" || r.RouteID != strings.TrimSpace(r.RouteID) || r.Version == 0 {
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
