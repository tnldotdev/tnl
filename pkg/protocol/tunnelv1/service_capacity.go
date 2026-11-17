package tunnelv1

import (
	"errors"
	"io"
	"time"
)

// ServiceCapacityRequest asks ingress to reserve capacity for one already-open
// visitor stream. it carries no visitor credential or application bytes.
type ServiceCapacityRequest struct {
	Kind     StreamKind              `json:"kind"`
	Stream   ServiceForwardingHeader `json:"stream"`
	Deadline time.Time               `json:"deadline"`
}

func (r ServiceCapacityRequest) Validate() error {
	if r.Kind != ServiceCapacityStream || r.Stream.PublicService == nil || r.Stream.Validate() != nil ||
		r.Deadline.IsZero() || r.Deadline.After(r.Stream.ExpiresAt) || r.Deadline.After(r.Stream.ServingUntil) {
		return errors.New("tunnelv1: invalid service capacity request")
	}
	return nil
}

func WriteServiceCapacityRequest(w io.Writer, r ServiceCapacityRequest) error {
	if err := r.Validate(); err != nil {
		return err
	}
	return writeJSONFrame(w, r, MaxServiceHeaderBytes)
}

func ReadServiceCapacityRequest(r io.Reader) (ServiceCapacityRequest, error) {
	var request ServiceCapacityRequest
	if err := readJSONFrame(r, &request, MaxServiceHeaderBytes); err != nil {
		return ServiceCapacityRequest{}, err
	}
	return request, request.Validate()
}

// SameServiceStream compares the complete forwarding identity. trace context
// describes telemetry, not authority; decoding also creates new pointer values.
func SameServiceStream(a, b ServiceForwardingHeader) bool {
	if a.PublicService == nil || b.PublicService == nil || *a.PublicService != *b.PublicService {
		return false
	}
	if !a.ExpiresAt.Equal(b.ExpiresAt) || !a.ServingUntil.Equal(b.ServingUntil) {
		return false
	}
	a.PublicService, b.PublicService = nil, nil
	a.TraceContext, b.TraceContext = TraceContext{}, TraceContext{}
	a.ExpiresAt, b.ExpiresAt = time.Time{}, time.Time{}
	a.ServingUntil, b.ServingUntil = time.Time{}, time.Time{}
	return a == b
}
