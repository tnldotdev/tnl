package tunnelv1

import (
	"errors"
	"strings"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

var ErrInvalidStreamReservation = errors.New("stream reservation is invalid")

// StreamReservation names capacity already held by the exact ingress process.
// its control allocation is prepared state, not a visitor permission credential.
type StreamReservation struct {
	ID                   string `json:"reservation_id"`
	AllocationID         string `json:"allocation_id"`
	Slot                 uint32 `json:"slot"`
	Sequence             uint64 `json:"sequence"`
	ResourceKind         string `json:"resource_kind"`
	ResourceID           string `json:"resource_id"`
	RunID                string `json:"run_id"`
	RunNumber            uint64 `json:"run_number"`
	VisitorConnectionID  string `json:"visitor_connection_id"`
	IngressID            string `json:"ingress_id"`
	IngressRunID         string `json:"ingress_run_id"`
	IngressLeaseRevision uint64 `json:"ingress_lease_revision"`
}

func (r StreamReservation) Validate() error {
	if !opaqueid.Valid(r.ID, "sres_") || !opaqueid.Valid(r.AllocationID, "salloc_") || !opaqueid.Valid(r.VisitorConnectionID, opaqueid.VisitorConnectionPrefix) || r.RunNumber == 0 || r.IngressLeaseRevision == 0 || r.Sequence == 0 || r.Slot >= 1<<20 {
		return ErrInvalidStreamReservation
	}
	for _, id := range []string{r.IngressID, r.IngressRunID} {
		if id == "" || len(id) > 128 || strings.ContainsAny(id, "\x00\r\n\t ") {
			return ErrInvalidStreamReservation
		}
	}
	switch r.ResourceKind {
	case "public_url":
		if !opaqueid.Valid(r.ResourceID, opaqueid.PublicURLPrefix) || !opaqueid.Valid(r.RunID, opaqueid.PublishRunPrefix) {
			return ErrInvalidStreamReservation
		}
	case "service":
		if !opaqueid.Valid(r.ResourceID, opaqueid.ServicePrefix) || !opaqueid.Valid(r.RunID, opaqueid.ServiceRunPrefix) {
			return ErrInvalidStreamReservation
		}
	default:
		return ErrInvalidStreamReservation
	}
	return nil
}

func (r StreamReservation) validatePublicBinding(resource, run string, number uint64, visitor string) error {
	if r == (StreamReservation{}) {
		return nil
	}
	if r.Validate() != nil || r.ResourceKind != "public_url" || r.ResourceID != resource || r.RunID != run || r.RunNumber != number || r.VisitorConnectionID != visitor {
		return ErrInvalidStreamReservation
	}
	return nil
}
