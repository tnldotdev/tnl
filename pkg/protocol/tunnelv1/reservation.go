package tunnelv1

import (
	"encoding/base64"
	"errors"
	"net/netip"
	"strings"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

var ErrInvalidStreamReservation = errors.New("stream reservation is invalid")

// StreamBinding identifies the exact run and ingress process authorized to use
// delegated capacity. allocations and reservations validate this independently
// of their own identifiers, slots, and visitor connection IDs.
type StreamBinding struct {
	ResourceKind, ResourceID string
	RunID                    string
	RunNumber                uint64
	IngressID, IngressRunID  string
	IngressLeaseRevision     uint64
}

func (b StreamBinding) Validate() error {
	if b.RunNumber == 0 || b.IngressLeaseRevision == 0 {
		return ErrInvalidStreamReservation
	}
	for _, id := range []string{b.IngressID, b.IngressRunID} {
		if id == "" || len(id) > 128 || strings.ContainsAny(id, "\x00\r\n\t ") {
			return ErrInvalidStreamReservation
		}
	}
	switch b.ResourceKind {
	case "public_url":
		if !opaqueid.Valid(b.ResourceID, opaqueid.PublicURLPrefix) || !opaqueid.Valid(b.RunID, opaqueid.PublishRunPrefix) {
			return ErrInvalidStreamReservation
		}
	case "service":
		if !opaqueid.Valid(b.ResourceID, opaqueid.ServicePrefix) || !opaqueid.Valid(b.RunID, opaqueid.ServiceRunPrefix) {
			return ErrInvalidStreamReservation
		}
	default:
		return ErrInvalidStreamReservation
	}
	return nil
}

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
	SourceIP             string `json:"source_ip"`
	Proof                string `json:"proof"`
}

func (r StreamReservation) Validate() error {
	if !opaqueid.Valid(r.ID, "sres_") || !opaqueid.Valid(r.AllocationID, "salloc_") || !opaqueid.Valid(r.VisitorConnectionID, opaqueid.VisitorConnectionPrefix) || r.Sequence == 0 || r.Slot >= 1<<20 {
		return ErrInvalidStreamReservation
	}
	if r.SourceIP != "" || r.Proof != "" {
		address, err := netip.ParseAddr(r.SourceIP)
		proof, decodeErr := base64.RawURLEncoding.Strict().DecodeString(r.Proof)
		if err != nil || !address.IsValid() || address.Zone() != "" || address.Unmap().String() != r.SourceIP || decodeErr != nil || len(proof) != 32 {
			return ErrInvalidStreamReservation
		}
	}
	return (StreamBinding{ResourceKind: r.ResourceKind, ResourceID: r.ResourceID, RunID: r.RunID, RunNumber: r.RunNumber,
		IngressID: r.IngressID, IngressRunID: r.IngressRunID, IngressLeaseRevision: r.IngressLeaseRevision}).Validate()
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
