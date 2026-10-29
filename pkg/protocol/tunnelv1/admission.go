package tunnelv1

import (
	"errors"
)

type PromotionKind string

const (
	PublisherPromotion PromotionKind = "publisher"
	IngressPromotion   PromotionKind = "ingress"
)

// AdmissionHeader binds a stream-local promotion to its visitor and assignment.
// the relay adds its current process identity on the ingress hop. this value
// is only carried inside ReturnPromoted, never on a separate stream.
type AdmissionHeader struct {
	ProtocolVersion              uint32        `json:"protocol_version"`
	Kind                         PromotionKind `json:"kind"`
	VisitorConnectionID          string        `json:"visitor_connection_id"`
	PublicURLID                  string        `json:"public_url_id"`
	PublishRunID                 string        `json:"publish_run_id"`
	PublishRunNumber             uint64        `json:"publish_run_number"`
	PublisherConnectionID        string        `json:"publisher_connection_id"`
	ConnectionSlot               uint8         `json:"connection_slot"`
	ConnectionAssignmentRevision uint64        `json:"connection_assignment_revision"`
	RelayServiceID               string        `json:"relay_service_id"`
	RelayID                      string        `json:"relay_id,omitempty"`
	RelayRunID                   string        `json:"relay_run_id,omitempty"`
	RelayLeaseRevision           uint64        `json:"relay_lease_revision,omitempty"`
}

type AdmissionResult = StreamResponse

func (h AdmissionHeader) Validate() error {
	if h.ProtocolVersion != Version || (h.Kind != PublisherPromotion && h.Kind != IngressPromotion) ||
		!validIdentifier(h.VisitorConnectionID) || !validIdentifier(h.PublicURLID) || !validIdentifier(h.PublishRunID) ||
		h.PublishRunNumber == 0 || !validIdentifier(h.PublisherConnectionID) || h.ConnectionSlot > 1 ||
		h.ConnectionAssignmentRevision == 0 || !validIdentifier(h.RelayServiceID) {
		return errors.New("tunnelv1: invalid admission identity")
	}
	if h.Kind == PublisherPromotion {
		if h.RelayID != "" || h.RelayRunID != "" || h.RelayLeaseRevision != 0 {
			return errors.New("tunnelv1: publisher supplied relay process identity")
		}
	} else if !validIdentifier(h.RelayID) || !validIdentifier(h.RelayRunID) || h.RelayLeaseRevision == 0 {
		return errors.New("tunnelv1: missing admission relay process identity")
	}
	return nil
}

func (h InternalForwardingHeader) Admission() AdmissionHeader {
	return AdmissionHeader{ProtocolVersion: Version, Kind: IngressPromotion,
		VisitorConnectionID: h.VisitorConnectionID, PublicURLID: h.PublicURLID, PublishRunID: h.PublishRunID,
		PublishRunNumber: h.PublishRunNumber, PublisherConnectionID: h.PublisherConnectionID, ConnectionSlot: h.ConnectionSlot,
		ConnectionAssignmentRevision: h.ConnectionAssignmentRevision, RelayServiceID: h.RelayServiceID,
		RelayID: h.RelayID, RelayRunID: h.RelayRunID, RelayLeaseRevision: h.RelayLeaseRevision}
}
