package tunnelv1

import (
	"errors"
	"io"
)

// AdmissionHeader is a single-use authorization decision, carried on a separate
// multiplexed stream. the relay adds its process identity on the ingress hop.
// the authenticated sessions, not caller-supplied network addresses, bind both hops.
type AdmissionHeader struct {
	ProtocolVersion              uint32     `json:"protocol_version"`
	Kind                         StreamKind `json:"kind"`
	VisitorConnectionID          string     `json:"visitor_connection_id"`
	PublicURLID                  string     `json:"public_url_id"`
	PublishRunID                 string     `json:"publish_run_id"`
	PublishRunNumber             uint64     `json:"publish_run_number"`
	PublisherConnectionID        string     `json:"publisher_connection_id"`
	ConnectionSlot               uint8      `json:"connection_slot"`
	ConnectionAssignmentRevision uint64     `json:"connection_assignment_revision"`
	RelayServiceID               string     `json:"relay_service_id"`
	RelayID                      string     `json:"relay_id,omitempty"`
	RelayRunID                   string     `json:"relay_run_id,omitempty"`
	RelayLeaseRevision           uint64     `json:"relay_lease_revision,omitempty"`
}

type AdmissionResult = StreamResponse

func (h AdmissionHeader) Validate() error {
	if h.ProtocolVersion != Version || (h.Kind != PublisherAdmissionStream && h.Kind != IngressAdmissionStream) ||
		!validIdentifier(h.VisitorConnectionID) || !validIdentifier(h.PublicURLID) || !validIdentifier(h.PublishRunID) ||
		h.PublishRunNumber == 0 || !validIdentifier(h.PublisherConnectionID) || h.ConnectionSlot > 1 ||
		h.ConnectionAssignmentRevision == 0 || !validIdentifier(h.RelayServiceID) {
		return errors.New("tunnelv1: invalid admission identity")
	}
	if h.Kind == PublisherAdmissionStream {
		if h.RelayID != "" || h.RelayRunID != "" || h.RelayLeaseRevision != 0 {
			return errors.New("tunnelv1: publisher supplied relay process identity")
		}
	} else if !validIdentifier(h.RelayID) || !validIdentifier(h.RelayRunID) || h.RelayLeaseRevision == 0 {
		return errors.New("tunnelv1: missing admission relay process identity")
	}
	return nil
}

func WriteAdmissionHeader(w io.Writer, h AdmissionHeader) error {
	if err := h.Validate(); err != nil {
		return err
	}
	return writeJSONFrame(w, h, MaxHeaderBytes)
}
func ReadAdmissionHeader(r io.Reader) (AdmissionHeader, error) {
	var h AdmissionHeader
	if err := readJSONFrame(r, &h, MaxHeaderBytes); err != nil {
		return AdmissionHeader{}, err
	}
	return h, h.Validate()
}
func WriteAdmissionResult(w io.Writer, r AdmissionResult) error { return WriteStreamResponse(w, r) }
func ReadAdmissionResult(r io.Reader) (AdmissionResult, error)  { return ReadStreamResponse(r) }

func (h InternalForwardingHeader) Admission() AdmissionHeader {
	return AdmissionHeader{ProtocolVersion: Version, Kind: IngressAdmissionStream,
		VisitorConnectionID: h.VisitorConnectionID, PublicURLID: h.PublicURLID, PublishRunID: h.PublishRunID,
		PublishRunNumber: h.PublishRunNumber, PublisherConnectionID: h.PublisherConnectionID, ConnectionSlot: h.ConnectionSlot,
		ConnectionAssignmentRevision: h.ConnectionAssignmentRevision, RelayServiceID: h.RelayServiceID,
		RelayID: h.RelayID, RelayRunID: h.RelayRunID, RelayLeaseRevision: h.RelayLeaseRevision}
}
