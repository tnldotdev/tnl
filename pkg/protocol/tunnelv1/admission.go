package tunnelv1

import (
	"encoding/hex"
	"errors"
	"io"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

// AdmissionHeader is a single-use promotion on the visitor's outer return stream.
// the relay adds its process identity on the ingress hop.
// the authenticated sessions, not caller-supplied network addresses, bind both hops.
type AdmissionHeader struct {
	ProtocolVersion              uint32                  `json:"protocol_version"`
	Kind                         StreamKind              `json:"kind"`
	VisitorConnectionID          string                  `json:"visitor_connection_id"`
	PublicURLID                  string                  `json:"public_url_id,omitempty"`
	PublishRunID                 string                  `json:"publish_run_id,omitempty"`
	PublishRunNumber             uint64                  `json:"publish_run_number,omitempty"`
	ServiceID                    string                  `json:"service_id,omitempty"`
	ServiceRunID                 string                  `json:"service_run_id,omitempty"`
	ServiceRunNumber             uint64                  `json:"service_run_number,omitempty"`
	Visitor                      ServiceVisitorReference `json:"visitor,omitzero"`
	PublisherConnectionID        string                  `json:"publisher_connection_id"`
	ConnectionSlot               uint8                   `json:"connection_slot"`
	ConnectionAssignmentRevision uint64                  `json:"connection_assignment_revision"`
	RelayServiceID               string                  `json:"relay_service_id"`
	RelayID                      string                  `json:"relay_id,omitempty"`
	RelayRunID                   string                  `json:"relay_run_id,omitempty"`
	RelayLeaseRevision           uint64                  `json:"relay_lease_revision,omitempty"`
}

type AdmissionResult = StreamResponse

func (h AdmissionHeader) Validate() error {
	public := validIdentifier(h.PublicURLID) && validIdentifier(h.PublishRunID) && h.PublishRunNumber > 0 && h.ServiceID == "" && h.ServiceRunID == "" && h.ServiceRunNumber == 0 && h.Visitor == (ServiceVisitorReference{})
	service := opaqueid.Valid(h.ServiceID, opaqueid.ServicePrefix) && opaqueid.Valid(h.ServiceRunID, opaqueid.ServiceRunPrefix) && h.ServiceRunNumber > 0 && h.PublicURLID == "" && h.PublishRunID == "" && h.PublishRunNumber == 0 && h.Visitor.Valid()
	if h.ProtocolVersion != Version || (h.Kind != PublisherAdmissionStream && h.Kind != IngressAdmissionStream) ||
		!validIdentifier(h.VisitorConnectionID) || (!public && !service) ||
		!validIdentifier(h.PublisherConnectionID) || h.ConnectionSlot > 1 ||
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

// ServiceVisitorReference is an audit reference supplied after the publisher
// verified permission. it contains no secret and grants no visitor authority.
type ServiceVisitorReference struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

func (r ServiceVisitorReference) Valid() bool {
	switch r.Kind {
	case "certificate":
		digest, err := hex.DecodeString(r.ID)
		return err == nil && len(digest) == 32 && hex.EncodeToString(digest) == r.ID
	case "browser_session":
		return opaqueid.Valid(r.ID, opaqueid.ControlSessionPrefix)
	case "grant":
		return opaqueid.Valid(r.ID, "shg_")
	default:
		return false
	}
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

func (h ServiceForwardingHeader) Admission() AdmissionHeader {
	return AdmissionHeader{ProtocolVersion: Version, Kind: IngressAdmissionStream,
		VisitorConnectionID: h.VisitorConnectionID, ServiceID: h.ServiceID, ServiceRunID: h.ServiceRunID,
		ServiceRunNumber: h.RunNumber, PublisherConnectionID: h.PublisherConnectionID, ConnectionSlot: h.ConnectionSlot,
		ConnectionAssignmentRevision: h.ConnectionAssignmentRevision, RelayServiceID: h.RelayServiceID,
		RelayID: h.RelayID, RelayRunID: h.RelayRunID, RelayLeaseRevision: h.RelayLeaseRevision}
}
