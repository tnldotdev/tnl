package tunnelv1

import (
	"errors"
	"io"
	"net/netip"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

// private forwarding includes up to three configured 256-byte process IDs,
// each of which may expand sixfold in JSON, plus fixed opaque IDs and metadata.
const MaxServiceHeaderBytes = 8 << 10

// ServiceStreamHeader is trusted direct ingress state forwarded through a relay.
// it has no native visitor identity: the publisher authenticates application TLS
// before target access. native visitors use the separate inner peer protocol.
type ServiceStreamHeader struct {
	TraceContext                 TraceContext     `json:"trace_context,omitzero"`
	ProtocolVersion              uint32           `json:"protocol_version"`
	Kind                         StreamKind       `json:"kind"`
	ServiceID                    string           `json:"service_id"`
	ServiceRunID                 string           `json:"service_run_id"`
	Direct                       *DirectAdmission `json:"direct,omitempty"`
	SourceIP                     string           `json:"source_ip"`
	RunNumber                    uint64           `json:"run_number"`
	VisitorConnectionID          string           `json:"visitor_connection_id"`
	PublisherConnectionID        string           `json:"publisher_connection_id"`
	ConnectionAssignmentRevision uint64           `json:"connection_assignment_revision"`
	ExpiresAt                    time.Time        `json:"expires_at"`
}

type DirectAdmission struct {
	IngressID            string `json:"ingress_id"`
	IngressRunID         string `json:"ingress_run_id"`
	IngressLeaseRevision uint64 `json:"ingress_lease_revision"`
	DestinationPort      uint16 `json:"destination_port"`
}

func (a DirectAdmission) valid() bool {
	return validIdentifier(a.IngressID) && opaqueid.Valid(a.IngressRunID, opaqueid.IngressRunPrefix) && a.IngressLeaseRevision > 0 && a.DestinationPort >= 1024
}

func (h ServiceStreamHeader) validate() error {
	if err := h.TraceContext.Validate(); err != nil {
		return err
	}
	if h.ProtocolVersion != Version || h.Kind != ServiceForwardingStream ||
		!opaqueid.Valid(h.ServiceID, opaqueid.ServicePrefix) ||
		!opaqueid.Valid(h.ServiceRunID, opaqueid.ServiceRunPrefix) || h.RunNumber == 0 ||
		!validPrivateSourceIP(h.SourceIP) ||
		!opaqueid.Valid(h.VisitorConnectionID, opaqueid.VisitorConnectionPrefix) ||
		!opaqueid.Valid(h.PublisherConnectionID, opaqueid.PublisherConnectionPrefix) ||
		h.ConnectionAssignmentRevision == 0 || h.ExpiresAt.IsZero() || h.Direct == nil || !h.Direct.valid() {
		return errors.New("tunnelv1: invalid direct service stream header")
	}
	return nil
}

func validPrivateSourceIP(value string) bool {
	addr, err := netip.ParseAddr(value)
	return err == nil && addr.IsValid() && addr.Zone() == "" && addr.String() == value
}

// ServiceForwardingHeader carries the current relay lease and direct service/run
// admission. it never accepts public URL IDs or a native connector admission.
type ServiceForwardingHeader struct {
	ServiceStreamHeader
	ConnectionSlot     uint8     `json:"connection_slot"`
	RelayServiceID     string    `json:"relay_service_id"`
	RelayID            string    `json:"relay_id"`
	RelayRunID         string    `json:"relay_run_id"`
	RelayLeaseRevision uint64    `json:"relay_lease_revision"`
	LeaseExpiresAt     time.Time `json:"lease_expires_at"`
}

func (h ServiceForwardingHeader) Validate() error {
	if err := h.ServiceStreamHeader.validate(); err != nil {
		return err
	}
	if h.ConnectionSlot > 1 || !validIdentifier(h.RelayServiceID) || !validIdentifier(h.RelayID) ||
		!opaqueid.Valid(h.RelayRunID, opaqueid.RelayRunPrefix) || h.RelayLeaseRevision == 0 || h.LeaseExpiresAt.IsZero() {
		return errors.New("tunnelv1: invalid direct service forwarding header")
	}
	return nil
}

func WriteServiceForwardingHeader(w io.Writer, h ServiceForwardingHeader) error {
	if err := h.Validate(); err != nil {
		return err
	}
	return writeJSONFrame(w, h, MaxServiceHeaderBytes)
}

func ReadServiceForwardingHeader(r io.Reader) (ServiceForwardingHeader, error) {
	var h ServiceForwardingHeader
	if err := readJSONFrame(r, &h, MaxServiceHeaderBytes); err != nil {
		return ServiceForwardingHeader{}, err
	}
	if err := h.Validate(); err != nil {
		return ServiceForwardingHeader{}, err
	}
	return h, nil
}
