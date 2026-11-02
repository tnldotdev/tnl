package tunnelv1

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/netip"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

var ErrConnectorPeerVisitorOpening = errors.New("tunnelv1: invalid connector peer visitor opening")

const ConnectorPeerVisitorStream StreamKind = "connector_peer_visitor"

// ConnectorPeerSession is the independently checked pair, relay receipt, and
// publisher run state. callers must obtain SourceIP from the checked relay
// HelloAccepted receipt, never from the application stream body.
type ConnectorPeerSession struct {
	PairID             string
	DeliveryID         string
	DeliveryGeneration int64
	ServiceID          string
	ServiceRunID       string
	RunNumber          uint64
	Subject            VisitorSubject
	SourceIP           string
	// ExpiresAt comes from trusted publisher state, not the visitor opening.
	ExpiresAt time.Time
}

func (s ConnectorPeerSession) Validate() error {
	address, err := netip.ParseAddr(s.SourceIP)
	if !opaqueid.Valid(s.PairID, "cpp_") || s.DeliveryGeneration < 1 ||
		!opaqueid.Valid(s.ServiceID, opaqueid.ServicePrefix) || !opaqueid.Valid(s.ServiceRunID, opaqueid.ServiceRunPrefix) ||
		s.RunNumber == 0 || s.RunNumber > math.MaxInt64 || s.Subject.Validate() != nil ||
		err != nil || !address.IsValid() || address.IsUnspecified() || address.Zone() != "" || address.Unmap().String() != s.SourceIP {
		return ErrConnectorPeerVisitorOpening
	}
	if _, err := ParsePeerDeliveryIdentifier(s.DeliveryID); err != nil {
		return ErrConnectorPeerVisitorOpening
	}
	return nil
}

// ConnectorPeerVisitorEntry is the application-stream opening on an inner-QUIC
// connector pair. a delivery key authenticates the carrier, not visitor access.
// SourceIP repeats the relay-attested source so the publisher can compare it
// with independently checked session state before verifying visitor permission.
type ConnectorPeerVisitorEntry struct {
	TraceContext        TraceContext               `json:"trace_context,omitzero"`
	ProtocolVersion     uint32                     `json:"protocol_version"`
	Kind                StreamKind                 `json:"kind"`
	PairID              string                     `json:"pair_id"`
	DeliveryID          string                     `json:"delivery_id"`
	DeliveryGeneration  int64                      `json:"delivery_generation"`
	ServiceID           string                     `json:"service_id"`
	ServiceRunID        string                     `json:"service_run_id"`
	RunNumber           uint64                     `json:"run_number"`
	Subject             VisitorSubject             `json:"subject"`
	SourceIP            string                     `json:"source_ip"`
	VisitorConnectionID string                     `json:"visitor_connection_id"`
	MetadataRevision    uint64                     `json:"metadata_revision"`
	Permission          ConnectorVisitorPermission `json:"permission"`
}

func (e ConnectorPeerVisitorEntry) Session() ConnectorPeerSession {
	return ConnectorPeerSession{PairID: e.PairID, DeliveryID: e.DeliveryID, DeliveryGeneration: e.DeliveryGeneration,
		ServiceID: e.ServiceID, ServiceRunID: e.ServiceRunID, RunNumber: e.RunNumber, Subject: e.Subject, SourceIP: e.SourceIP}
}

func (e ConnectorPeerVisitorEntry) Validate() error {
	if err := e.TraceContext.Validate(); err != nil {
		return err
	}
	if e.ProtocolVersion != Version || e.Kind != ConnectorPeerVisitorStream || e.Session().Validate() != nil ||
		!opaqueid.Valid(e.VisitorConnectionID, opaqueid.VisitorConnectionPrefix) ||
		e.MetadataRevision == 0 || e.MetadataRevision > math.MaxInt64 || !e.Permission.valid() {
		return ErrConnectorPeerVisitorOpening
	}
	return nil
}

// ConnectorPeerProofMessage is signed by the token subject's native key. the
// domain and ordered fields separate this proof from mux visitor and pair-leg
// proofs. hashes bind the exact signed control token and initial bytes.
// trace context remains untrusted telemetry, not part of visitor authority.
func ConnectorPeerProofMessage(e ConnectorPeerVisitorEntry, initial []byte) ([]byte, error) {
	if e.Validate() != nil || len(initial) > MaxInitialBytes {
		return nil, ErrConnectorPeerVisitorOpening
	}
	tokenHash, initialHash := sha256.Sum256([]byte(e.Permission.Token)), sha256.Sum256(initial)
	body, err := json.Marshal([]any{e.PairID, e.DeliveryID, e.DeliveryGeneration, e.ServiceID, e.ServiceRunID,
		e.RunNumber, e.Subject, e.VisitorConnectionID, e.MetadataRevision, tokenHash, e.SourceIP, initialHash})
	if err != nil {
		return nil, ErrConnectorPeerVisitorOpening
	}
	return append([]byte("tnl connector peer visitor opening v1\x00"), body...), nil
}

func WriteConnectorPeerVisitorEntry(w io.Writer, e ConnectorPeerVisitorEntry) error {
	if err := e.Validate(); err != nil {
		return err
	}
	return writeJSONFrame(w, e, MaxHeaderBytes)
}

func ReadConnectorPeerVisitorEntry(r io.Reader) (ConnectorPeerVisitorEntry, error) {
	var e ConnectorPeerVisitorEntry
	if err := readJSONFrame(r, &e, MaxHeaderBytes); err != nil {
		return ConnectorPeerVisitorEntry{}, err
	}
	if err := e.Validate(); err != nil {
		return ConnectorPeerVisitorEntry{}, err
	}
	return e, nil
}

func WriteConnectorPeerVisitorOpening(w io.Writer, e ConnectorPeerVisitorEntry, initial []byte) (bool, error) {
	n, err := writeOpening(w, nil, initial, func(w io.Writer) error { return WriteConnectorPeerVisitorEntry(w, e) })
	return n > 0, err
}

func ReadConnectorPeerVisitorOpening(r io.Reader) (ConnectorPeerVisitorEntry, []byte, error) {
	e, err := ReadConnectorPeerVisitorEntry(r)
	if err != nil {
		return ConnectorPeerVisitorEntry{}, nil, err
	}
	initial, err := ReadInitialBytes(r)
	if err != nil {
		return ConnectorPeerVisitorEntry{}, nil, err
	}
	return e, initial, nil
}
