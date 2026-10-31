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

var ErrNativePeerVisitorOpening = errors.New("tunnelv1: invalid native peer visitor opening")

const NativePeerVisitorStream StreamKind = "native_peer_visitor"

// NativePeerSession is the independently checked pair, relay receipt, and
// publisher run state. callers must obtain SourceIP from the checked relay
// HelloAccepted receipt, never from the application stream body.
type NativePeerSession struct {
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

func (s NativePeerSession) Validate() error {
	address, err := netip.ParseAddr(s.SourceIP)
	if !opaqueid.Valid(s.PairID, "npp_") || s.DeliveryGeneration < 1 ||
		!opaqueid.Valid(s.ServiceID, opaqueid.ServicePrefix) || !opaqueid.Valid(s.ServiceRunID, opaqueid.ServiceRunPrefix) ||
		s.RunNumber == 0 || s.RunNumber > math.MaxInt64 || s.Subject.Validate() != nil ||
		err != nil || !address.IsValid() || address.IsUnspecified() || address.Zone() != "" || address.Unmap().String() != s.SourceIP {
		return ErrNativePeerVisitorOpening
	}
	if _, err := ParsePeerDeliveryIdentifier(s.DeliveryID); err != nil {
		return ErrNativePeerVisitorOpening
	}
	return nil
}

// NativePeerVisitorEntry is the application-stream opening on an inner-QUIC
// native pair. a delivery key authenticates the carrier, not visitor access.
// SourceIP repeats the relay-attested source so the publisher can compare it
// with independently checked session state before verifying visitor permission.
type NativePeerVisitorEntry struct {
	TraceContext        TraceContext            `json:"trace_context,omitzero"`
	ProtocolVersion     uint32                  `json:"protocol_version"`
	Kind                StreamKind              `json:"kind"`
	PairID              string                  `json:"pair_id"`
	DeliveryID          string                  `json:"delivery_id"`
	DeliveryGeneration  int64                   `json:"delivery_generation"`
	ServiceID           string                  `json:"service_id"`
	ServiceRunID        string                  `json:"service_run_id"`
	RunNumber           uint64                  `json:"run_number"`
	Subject             VisitorSubject          `json:"subject"`
	SourceIP            string                  `json:"source_ip"`
	VisitorConnectionID string                  `json:"visitor_connection_id"`
	MetadataRevision    uint64                  `json:"metadata_revision"`
	Permission          NativeVisitorPermission `json:"permission"`
}

func (e NativePeerVisitorEntry) Session() NativePeerSession {
	return NativePeerSession{PairID: e.PairID, DeliveryID: e.DeliveryID, DeliveryGeneration: e.DeliveryGeneration,
		ServiceID: e.ServiceID, ServiceRunID: e.ServiceRunID, RunNumber: e.RunNumber, Subject: e.Subject, SourceIP: e.SourceIP}
}

func (e NativePeerVisitorEntry) Validate() error {
	if err := e.TraceContext.Validate(); err != nil {
		return err
	}
	if e.ProtocolVersion != Version || e.Kind != NativePeerVisitorStream || e.Session().Validate() != nil ||
		!opaqueid.Valid(e.VisitorConnectionID, opaqueid.VisitorConnectionPrefix) ||
		e.MetadataRevision == 0 || e.MetadataRevision > math.MaxInt64 || !e.Permission.valid() {
		return ErrNativePeerVisitorOpening
	}
	return nil
}

// NativePeerProofMessage is signed by the token subject's native key. the
// domain and ordered fields separate this proof from mux visitor and pair-leg
// proofs. hashes bind the exact signed control token and initial bytes.
// trace context remains untrusted telemetry, not part of visitor authority.
func NativePeerProofMessage(e NativePeerVisitorEntry, initial []byte) ([]byte, error) {
	if e.Validate() != nil || len(initial) > MaxInitialBytes {
		return nil, ErrNativePeerVisitorOpening
	}
	tokenHash, initialHash := sha256.Sum256([]byte(e.Permission.Token)), sha256.Sum256(initial)
	body, err := json.Marshal([]any{e.PairID, e.DeliveryID, e.DeliveryGeneration, e.ServiceID, e.ServiceRunID,
		e.RunNumber, e.Subject, e.VisitorConnectionID, e.MetadataRevision, tokenHash, e.SourceIP, initialHash})
	if err != nil {
		return nil, ErrNativePeerVisitorOpening
	}
	return append([]byte("tnl native peer visitor opening v1\x00"), body...), nil
}

func WriteNativePeerVisitorEntry(w io.Writer, e NativePeerVisitorEntry) error {
	if err := e.Validate(); err != nil {
		return err
	}
	return writeJSONFrame(w, e, MaxHeaderBytes)
}

func ReadNativePeerVisitorEntry(r io.Reader) (NativePeerVisitorEntry, error) {
	var e NativePeerVisitorEntry
	if err := readJSONFrame(r, &e, MaxHeaderBytes); err != nil {
		return NativePeerVisitorEntry{}, err
	}
	if err := e.Validate(); err != nil {
		return NativePeerVisitorEntry{}, err
	}
	return e, nil
}

func WriteNativePeerVisitorOpening(w io.Writer, e NativePeerVisitorEntry, initial []byte) (bool, error) {
	n, err := writeOpening(w, nil, initial, func(w io.Writer) error { return WriteNativePeerVisitorEntry(w, e) })
	return n > 0, err
}

func ReadNativePeerVisitorOpening(r io.Reader) (NativePeerVisitorEntry, []byte, error) {
	e, err := ReadNativePeerVisitorEntry(r)
	if err != nil {
		return NativePeerVisitorEntry{}, nil, err
	}
	initial, err := ReadInitialBytes(r)
	if err != nil {
		return NativePeerVisitorEntry{}, nil, err
	}
	return e, initial, nil
}
