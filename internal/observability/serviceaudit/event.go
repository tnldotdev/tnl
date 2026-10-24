// package serviceaudit defines the allowlisted service audit boundary. observations
// are best-effort until control commits them; a process crash loses queued memory.
package serviceaudit

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

const MaxBatch = 256
const MaxPayloadBytes = 256 << 10
const Retention = 30 * 24 * time.Hour

var ErrInvalid = errors.New("invalid service audit event")

// event fields deliberately exclude arbitrary metadata, request bodies, paths,
// credentials, keys, target addresses and configuration snapshots.
type Event struct {
	ID                    string    `json:"id"`
	Cursor                string    `json:"cursor"`
	TeamID                string    `json:"team_id"`
	ServiceID             string    `json:"service_id"`
	ServiceKind           string    `json:"service_kind"`
	EventType             string    `json:"event_type"`
	OccurredAt            time.Time `json:"occurred_at"`
	ActorIdentityID       string    `json:"actor_identity_id,omitempty"`
	DeviceID              string    `json:"device_id,omitempty"`
	PublisherIdentityID   string    `json:"publisher_identity_id,omitempty"`
	RunID                 string    `json:"run_id,omitempty"`
	VisitorConnectionID   string    `json:"visitor_connection_id,omitempty"`
	SourceIP              string    `json:"source_ip,omitempty"`
	Outcome               string    `json:"outcome,omitempty"`
	Reason                string    `json:"reason,omitempty"`
	ConfigurationRevision int64     `json:"configuration_revision,omitempty"`
}

// observation carries only component-known facts. control derives team and
// actor scope from authenticated leases, runs and admitted private visitors.
type Observation struct {
	EventID             string                           `json:"event_id"`
	ServiceID           string                           `json:"service_id"`
	ServiceKind         string                           `json:"service_kind"`
	EventType           string                           `json:"event_type"`
	OccurredAt          time.Time                        `json:"occurred_at"`
	RunID               string                           `json:"run_id"`
	RunNumber           int64                            `json:"run_number"`
	ConnectorSessionID  string                           `json:"connector_session_id,omitempty"`
	StreamAllocationID  string                           `json:"stream_allocation_id,omitempty"`
	VisitorReference    tunnelv1.ServiceVisitorReference `json:"visitor_reference,omitzero"`
	VisitorConnectionID string                           `json:"visitor_connection_id"`
	SourceIP            string                           `json:"source_ip,omitempty"`
	Outcome             string                           `json:"outcome"`
	Reason              string                           `json:"reason,omitempty"`
}

type Batch struct {
	Events []Observation `json:"events"`
}

// Sink must return immediately; Queue implements it without network I/O.
type Sink interface{ Observe(Observation) bool }

func NewID() string {
	id, err := opaqueid.New("sae_")
	if err != nil {
		return ""
	}
	return id
}

// StableID is for committed mutation/request identities, never secrets or
// user-supplied plaintext configuration. retries of the same mutation dedup.
func StableID(scope, operation, requestID string) string {
	h := sha256.Sum256([]byte(scope + "\x00" + operation + "\x00" + requestID))
	return "sae_" + hex.EncodeToString(h[:])
}

func validID(id string) bool {
	if !strings.HasPrefix(id, "sae_") {
		return false
	}
	s := strings.TrimPrefix(id, "sae_")
	if len(s) != 22 && len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

func ValidService(id, kind string) bool {
	return kind == "public_url" && opaqueid.Valid(id, opaqueid.PublicURLPrefix) || kind == "service" && opaqueid.Valid(id, opaqueid.ServicePrefix)
}

// ValidReference accepts native and authority-issued identifiers. stored scope
// must still be verified by control; syntax alone never authenticates an actor.
func ValidReference(value string) bool {
	if len(value) < 1 || len(value) > 256 {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

func ValidReason(reason string) bool {
	switch reason {
	case "", "ip_policy", "capacity", "draining", "unavailable", "authorization", "invalid_request", "forwarding", "closed", "revoked", "expired", "cancelled":
		return true
	}
	return false
}

func (o Observation) Validate() error {
	if !validID(o.EventID) || !ValidService(o.ServiceID, o.ServiceKind) || o.OccurredAt.IsZero() || o.RunNumber < 0 ||
		!opaqueid.Valid(o.VisitorConnectionID, opaqueid.VisitorConnectionPrefix) || !ValidReason(o.Reason) {
		return ErrInvalid
	}
	if o.ConnectorSessionID != "" && !opaqueid.Valid(o.ConnectorSessionID, opaqueid.ConnectorSessionPrefix) {
		return ErrInvalid
	}
	if o.StreamAllocationID != "" && (!opaqueid.Valid(o.StreamAllocationID, "salloc_") || o.ServiceKind != "service" || o.RunID == "") {
		return ErrInvalid
	}
	if o.VisitorReference != (tunnelv1.ServiceVisitorReference{}) && (!o.VisitorReference.Valid() || o.ServiceKind != "service" || o.ConnectorSessionID != "" || o.RunID == "") {
		return ErrInvalid
	}
	serviceDenial := o.RunID == "" && o.RunNumber == 0 && o.EventType == "connection.open" &&
		(o.Outcome == "denied" || o.ServiceKind == "public_url" && o.Outcome == "failed")
	if !serviceDenial && (o.RunNumber < 1 || o.ServiceKind == "public_url" && !opaqueid.Valid(o.RunID, opaqueid.PublishRunPrefix) ||
		o.ServiceKind == "service" && !opaqueid.Valid(o.RunID, opaqueid.ServiceRunPrefix)) {
		return ErrInvalid
	}
	if o.ServiceKind == "service" && (o.ConnectorSessionID == "" && o.RunID == "" || o.SourceIP == "") ||
		o.ServiceKind == "public_url" && o.ConnectorSessionID != "" {
		return ErrInvalid
	}
	if o.SourceIP != "" {
		ip, err := netip.ParseAddr(o.SourceIP)
		if err != nil || ip.Zone() != "" || ip.Unmap().String() != o.SourceIP {
			return ErrInvalid
		}
	}
	switch o.EventType {
	case "connection.open", "connection.close":
		if o.Outcome != "allowed" && o.Outcome != "denied" && o.Outcome != "failed" && o.Outcome != "forwarded" && o.Outcome != "closed" {
			return ErrInvalid
		}
	case "http.decision":
		if o.ServiceKind != "public_url" || o.Outcome != "allowed" && o.Outcome != "denied" && o.Outcome != "failed" {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func Emit(s Sink, o Observation) {
	if s == nil {
		return
	}
	if o.EventID == "" {
		o.EventID = NewID()
	}
	if o.OccurredAt.IsZero() {
		o.OccurredAt = time.Now().UTC()
	}
	s.Observe(o)
}
