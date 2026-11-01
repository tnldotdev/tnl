package tunnelv1

import (
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

var ErrConnectorPeerPairProof = errors.New("tunnelv1: invalid connector peer pair proof")

// ConnectorPeerRelayLease retains Go field names in the signed v1 JSON. the
// public HTTP representation uses snake_case; changing these names would
// invalidate signatures issued for the original v1 preparation proof.
type ConnectorPeerRelayLease struct {
	RelayServiceID     string
	RelayID            string
	RelayRunID         string
	RelayLeaseRevision uint64
}

type ConnectorPeerPairRelay struct {
	PublisherConnectionID string                  `json:"publisher_connection_id"`
	AssignmentRevision    int64                   `json:"assignment_revision"`
	RelayLease            ConnectorPeerRelayLease `json:"relay_lease"`
	RelayAddress          string                  `json:"relay_address"`
	TLSServerName         string                  `json:"tls_server_name"`
}

// ConnectorPeerPairProof binds a source's enrolled key to one run and two exact
// ready publisher connections. source authentication and current permission
// remain control's job; this value supplies only signing input.
type ConnectorPeerPairProof struct {
	ServiceID, ServiceRunID, PublisherIdentityID, IdempotencyKey string
	RunNumber                                                    int64
	Subject                                                      VisitorSubject
	Action                                                       string
	RequestedAt                                                  time.Time
	PreviousPairID                                               string
	PreviousGeneration                                           int64
	ExpectedRelays                                               [2]ConnectorPeerPairRelay
}

// Message is the sole canonical v1 preparation proof for create, replace and
// renew. the ordered array, outer snake_case and inner Go field names are
// intentional; neither the HTTP source nor the signature itself is signed.
func (p ConnectorPeerPairProof) Message() ([]byte, error) {
	if !opaqueid.Valid(p.ServiceID, opaqueid.ServicePrefix) || !opaqueid.Valid(p.ServiceRunID, opaqueid.ServiceRunPrefix) ||
		!opaqueid.Valid(p.PublisherIdentityID, opaqueid.PublisherIdentityPrefix) || p.RunNumber < 1 ||
		p.IdempotencyKey == "" || len(p.IdempotencyKey) > 128 || strings.TrimSpace(p.IdempotencyKey) != p.IdempotencyKey || strings.ContainsRune(p.IdempotencyKey, '\x00') ||
		p.Subject.Validate() != nil || p.RequestedAt.IsZero() ||
		(p.Action != "create" && p.Action != "replace" && p.Action != "renew") ||
		(p.Action == "create" && (p.PreviousPairID != "" || p.PreviousGeneration != 0)) ||
		(p.Action != "create" && (!opaqueid.Valid(p.PreviousPairID, "cpp_") || p.PreviousGeneration < 1)) ||
		p.ExpectedRelays[0].PublisherConnectionID == "" || p.ExpectedRelays[1].PublisherConnectionID == "" ||
		p.ExpectedRelays[0].RelayLease.RelayServiceID == p.ExpectedRelays[1].RelayLease.RelayServiceID {
		return nil, ErrConnectorPeerPairProof
	}
	body, err := json.Marshal([]any{p.Action, p.ServiceID, p.ServiceRunID, p.RunNumber, p.PublisherIdentityID,
		p.Subject, p.IdempotencyKey, p.RequestedAt.UTC().Truncate(time.Microsecond), p.PreviousPairID, p.PreviousGeneration, p.ExpectedRelays})
	if err != nil {
		return nil, err
	}
	return append([]byte("tnl connector peer pair v1\x00"), body...), nil
}
