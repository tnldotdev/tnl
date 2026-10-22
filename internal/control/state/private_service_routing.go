package controlstate

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type PrivateServiceInventory struct {
	PrivateServiceMetadata
	KubernetesAuth                 *controlv1.KubernetesAuth
	ID, TeamID, Name, PrivateRunID string
	RunNumber                      int64
	CreatedAt                      time.Time
}

type PrivateConnectorSession struct {
	Subject                                      VisitorSubject
	ID, PrivateServiceID, IdentityID, Credential string
	DeviceID                                     string
	IngressID, IngressAddress, TLSServerName     string
	SourceIP                                     netip.Addr
	ExpiresAt                                    time.Time
}

type PrivateVisitorValidity struct {
	Allowed    bool
	Admitted   bool
	ValidUntil time.Time
}

type PrivateServiceRelay struct {
	TLSServerName                string    `json:"tls_server_name"`
	PublisherConnectionID        string    `json:"publisher_connection_id"`
	ConnectionSlot               int16     `json:"connection_slot"`
	RelayServiceID               string    `json:"relay_service_id"`
	RelayID                      string    `json:"relay_id"`
	RelayRunID                   string    `json:"relay_run_id"`
	InternalRelayAddress         string    `json:"internal_relay_address"`
	RelayLeaseRevision           int64     `json:"relay_lease_revision"`
	ConnectionAssignmentRevision int64     `json:"connection_assignment_revision"`
	LeaseExpiresAt               time.Time `json:"lease_expires_at"`
}

type PrivateServiceProjection struct {
	PrivateServiceID, PrivateRunID, Kind string
	RunNumber, Revision                  int64
	ExpiresAt                            time.Time
	ConnectedRelays                      []PrivateServiceRelay
}

type PrivateServiceRoutingSnapshot struct {
	Revision int64
	Entries  []PrivateServiceProjection
}

func privateRoutingProjection(row controlstatedb.ControlPrivateServiceRoutingEvent, now time.Time) (PrivateServiceProjection, error) {
	result := PrivateServiceProjection{PrivateServiceID: row.PrivateServiceID, PrivateRunID: row.PrivateRunID.String,
		Kind: row.Kind, RunNumber: row.RunNumber.Int64, Revision: row.Revision, ExpiresAt: row.ExpiresAt.Time}
	if row.Kind == "upsert" {
		if err := json.Unmarshal(row.Projection, &result.ConnectedRelays); err != nil || len(result.ConnectedRelays) < 1 || len(result.ConnectedRelays) > 2 {
			return PrivateServiceProjection{}, fmt.Errorf("controlstate: invalid private service routing projection")
		}
		live := result.ConnectedRelays[:0]
		for _, relay := range result.ConnectedRelays {
			if relay.LeaseExpiresAt.After(now) {
				live = append(live, relay)
			}
		}
		result.ConnectedRelays = live
		if len(live) == 0 || !row.ExpiresAt.Time.After(now) {
			result.Kind, result.ConnectedRelays = "tombstone", nil
		}
	} else if row.Kind != "tombstone" {
		return PrivateServiceProjection{}, fmt.Errorf("controlstate: invalid private service routing event")
	}
	return result, nil
}

func (d *Database) ReadPrivateServiceSnapshot(ctx context.Context, lease IngressLeaseIdentity, now time.Time) (result PrivateServiceRoutingSnapshot, retErr error) {
	if err := validateIngressLeaseIdentity(lease); err != nil {
		return result, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "read private service snapshot", &retErr)()
	q := controlstatedb.New(tx)
	if err = requireCurrentIngressLease(ctx, q, lease, now); err != nil {
		return result, err
	}
	result.Revision, err = q.ReadPrivateServiceRoutingClock(ctx)
	if err != nil {
		return result, err
	}
	rows, err := q.ListPrivateServiceRoutingSnapshot(ctx, controlstatedb.ListPrivateServiceRoutingSnapshotParams{ThroughRevision: result.Revision, Now: timestamptz(now)})
	if err != nil {
		return result, err
	}
	result.Entries = make([]PrivateServiceProjection, 0, len(rows))
	for _, row := range rows {
		entry, err := privateRoutingProjection(row, now)
		if err != nil {
			return PrivateServiceRoutingSnapshot{}, err
		}
		if entry.Kind == "upsert" {
			result.Entries = append(result.Entries, entry)
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return PrivateServiceRoutingSnapshot{}, err
	}
	return result, nil
}

func (d *Database) ReadPrivateServiceEvents(ctx context.Context, lease IngressLeaseIdentity, after int64, now time.Time) (result PrivateServiceRoutingSnapshot, retErr error) {
	if err := validateIngressLeaseIdentity(lease); err != nil {
		return result, err
	}
	if after < 0 {
		return result, ErrPrivateServiceAccess
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "read private service events", &retErr)()
	q := controlstatedb.New(tx)
	if err = requireCurrentIngressLease(ctx, q, lease, now); err != nil {
		return result, err
	}
	through, err := q.ReadPrivateServiceRoutingClock(ctx)
	if err != nil {
		return result, err
	}
	rows, err := q.ListPrivateServiceRoutingEvents(ctx, controlstatedb.ListPrivateServiceRoutingEventsParams{
		AfterRevision: after, ThroughRevision: through, PageLimit: 256,
	})
	if err != nil {
		return result, err
	}
	result.Revision = after
	result.Entries = make([]PrivateServiceProjection, 0, len(rows))
	for _, row := range rows {
		entry, err := privateRoutingProjection(row, now)
		if err != nil {
			return PrivateServiceRoutingSnapshot{}, err
		}
		result.Entries = append(result.Entries, entry)
		result.Revision = row.Revision
	}
	if len(rows) == 0 {
		result.Revision = through
	}
	if err = tx.Commit(ctx); err != nil {
		return PrivateServiceRoutingSnapshot{}, err
	}
	return result, nil
}
