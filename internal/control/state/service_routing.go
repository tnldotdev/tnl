package state

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type ServiceInventory struct {
	ServiceMetadata
	KubernetesAuth                 *controlv1.KubernetesAuth
	ID, TeamID, Name, ServiceRunID string
	RunNumber                      int64
	CreatedAt                      time.Time
}

type ConnectorSession struct {
	Subject                                  VisitorSubject
	ID, ServiceID, IdentityID, Credential    string
	DeviceID                                 string
	IngressID, IngressAddress, TLSServerName string
	SourceIP                                 netip.Addr
	ExpiresAt                                time.Time
}

type ServiceVisitorValidity struct {
	Allowed    bool
	Admitted   bool
	ValidUntil time.Time
}

type ServiceRelay struct {
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

type ServiceProjection struct {
	ServiceID, ServiceRunID, Kind string
	RunNumber, Revision           int64
	ExpiresAt                     time.Time
	ConnectedRelays               []ServiceRelay
}

type ServiceRoutingSnapshot struct {
	Revision int64
	Entries  []ServiceProjection
}

func serviceRoutingProjection(row controlstatedb.ControlServiceRoutingEvent, now time.Time) (ServiceProjection, error) {
	result := ServiceProjection{ServiceID: row.ServiceID, ServiceRunID: row.ServiceRunID.String,
		Kind: row.Kind, RunNumber: row.RunNumber.Int64, Revision: row.Revision, ExpiresAt: row.ExpiresAt.Time}
	if row.Kind == "upsert" {
		if err := json.Unmarshal(row.Projection, &result.ConnectedRelays); err != nil || len(result.ConnectedRelays) < 1 || len(result.ConnectedRelays) > 2 {
			return ServiceProjection{}, fmt.Errorf("controlstate: invalid service routing projection")
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
		return ServiceProjection{}, fmt.Errorf("controlstate: invalid service routing event")
	}
	return result, nil
}

func (d *Database) ReadServiceSnapshot(ctx context.Context, lease IngressLeaseIdentity, now time.Time) (result ServiceRoutingSnapshot, retErr error) {
	if err := validateIngressLeaseIdentity(lease); err != nil {
		return result, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "read service snapshot", &retErr)()
	q := controlstatedb.New(tx)
	if err = requireCurrentIngressLease(ctx, q, lease, now); err != nil {
		return result, err
	}
	result.Revision, err = q.ReadServiceRoutingClock(ctx)
	if err != nil {
		return result, err
	}
	rows, err := q.ListServiceRoutingSnapshot(ctx, controlstatedb.ListServiceRoutingSnapshotParams{ThroughRevision: result.Revision, Now: timestamptz(now)})
	if err != nil {
		return result, err
	}
	result.Entries = make([]ServiceProjection, 0, len(rows))
	for _, row := range rows {
		entry, err := serviceRoutingProjection(row, now)
		if err != nil {
			return ServiceRoutingSnapshot{}, err
		}
		if entry.Kind == "upsert" {
			result.Entries = append(result.Entries, entry)
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return ServiceRoutingSnapshot{}, err
	}
	return result, nil
}

func (d *Database) ReadServiceEvents(ctx context.Context, lease IngressLeaseIdentity, after int64, now time.Time) (result ServiceRoutingSnapshot, retErr error) {
	if err := validateIngressLeaseIdentity(lease); err != nil {
		return result, err
	}
	if after < 0 {
		return result, ErrServiceAccess
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "read service events", &retErr)()
	q := controlstatedb.New(tx)
	if err = requireCurrentIngressLease(ctx, q, lease, now); err != nil {
		return result, err
	}
	through, err := q.ReadServiceRoutingClock(ctx)
	if err != nil {
		return result, err
	}
	rows, err := q.ListServiceRoutingEvents(ctx, controlstatedb.ListServiceRoutingEventsParams{
		AfterRevision: after, ThroughRevision: through, PageLimit: 256,
	})
	if err != nil {
		return result, err
	}
	result.Revision = after
	result.Entries = make([]ServiceProjection, 0, len(rows))
	for _, row := range rows {
		entry, err := serviceRoutingProjection(row, now)
		if err != nil {
			return ServiceRoutingSnapshot{}, err
		}
		result.Entries = append(result.Entries, entry)
		result.Revision = row.Revision
	}
	if len(rows) == 0 {
		result.Revision = through
	}
	if err = tx.Commit(ctx); err != nil {
		return ServiceRoutingSnapshot{}, err
	}
	return result, nil
}
