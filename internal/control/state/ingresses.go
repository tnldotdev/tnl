package state

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/tcpport"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/region"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

var (
	ErrIngressAlreadyRunning = errors.New("controlstate: ingress identity already has a live process run")
	ErrIngressLeaseStale     = errors.New("controlstate: ingress lease identity or revision is stale")
)

// IngressRegistration describes one ingress process run.
type IngressRegistration struct {
	Region             region.ID
	IngressID          string
	IngressRunID       string
	ProtocolVersion    uint64
	ConnectionCapacity uint64
	IngressPoolID      string
	HTTPS              bool
	ServicePortRanges  []tcpport.Range
}

// IngressLeaseIdentity identifies one exact ingress process lease.
type IngressLeaseIdentity struct {
	IngressID            string
	IngressRunID         string
	IngressLeaseRevision uint64
}

// IngressRenewal reports the current connection load for one process lease.
type IngressRenewal struct {
	IngressLeaseIdentity
	ReportedConnections uint64
}

// IngressLease is the control-issued lease for one ingress process.
type IngressLease struct {
	IngressLeaseIdentity
	Region              region.ID
	ProtocolVersion     uint64
	ConnectionCapacity  uint64
	ReportedConnections uint64
	Draining            bool
	DrainDeadline       *time.Time
	RegisteredAt        time.Time
	RenewedAt           time.Time
	LeaseExpiresAt      time.Time
	ServingUntil        time.Time
}

// RegisterIngress creates or renews one ingress process lease.
func (d *Database) RegisterIngress(
	ctx context.Context,
	registration IngressRegistration,
	now time.Time,
	leaseDuration time.Duration,
) (result IngressLease, retErr error) {
	if registration.Region == "" {
		registration.Region = region.Local
	}
	if !registration.Region.Valid() {
		return result, region.ErrPreference
	}
	if err := validateIngressRegistration(registration, leaseDuration); err != nil {
		return IngressLease{}, err
	}
	portRanges, err := ingressPortRanges(registration.ServicePortRanges)
	if err != nil {
		return IngressLease{}, err
	}
	if err := d.requireOpen(); err != nil {
		return IngressLease{}, err
	}
	protocolVersion, _ := positiveInt64(registration.ProtocolVersion)
	connectionCapacity, _ := positiveInt64(registration.ConnectionCapacity)
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return IngressLease{}, fmt.Errorf("controlstate: register ingress: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "register ingress", &retErr)()
	queries := controlstatedb.New(tx)
	if err := queries.LockIngressPoolMembership(ctx, registration.IngressPoolID); err != nil {
		return IngressLease{}, fmt.Errorf("lock ingress pool membership: %w", err)
	}
	row, err := queries.RegisterIngress(ctx, controlstatedb.RegisterIngressParams{
		Region:    string(registration.Region),
		IngressID: registration.IngressID, IngressRunID: registration.IngressRunID,
		ProtocolVersion: protocolVersion, ConnectionCapacity: connectionCapacity,
		IngressPoolID: registration.IngressPoolID, Https: registration.HTTPS, ServicePortRanges: portRanges,
		RegisteredAt: timestamptz(now), RenewedAt: timestamptz(now),
		LeaseExpiresAt: timestamptz(now.Add(leaseDuration)),
		ServingUntil:   timestamptz(now.Add(d.servingTolerance())),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		expired, lookupErr := queries.IngressRegistrationDrainExpired(ctx, controlstatedb.IngressRegistrationDrainExpiredParams{
			IngressID: registration.IngressID, IngressRunID: registration.IngressRunID,
			Region: string(registration.Region), IngressPoolID: registration.IngressPoolID,
			Https: registration.HTTPS, ServicePortRanges: portRanges, Now: timestamptz(now),
		})
		if lookupErr != nil {
			return IngressLease{}, fmt.Errorf("controlstate: classify refused ingress registration: %w", lookupErr)
		}
		if expired {
			return IngressLease{}, ErrIngressLeaseStale
		}
		return IngressLease{}, ErrIngressAlreadyRunning
	}
	if err != nil {
		return IngressLease{}, fmt.Errorf("controlstate: register ingress: %w", err)
	}
	// retain the process fence even after its runtime lease row is removed.
	if _, err := queries.FenceIngressRun(ctx, controlstatedb.FenceIngressRunParams{
		IngressID: row.IngressID, IngressRunID: row.IngressRunID, IngressLeaseRevision: row.IngressLeaseRevision,
	}); errors.Is(err, pgx.ErrNoRows) {
		return IngressLease{}, ErrIngressLeaseStale
	} else if err != nil {
		return IngressLease{}, fmt.Errorf("retain ingress process fence: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return IngressLease{}, fmt.Errorf("controlstate: register ingress: commit: %w", err)
	}
	return ingressLease(row)
}

// RenewIngress extends one exact, unexpired ingress lease.
func (d *Database) RenewIngress(
	ctx context.Context,
	renewal IngressRenewal,
	now time.Time,
	leaseDuration time.Duration,
) (result IngressLease, retErr error) {
	ctx, finish := d.observeOperation(ctx, observability.OpRenewIngress)
	defer func() { finish(retErr) }()
	if err := validateIngressLeaseIdentity(renewal.IngressLeaseIdentity); err != nil {
		return IngressLease{}, err
	}
	if leaseDuration <= 0 {
		return IngressLease{}, errors.New("controlstate: ingress lease duration must be positive")
	}
	if err := d.requireOpen(); err != nil {
		return IngressLease{}, err
	}
	reportedConnections, ok := nonnegativeInt64(renewal.ReportedConnections)
	if !ok {
		return IngressLease{}, errors.New("controlstate: reported ingress connection count is too large")
	}
	leaseRevision, _ := positiveInt64(renewal.IngressLeaseRevision)
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return IngressLease{}, fmt.Errorf("controlstate: renew ingress: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "renew ingress", &retErr)()
	queries := controlstatedb.New(tx)
	row, err := queries.RenewIngress(ctx, controlstatedb.RenewIngressParams{
		ReportedConnections: reportedConnections,
		RenewedAt:           timestamptz(now), LeaseExpiresAt: timestamptz(now.Add(leaseDuration)),
		ServingUntil: timestamptz(now.Add(d.servingTolerance())),
		IngressID:    renewal.IngressID, IngressRunID: renewal.IngressRunID,
		IngressLeaseRevision: leaseRevision,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return IngressLease{}, ErrIngressLeaseStale
	}
	if err != nil {
		return IngressLease{}, fmt.Errorf("controlstate: renew ingress: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return IngressLease{}, fmt.Errorf("controlstate: renew ingress: commit: %w", err)
	}
	return ingressLease(row)
}

// BeginIngressDrain removes one exact ingress process from readiness and keeps
// its lease current through the drain deadline.
func (d *Database) BeginIngressDrain(
	ctx context.Context,
	identity IngressLeaseIdentity,
	now time.Time,
	deadline time.Time,
) (result IngressLease, retErr error) {
	if err := validateIngressLeaseIdentity(identity); err != nil {
		return IngressLease{}, err
	}
	if !deadline.After(now) {
		return IngressLease{}, errors.New("controlstate: ingress drain deadline must be in the future")
	}
	if err := d.requireOpen(); err != nil {
		return IngressLease{}, err
	}
	leaseRevision, _ := positiveInt64(identity.IngressLeaseRevision)
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return IngressLease{}, fmt.Errorf("controlstate: begin ingress drain: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "begin ingress drain", &retErr)()
	queries := controlstatedb.New(tx)
	row, err := queries.BeginIngressDrain(ctx, controlstatedb.BeginIngressDrainParams{
		DrainDeadline: timestamptz(deadline), RenewedAt: timestamptz(now),
		IngressID: identity.IngressID, IngressRunID: identity.IngressRunID,
		IngressLeaseRevision: leaseRevision,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return IngressLease{}, ErrIngressLeaseStale
	}
	if err != nil {
		return IngressLease{}, fmt.Errorf("controlstate: begin ingress drain: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return IngressLease{}, fmt.Errorf("controlstate: begin ingress drain: commit: %w", err)
	}
	return ingressLease(row)
}

func validateIngressRegistration(registration IngressRegistration, leaseDuration time.Duration) error {
	if len(registration.ServicePortRanges) > 0 && !validStateText(registration.IngressPoolID) {
		return errors.New("ingress service port inventory is invalid")
	}
	if !validStateText(registration.IngressID) || !validStateText(registration.IngressRunID) {
		return errors.New("controlstate: ingress registration is invalid")
	}
	if _, ok := positiveInt64(registration.ProtocolVersion); !ok {
		return errors.New("controlstate: ingress protocol version must be positive")
	}
	if _, ok := positiveInt64(registration.ConnectionCapacity); !ok {
		return errors.New("controlstate: ingress connection capacity must be positive")
	}
	if leaseDuration <= 0 {
		return errors.New("controlstate: ingress lease duration must be positive")
	}
	return nil
}

func validateIngressLeaseIdentity(identity IngressLeaseIdentity) error {
	if !validStateText(identity.IngressID) || !validStateText(identity.IngressRunID) {
		return errors.New("controlstate: ingress lease identity is invalid")
	}
	if _, ok := positiveInt64(identity.IngressLeaseRevision); !ok {
		return errors.New("controlstate: ingress lease revision must be positive")
	}
	return nil
}

func requireCurrentIngressLease(
	ctx context.Context,
	queries *controlstatedb.Queries,
	identity IngressLeaseIdentity,
	now time.Time,
) error {
	if err := validateIngressLeaseIdentity(identity); err != nil {
		return err
	}
	revision, _ := positiveInt64(identity.IngressLeaseRevision)
	if _, err := queries.GetIngressLease(ctx, controlstatedb.GetIngressLeaseParams{
		IngressID: identity.IngressID, IngressRunID: identity.IngressRunID,
		IngressLeaseRevision: revision, Now: timestamptz(now),
	}); errors.Is(err, pgx.ErrNoRows) {
		return ErrIngressLeaseStale
	} else if err != nil {
		return fmt.Errorf("controlstate: read ingress lease: %w", err)
	}
	return nil
}

func lockCurrentIngressLease(
	ctx context.Context,
	queries *controlstatedb.Queries,
	identity IngressLeaseIdentity,
	now time.Time,
) (controlstatedb.ControlIngressLease, error) {
	if err := validateIngressLeaseIdentity(identity); err != nil {
		return controlstatedb.ControlIngressLease{}, err
	}
	revision, _ := positiveInt64(identity.IngressLeaseRevision)
	lease, err := queries.LockIngressLease(ctx, controlstatedb.LockIngressLeaseParams{
		IngressID: identity.IngressID, IngressRunID: identity.IngressRunID,
		IngressLeaseRevision: revision, Now: timestamptz(now),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return controlstatedb.ControlIngressLease{}, ErrIngressLeaseStale
	}
	if err != nil {
		return controlstatedb.ControlIngressLease{}, fmt.Errorf("controlstate: lock ingress lease: %w", err)
	}
	return lease, nil
}

func ingressLease(row controlstatedb.ControlIngressLease) (IngressLease, error) {
	if !region.ID(row.Region).Valid() {
		return IngressLease{}, region.ErrPreference
	}
	if row.IngressLeaseRevision <= 0 || row.ProtocolVersion <= 0 || row.ConnectionCapacity < 0 ||
		row.ReportedConnections < 0 || !row.RegisteredAt.Valid ||
		!row.RenewedAt.Valid || !row.LeaseExpiresAt.Valid {
		return IngressLease{}, errors.New("controlstate: invalid ingress lease row")
	}
	var drainDeadline *time.Time
	if row.DrainDeadline.Valid {
		value := row.DrainDeadline.Time
		drainDeadline = &value
	}
	return IngressLease{
		Region: region.ID(row.Region),
		IngressLeaseIdentity: IngressLeaseIdentity{
			IngressID: row.IngressID, IngressRunID: row.IngressRunID,
			IngressLeaseRevision: uint64(row.IngressLeaseRevision),
		},
		ProtocolVersion: uint64(row.ProtocolVersion), ConnectionCapacity: uint64(row.ConnectionCapacity),
		ReportedConnections: uint64(row.ReportedConnections),
		Draining:            row.Draining, DrainDeadline: drainDeadline, RegisteredAt: row.RegisteredAt.Time,
		RenewedAt: row.RenewedAt.Time, LeaseExpiresAt: row.LeaseExpiresAt.Time, ServingUntil: row.ServingUntil.Time,
	}, nil
}
