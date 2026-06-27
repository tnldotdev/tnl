package controlstate

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
)

var (
	ErrIngressAlreadyRunning = errors.New("controlstate: ingress identity already has a live process run")
	ErrIngressLeaseStale     = errors.New("controlstate: ingress lease identity or revision is stale")
)

// IngressRegistration describes one ingress process run.
type IngressRegistration struct {
	IngressID          string
	IngressRunID       string
	ProtocolVersion    uint64
	ConnectionCapacity uint64
}

// IngressLeaseIdentity identifies one exact ingress process lease.
type IngressLeaseIdentity struct {
	IngressID            string
	IngressRunID         string
	IngressLeaseRevision uint64
}

// IngressRenewal reports load and applied routing-table state.
type IngressRenewal struct {
	IngressLeaseIdentity
	ReportedConnections  uint64
	RoutingTableRevision uint64
}

// IngressLease is the control-issued lease for one ingress process.
type IngressLease struct {
	IngressLeaseIdentity
	ProtocolVersion        uint64
	ConnectionCapacity     uint64
	ReportedConnections    uint64
	RoutingTableRevision   uint64
	VisitorNetworkHashKeys [2]VisitorNetworkHashKey
	Draining               bool
	DrainDeadline          *time.Time
	RegisteredAt           time.Time
	RenewedAt              time.Time
	LeaseExpiresAt         time.Time
}

// VisitorNetworkHashKey limits visitor-network pseudonyms to one UTC date.
type VisitorNetworkHashKey struct {
	UTCDate time.Time
	Key     [32]byte
}

// RegisterIngress creates or renews one ingress process lease.
func (d *Database) RegisterIngress(
	ctx context.Context,
	registration IngressRegistration,
	now time.Time,
	leaseDuration time.Duration,
) (result IngressLease, retErr error) {
	if err := validateIngressRegistration(registration, leaseDuration); err != nil {
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
	row, err := queries.RegisterIngress(ctx, controlstatedb.RegisterIngressParams{
		IngressID: registration.IngressID, IngressRunID: registration.IngressRunID,
		ProtocolVersion: protocolVersion, ConnectionCapacity: connectionCapacity,
		RegisteredAt: timestamptz(now), RenewedAt: timestamptz(now),
		LeaseExpiresAt: timestamptz(now.Add(leaseDuration)),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return IngressLease{}, ErrIngressAlreadyRunning
	}
	if err != nil {
		return IngressLease{}, fmt.Errorf("controlstate: register ingress: %w", err)
	}
	if err := ensureIngressUsageRun(ctx, queries, row); err != nil {
		return IngressLease{}, fmt.Errorf("controlstate: register ingress usage run: %w", err)
	}
	visitorNetworkHashMasterKey, err := ensureRouteUsageConfiguration(ctx, queries, now)
	if err != nil {
		return IngressLease{}, fmt.Errorf("controlstate: register ingress usage configuration: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return IngressLease{}, fmt.Errorf("controlstate: register ingress: commit: %w", err)
	}
	return ingressLease(row, visitorNetworkHashKeys(visitorNetworkHashMasterKey, now))
}

// RenewIngress extends one exact, unexpired ingress lease.
func (d *Database) RenewIngress(
	ctx context.Context,
	renewal IngressRenewal,
	now time.Time,
	leaseDuration time.Duration,
) (result IngressLease, retErr error) {
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
	routingTableRevision, ok := nonnegativeInt64(renewal.RoutingTableRevision)
	if !ok {
		return IngressLease{}, errors.New("controlstate: ingress routing-table revision is too large")
	}
	leaseRevision, _ := positiveInt64(renewal.IngressLeaseRevision)
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return IngressLease{}, fmt.Errorf("controlstate: renew ingress: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "renew ingress", &retErr)()
	queries := controlstatedb.New(tx)
	row, err := queries.RenewIngress(ctx, controlstatedb.RenewIngressParams{
		ReportedConnections: reportedConnections, RoutingTableRevision: routingTableRevision,
		RenewedAt: timestamptz(now), LeaseExpiresAt: timestamptz(now.Add(leaseDuration)),
		IngressID: renewal.IngressID, IngressRunID: renewal.IngressRunID,
		IngressLeaseRevision: leaseRevision,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return IngressLease{}, ErrIngressLeaseStale
	}
	if err != nil {
		return IngressLease{}, fmt.Errorf("controlstate: renew ingress: %w", err)
	}
	if err := ensureIngressUsageRun(ctx, queries, row); err != nil {
		return IngressLease{}, fmt.Errorf("controlstate: renew ingress usage run: %w", err)
	}
	visitorNetworkHashMasterKey, err := ensureRouteUsageConfiguration(ctx, queries, now)
	if err != nil {
		return IngressLease{}, fmt.Errorf("controlstate: renew ingress usage configuration: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return IngressLease{}, fmt.Errorf("controlstate: renew ingress: commit: %w", err)
	}
	return ingressLease(row, visitorNetworkHashKeys(visitorNetworkHashMasterKey, now))
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
	if err := ensureIngressUsageRun(ctx, queries, row); err != nil {
		return IngressLease{}, fmt.Errorf("controlstate: begin ingress drain usage run: %w", err)
	}
	visitorNetworkHashMasterKey, err := ensureRouteUsageConfiguration(ctx, queries, now)
	if err != nil {
		return IngressLease{}, fmt.Errorf("controlstate: begin ingress drain usage configuration: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return IngressLease{}, fmt.Errorf("controlstate: begin ingress drain: commit: %w", err)
	}
	return ingressLease(row, visitorNetworkHashKeys(visitorNetworkHashMasterKey, now))
}

func ensureRouteUsageConfiguration(
	ctx context.Context,
	queries *controlstatedb.Queries,
	createdAt time.Time,
) ([32]byte, error) {
	var candidate [32]byte
	if _, err := rand.Read(candidate[:]); err != nil {
		return [32]byte{}, err
	}
	configuration, err := queries.EnsureRouteUsageConfiguration(ctx, controlstatedb.EnsureRouteUsageConfigurationParams{
		VisitorNetworkHashMasterKey: candidate[:], CreatedAt: timestamptz(createdAt),
	})
	if err != nil {
		return [32]byte{}, err
	}
	if len(configuration.VisitorNetworkHashMasterKey) != len(candidate) {
		return [32]byte{}, errors.New("controlstate: invalid visitor network hash key")
	}
	return [32]byte(configuration.VisitorNetworkHashMasterKey), nil
}

func visitorNetworkHashKeys(masterKey [32]byte, now time.Time) [2]VisitorNetworkHashKey {
	day := now.UTC().Truncate(24 * time.Hour)
	var result [2]VisitorNetworkHashKey
	for index := range result {
		utcDate := day.AddDate(0, 0, index)
		mac := hmac.New(sha256.New, masterKey[:])
		_, _ = mac.Write([]byte("tnl/route-usage/visitor-day/v1\x00" + utcDate.Format(time.DateOnly)))
		result[index] = VisitorNetworkHashKey{UTCDate: utcDate, Key: [32]byte(mac.Sum(nil))}
	}
	return result
}

func ensureIngressUsageRun(
	ctx context.Context,
	queries *controlstatedb.Queries,
	lease controlstatedb.ControlIngressLease,
) error {
	_, err := queries.EnsureIngressUsageRun(ctx, controlstatedb.EnsureIngressUsageRunParams{
		IngressID: lease.IngressID, IngressRunID: lease.IngressRunID,
		IngressLeaseRevision: lease.IngressLeaseRevision, StartedAt: lease.RegisteredAt,
		LeaseExpiresAt: lease.LeaseExpiresAt, ObservedThrough: lease.RegisteredAt,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrIngressLeaseStale
	}
	return err
}

func validateIngressRegistration(registration IngressRegistration, leaseDuration time.Duration) error {
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

func ingressLease(row controlstatedb.ControlIngressLease, visitorNetworkHashKeys [2]VisitorNetworkHashKey) (IngressLease, error) {
	if row.IngressLeaseRevision <= 0 || row.ProtocolVersion <= 0 || row.ConnectionCapacity < 0 ||
		row.ReportedConnections < 0 || row.RoutingTableRevision < 0 || !row.RegisteredAt.Valid ||
		!row.RenewedAt.Valid || !row.LeaseExpiresAt.Valid {
		return IngressLease{}, errors.New("controlstate: invalid ingress lease row")
	}
	var drainDeadline *time.Time
	if row.DrainDeadline.Valid {
		value := row.DrainDeadline.Time
		drainDeadline = &value
	}
	return IngressLease{
		IngressLeaseIdentity: IngressLeaseIdentity{
			IngressID: row.IngressID, IngressRunID: row.IngressRunID,
			IngressLeaseRevision: uint64(row.IngressLeaseRevision),
		},
		ProtocolVersion: uint64(row.ProtocolVersion), ConnectionCapacity: uint64(row.ConnectionCapacity),
		ReportedConnections: uint64(row.ReportedConnections), RoutingTableRevision: uint64(row.RoutingTableRevision),
		VisitorNetworkHashKeys: visitorNetworkHashKeys,
		Draining:               row.Draining, DrainDeadline: drainDeadline, RegisteredAt: row.RegisteredAt.Time,
		RenewedAt: row.RenewedAt.Time, LeaseExpiresAt: row.LeaseExpiresAt.Time,
	}, nil
}
