package state

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/region"
)

var (
	ErrIngressAlreadyRunning = errors.New("controlstate: ingress identity already has a live process run")
	ErrIngressLeaseStale     = errors.New("controlstate: ingress lease identity or revision is stale")
)

// IngressRegistration describes one ingress process run.
type IngressRegistration struct {
	IngressID                                string
	IngressRunID                             string
	Region                                   region.Code
	ProtocolVersion                          uint64
	ConnectionCapacity                       uint64
	IngressPoolID                            string
	ConnectorOnly                            bool
	ServicePorts                             []int32
	ConnectorAddress, ConnectorTLSServerName string
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
	Region               region.Code
	ProtocolVersion      uint64
	ConnectionCapacity   uint64
	ReportedConnections  uint64
	RoutingTableRevision uint64
	Draining             bool
	DrainDeadline        *time.Time
	RegisteredAt         time.Time
	RenewedAt            time.Time
	LeaseExpiresAt       time.Time
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
	if registration.Region == "" {
		registration.Region = region.Local
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
		Region:          string(registration.Region),
		ProtocolVersion: protocolVersion, ConnectionCapacity: connectionCapacity,
		IngressPoolID: registration.IngressPoolID, ServicePorts: append([]int32{}, registration.ServicePorts...),
		ConnectorOnly:    registration.ConnectorOnly,
		ConnectorAddress: registration.ConnectorAddress, ConnectorTlsServerName: registration.ConnectorTLSServerName,
		RegisteredAt: timestamptz(now), RenewedAt: timestamptz(now),
		LeaseExpiresAt: timestamptz(now.Add(leaseDuration)),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		var runID string
		var expiresAt time.Time
		if err := tx.QueryRow(ctx, `SELECT ingress_run_id, lease_expires_at FROM control.ingress_leases WHERE ingress_id=$1`, registration.IngressID).Scan(&runID, &expiresAt); err != nil {
			return IngressLease{}, fmt.Errorf("read rejected ingress registration: %w", err)
		}
		if runID == registration.IngressRunID && !expiresAt.After(now) {
			return IngressLease{}, ErrIngressLeaseStale
		}
		return IngressLease{}, ErrIngressAlreadyRunning
	}
	if err != nil {
		return IngressLease{}, fmt.Errorf("controlstate: register ingress: %w", err)
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
	ctx, finish := d.observeOperation(ctx, "RenewIngress")
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
	if registration.Region != "" {
		code, ok := region.Parse(string(registration.Region))
		if !ok || code != registration.Region {
			return errors.New("controlstate: ingress region is invalid")
		}
	}
	if len(registration.ServicePorts) > 256 || len(registration.ServicePorts) > 0 && !validStateText(registration.IngressPoolID) {
		return errors.New("ingress service port inventory is invalid")
	}
	for index, port := range registration.ServicePorts {
		if port < 1024 || port > 65535 || index > 0 && port <= registration.ServicePorts[index-1] {
			return errors.New("ingress service ports must be sorted, distinct network ports")
		}
	}
	if registration.ConnectorAddress != "" || registration.ConnectorTLSServerName != "" {
		host, port, err := net.SplitHostPort(registration.ConnectorAddress)
		number, portErr := strconv.Atoi(port)
		name, nameErr := naming.CanonicalizeHostname(registration.ConnectorTLSServerName)
		_, hostErr := naming.CanonicalizeHostname(host)
		if ip, err := netip.ParseAddr(host); err == nil && ip.Zone() == "" {
			hostErr = nil
		}
		if err != nil || portErr != nil || number < 1 || number > 65535 || hostErr != nil || nameErr != nil || name != registration.ConnectorTLSServerName {
			return errors.New("controlstate: private connector address and TLS server name are invalid")
		}
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
	if code, ok := region.Parse(row.Region); !ok || code != region.Code(row.Region) {
		return IngressLease{}, errors.New("controlstate: ingress region is invalid")
	}
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
		Region: region.Code(row.Region),
		IngressLeaseIdentity: IngressLeaseIdentity{
			IngressID: row.IngressID, IngressRunID: row.IngressRunID,
			IngressLeaseRevision: uint64(row.IngressLeaseRevision),
		},
		ProtocolVersion: uint64(row.ProtocolVersion), ConnectionCapacity: uint64(row.ConnectionCapacity),
		ReportedConnections: uint64(row.ReportedConnections), RoutingTableRevision: uint64(row.RoutingTableRevision),
		Draining: row.Draining, DrainDeadline: drainDeadline, RegisteredAt: row.RegisteredAt.Time,
		RenewedAt: row.RenewedAt.Time, LeaseExpiresAt: row.LeaseExpiresAt.Time,
	}, nil
}
