package state

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/region"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

var (
	ErrRelayRegistrationConflict       = errors.New("controlstate: relay identity or service configuration conflicts with live state")
	ErrRelayLeaseStale                 = errors.New("controlstate: relay lease identity or revision is stale")
	ErrRelayDraining                   = errors.New("controlstate: relay is draining")
	ErrRelayConnectionCapacity         = errors.New("controlstate: relay connection capacity is exhausted")
	ErrPublisherConnectionRelayService = errors.New("controlstate: publisher connection is assigned to another relay service")
)

// RelayRegistration describes one relay process and its relay service.
type RelayRegistration struct {
	Region               region.ID
	PeerSigningPublicKey []byte
	RelayServiceID       string
	RelayID              string
	RelayRunID           string
	ProtocolVersion      uint64
	RelayAddress         string
	TLSServerName        string
	InternalRelayAddress string
	InternalNetworks     []netip.Prefix
	ConnectionCapacity   uint64
	StreamCapacity       uint64
}

// RelayLeaseIdentity identifies one exact relay process lease.
type RelayLeaseIdentity struct {
	RelayServiceID     string
	RelayID            string
	RelayRunID         string
	RelayLeaseRevision uint64
}

// RelayRenewal reports the relay process's current load.
type RelayRenewal struct {
	RelayLeaseIdentity
	ReportedConnections uint64
	ReportedStreams     uint64
}

// RelayLease is the control-issued lease for one relay process.
type RelayLease struct {
	RelayLeaseIdentity
	Region               region.ID
	PeerSigningPublicKey []byte
	ProtocolVersion      uint64
	RelayAddress         string
	TLSServerName        string
	InternalRelayAddress string
	ObservedAddress      *netip.Addr
	InternalNetworks     []netip.Prefix
	ConnectionCapacity   uint64
	StreamCapacity       uint64
	ReportedConnections  uint64
	ReportedStreams      uint64
	Draining             bool
	DrainDeadline        *time.Time
	RegisteredAt         time.Time
	RenewedAt            time.Time
	LeaseExpiresAt       time.Time
}

// RegisterRelay creates or renews one relay process lease. A different process
// run cannot replace an unexpired lease for the same relay identity.
func (d *Database) RegisterRelay(
	ctx context.Context,
	registration RelayRegistration,
	now time.Time,
	leaseDuration time.Duration,
) (result RelayLease, retErr error) {
	if registration.Region == "" {
		registration.Region = region.Local
	}
	if !registration.Region.Valid() {
		return result, region.ErrPreference
	}
	if err := validateRelayRegistration(registration, leaseDuration); err != nil {
		return RelayLease{}, err
	}
	if err := d.requireOpen(); err != nil {
		return RelayLease{}, err
	}
	protocolVersion, _ := positiveInt64(registration.ProtocolVersion)
	connectionCapacity, _ := positiveInt64(registration.ConnectionCapacity)
	streamCapacity, _ := positiveInt64(registration.StreamCapacity)
	internalNetworks := registration.InternalNetworks
	if internalNetworks == nil {
		internalNetworks = []netip.Prefix{}
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return RelayLease{}, err
	}
	defer rollback(ctx, tx, "register relay", &retErr)()
	queries := controlstatedb.New(tx)
	row, err := queries.RegisterRelay(ctx, controlstatedb.RegisterRelayParams{
		Region:  string(registration.Region),
		RelayID: registration.RelayID, RelayRunID: registration.RelayRunID,
		ProtocolVersion: protocolVersion, InternalRelayAddress: registration.InternalRelayAddress,
		InternalNetworks: internalNetworks, ConnectionCapacity: connectionCapacity,
		StreamCapacity: streamCapacity, RegisteredAt: timestamptz(now), RenewedAt: timestamptz(now),
		LeaseExpiresAt: timestamptz(now.Add(leaseDuration)), RelayServiceID: registration.RelayServiceID,
		RelayAddress: registration.RelayAddress, TlsServerName: registration.TLSServerName,
		PeerSigningPublicKey: registration.PeerSigningPublicKey,
	})
	if errors.Is(err, pgx.ErrNoRows) || isUniqueViolation(err) {
		return RelayLease{}, ErrRelayRegistrationConflict
	}
	if err != nil {
		return RelayLease{}, fmt.Errorf("controlstate: register relay: %w", err)
	}
	if len(registration.PeerSigningPublicKey) != 0 {
		bound, err := queries.BindRelayRunSigningKey(ctx, controlstatedb.BindRelayRunSigningKeyParams{
			RelayID: registration.RelayID, RelayRunID: registration.RelayRunID, PeerSigningPublicKey: registration.PeerSigningPublicKey,
		})
		if isUniqueViolation(err) {
			return RelayLease{}, ErrRelayRegistrationConflict
		}
		if err != nil {
			return RelayLease{}, err
		}
		if bound != 1 {
			return RelayLease{}, ErrRelayRegistrationConflict
		}
	}
	if err := queries.MarkSupersededRelayRunSigningKeys(ctx, controlstatedb.MarkSupersededRelayRunSigningKeysParams{
		RelayID: registration.RelayID, RelayRunID: registration.RelayRunID, SupersededAt: timestamptz(now),
	}); err != nil {
		return RelayLease{}, err
	}
	result, err = relayLeaseFromRegister(row)
	if err != nil {
		return RelayLease{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return RelayLease{}, err
	}
	return result, nil
}

// RenewRelay extends one exact, unexpired relay lease.
func (d *Database) RenewRelay(
	ctx context.Context,
	renewal RelayRenewal,
	now time.Time,
	leaseDuration time.Duration,
) (RelayLease, error) {
	if err := validateRelayLeaseIdentity(renewal.RelayLeaseIdentity); err != nil {
		return RelayLease{}, err
	}
	if leaseDuration <= 0 {
		return RelayLease{}, errors.New("controlstate: relay lease duration must be positive")
	}
	if err := d.requireOpen(); err != nil {
		return RelayLease{}, err
	}
	reportedConnections, ok := nonnegativeInt64(renewal.ReportedConnections)
	if !ok {
		return RelayLease{}, errors.New("controlstate: reported connection count is too large")
	}
	reportedStreams, ok := nonnegativeInt64(renewal.ReportedStreams)
	if !ok {
		return RelayLease{}, errors.New("controlstate: reported stream count is too large")
	}
	revision, _ := positiveInt64(renewal.RelayLeaseRevision)
	row, err := controlstatedb.New(d.pool).RenewRelay(ctx, controlstatedb.RenewRelayParams{
		ReportedConnections: reportedConnections, ReportedStreams: reportedStreams,
		RenewedAt: timestamptz(now), LeaseExpiresAt: timestamptz(now.Add(leaseDuration)),
		RelayServiceID: renewal.RelayServiceID, RelayID: renewal.RelayID,
		RelayRunID: renewal.RelayRunID, RelayLeaseRevision: revision,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return RelayLease{}, ErrRelayLeaseStale
	}
	if err != nil {
		return RelayLease{}, fmt.Errorf("controlstate: renew relay: %w", err)
	}
	return relayLeaseFromRenewal(row)
}

// BeginRelayDrain removes one exact relay process from placement and keeps its
// lease current through the deadline while established streams drain.
func (d *Database) BeginRelayDrain(
	ctx context.Context,
	identity RelayLeaseIdentity,
	now time.Time,
	deadline time.Time,
) (RelayLease, error) {
	if err := validateRelayLeaseIdentity(identity); err != nil {
		return RelayLease{}, err
	}
	if !deadline.After(now) {
		return RelayLease{}, errors.New("controlstate: relay drain deadline must be in the future")
	}
	if err := d.requireOpen(); err != nil {
		return RelayLease{}, err
	}
	revision, _ := positiveInt64(identity.RelayLeaseRevision)
	row, err := controlstatedb.New(d.pool).BeginRelayDrain(ctx, controlstatedb.BeginRelayDrainParams{
		DrainDeadline: timestamptz(deadline), RenewedAt: timestamptz(now),
		RelayServiceID: identity.RelayServiceID, RelayID: identity.RelayID,
		RelayRunID: identity.RelayRunID, RelayLeaseRevision: revision,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return RelayLease{}, ErrRelayLeaseStale
	}
	if err != nil {
		return RelayLease{}, fmt.Errorf("controlstate: begin relay drain: %w", err)
	}
	return relayLeaseFromDrain(row)
}

func validateRelayRegistration(registration RelayRegistration, leaseDuration time.Duration) error {
	if registration.PeerSigningPublicKey != nil && len(registration.PeerSigningPublicKey) != 32 {
		return errors.New("relay peer signing public key must be 32 bytes")
	}
	for field, value := range map[string]string{
		"relay service ID": registration.RelayServiceID, "relay ID": registration.RelayID,
		"relay process run ID": registration.RelayRunID, "relay address": registration.RelayAddress,
		"TLS server name": registration.TLSServerName, "internal relay address": registration.InternalRelayAddress,
	} {
		if !validStateText(value) {
			return fmt.Errorf("controlstate: %s is invalid", field)
		}
	}
	if _, ok := positiveInt64(registration.ProtocolVersion); !ok {
		return errors.New("controlstate: relay protocol version must be positive")
	}
	if _, ok := positiveInt64(registration.ConnectionCapacity); !ok {
		return errors.New("controlstate: relay connection capacity must be positive")
	}
	if _, ok := positiveInt64(registration.StreamCapacity); !ok {
		return errors.New("controlstate: relay stream capacity must be positive")
	}
	if leaseDuration <= 0 {
		return errors.New("controlstate: relay lease duration must be positive")
	}
	for _, prefix := range registration.InternalNetworks {
		if !prefix.IsValid() || prefix != prefix.Masked() {
			return errors.New("controlstate: relay internal network is invalid")
		}
	}
	return nil
}

func validateRelayLeaseIdentity(identity RelayLeaseIdentity) error {
	for _, value := range []string{identity.RelayServiceID, identity.RelayID, identity.RelayRunID} {
		if !validStateText(value) {
			return errors.New("controlstate: relay lease identity is invalid")
		}
	}
	if _, ok := positiveInt64(identity.RelayLeaseRevision); !ok {
		return errors.New("controlstate: relay lease revision must be positive")
	}
	return nil
}

func validateClaimRelayLease(
	lease controlstatedb.GetRelayLeaseForClaimRow,
	identity RelayLeaseIdentity,
	assignedRelayServiceID string,
	now time.Time,
) error {
	if lease.RelayServiceID != identity.RelayServiceID || lease.RelayID != identity.RelayID ||
		lease.RelayRunID != identity.RelayRunID ||
		!matchesPositiveInt64(lease.RelayLeaseRevision, identity.RelayLeaseRevision) ||
		!lease.LeaseExpiresAt.Valid || !lease.LeaseExpiresAt.Time.After(now) {
		return ErrRelayLeaseStale
	}
	if lease.RelayServiceID != assignedRelayServiceID {
		return ErrPublisherConnectionRelayService
	}
	if lease.Draining {
		return ErrRelayDraining
	}
	return nil
}

func relayLeaseFromRegister(row controlstatedb.RegisterRelayRow) (RelayLease, error) {
	return relayLease(relayLeaseValues{
		region:               row.Region,
		peerSigningPublicKey: row.PeerSigningPublicKey,
		relayID:              row.RelayID, relayServiceID: row.RelayServiceID, relayRunID: row.RelayRunID,
		relayLeaseRevision: row.RelayLeaseRevision, protocolVersion: row.ProtocolVersion,
		internalRelayAddress: row.InternalRelayAddress, observedAddress: row.ObservedAddress,
		internalNetworks: row.InternalNetworks, connectionCapacity: row.ConnectionCapacity,
		streamCapacity: row.StreamCapacity, reportedConnections: row.ReportedConnections,
		reportedStreams: row.ReportedStreams, draining: row.Draining, drainDeadline: row.DrainDeadline,
		registeredAt: row.RegisteredAt, renewedAt: row.RenewedAt, leaseExpiresAt: row.LeaseExpiresAt,
		relayAddress: row.RelayAddress, tlsServerName: row.TlsServerName,
	})
}

func relayLeaseFromRenewal(row controlstatedb.RenewRelayRow) (RelayLease, error) {
	return relayLease(relayLeaseValues{
		region:               row.Region,
		peerSigningPublicKey: row.PeerSigningPublicKey,
		relayID:              row.RelayID, relayServiceID: row.RelayServiceID, relayRunID: row.RelayRunID,
		relayLeaseRevision: row.RelayLeaseRevision, protocolVersion: row.ProtocolVersion,
		internalRelayAddress: row.InternalRelayAddress, observedAddress: row.ObservedAddress,
		internalNetworks: row.InternalNetworks, connectionCapacity: row.ConnectionCapacity,
		streamCapacity: row.StreamCapacity, reportedConnections: row.ReportedConnections,
		reportedStreams: row.ReportedStreams, draining: row.Draining, drainDeadline: row.DrainDeadline,
		registeredAt: row.RegisteredAt, renewedAt: row.RenewedAt, leaseExpiresAt: row.LeaseExpiresAt,
		relayAddress: row.RelayAddress, tlsServerName: row.TlsServerName,
	})
}

func relayLeaseFromDrain(row controlstatedb.BeginRelayDrainRow) (RelayLease, error) {
	return relayLease(relayLeaseValues{
		region:               row.Region,
		peerSigningPublicKey: row.PeerSigningPublicKey,
		relayID:              row.RelayID, relayServiceID: row.RelayServiceID, relayRunID: row.RelayRunID,
		relayLeaseRevision: row.RelayLeaseRevision, protocolVersion: row.ProtocolVersion,
		internalRelayAddress: row.InternalRelayAddress, observedAddress: row.ObservedAddress,
		internalNetworks: row.InternalNetworks, connectionCapacity: row.ConnectionCapacity,
		streamCapacity: row.StreamCapacity, reportedConnections: row.ReportedConnections,
		reportedStreams: row.ReportedStreams, draining: row.Draining, drainDeadline: row.DrainDeadline,
		registeredAt: row.RegisteredAt, renewedAt: row.RenewedAt, leaseExpiresAt: row.LeaseExpiresAt,
		relayAddress: row.RelayAddress, tlsServerName: row.TlsServerName,
	})
}

type relayLeaseValues struct {
	region                                                                                 string
	peerSigningPublicKey                                                                   []byte
	relayID, relayServiceID, relayRunID, internalRelayAddress, relayAddress, tlsServerName string
	relayLeaseRevision, protocolVersion, connectionCapacity, streamCapacity                int64
	reportedConnections, reportedStreams                                                   int64
	observedAddress                                                                        *netip.Addr
	internalNetworks                                                                       []netip.Prefix
	draining                                                                               bool
	drainDeadline, registeredAt, renewedAt, leaseExpiresAt                                 pgtype.Timestamptz
}

func relayLease(row relayLeaseValues) (RelayLease, error) {
	if !region.ID(row.region).Valid() {
		return RelayLease{}, region.ErrPreference
	}
	if row.relayLeaseRevision <= 0 || row.protocolVersion <= 0 || row.connectionCapacity < 0 ||
		row.streamCapacity < 0 || row.reportedConnections < 0 || row.reportedStreams < 0 ||
		(len(row.peerSigningPublicKey) != 0 && len(row.peerSigningPublicKey) != 32) ||
		!row.registeredAt.Valid || !row.renewedAt.Valid || !row.leaseExpiresAt.Valid {
		return RelayLease{}, errors.New("controlstate: invalid relay lease row")
	}
	var drainDeadline *time.Time
	if row.drainDeadline.Valid {
		value := row.drainDeadline.Time
		drainDeadline = &value
	}
	return RelayLease{
		Region:               region.ID(row.region),
		PeerSigningPublicKey: append([]byte(nil), row.peerSigningPublicKey...),
		RelayLeaseIdentity: RelayLeaseIdentity{
			RelayServiceID: row.relayServiceID, RelayID: row.relayID, RelayRunID: row.relayRunID,
			RelayLeaseRevision: uint64(row.relayLeaseRevision),
		},
		ProtocolVersion: uint64(row.protocolVersion), RelayAddress: row.relayAddress,
		TLSServerName: row.tlsServerName, InternalRelayAddress: row.internalRelayAddress,
		ObservedAddress: row.observedAddress, InternalNetworks: append([]netip.Prefix(nil), row.internalNetworks...),
		ConnectionCapacity: uint64(row.connectionCapacity), StreamCapacity: uint64(row.streamCapacity),
		ReportedConnections: uint64(row.reportedConnections), ReportedStreams: uint64(row.reportedStreams),
		Draining: row.draining, DrainDeadline: drainDeadline, RegisteredAt: row.registeredAt.Time,
		RenewedAt: row.renewedAt.Time, LeaseExpiresAt: row.leaseExpiresAt.Time,
	}, nil
}

func (d *Database) requireOpen() error {
	if d == nil || d.pool == nil {
		return errors.New("controlstate: database is not open")
	}
	return nil
}

func validStateText(value string) bool {
	return value != "" && len(value) <= 256 && strings.TrimSpace(value) == value && !strings.ContainsRune(value, '\x00')
}

func positiveInt64(value uint64) (int64, bool) {
	if value == 0 || value > math.MaxInt64 {
		return 0, false
	}
	return int64(value), true
}

func nonnegativeInt64(value uint64) (int64, bool) {
	if value > math.MaxInt64 {
		return 0, false
	}
	return int64(value), true
}

func positive(value uint64) int64 {
	result, _ := positiveInt64(value)
	return result
}

func matchesPositiveInt64(stored int64, value uint64) bool {
	expected, ok := positiveInt64(value)
	return ok && stored == expected
}

func timestamptz(value time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: value, Valid: true}
}

func text(value string) pgtype.Text { return pgtype.Text{String: value, Valid: true} }

func int8(value uint64) pgtype.Int8 { return pgtype.Int8{Int64: positive(value), Valid: true} }

func isUniqueViolation(err error) bool {
	var postgresError *pgconn.PgError
	return errors.As(err, &postgresError) && postgresError.Code == "23505"
}
