package controlstate

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

const tcpPortQuarantine = 7 * 24 * time.Hour

var ErrTCPPortPoolFull = errors.New("controlstate: no public TCP port is available")

type TCPPortClaim struct {
	ID, PublicURLID, IngressPoolID, Hostname string
	Port                                     uint16
	ClaimedAt                                time.Time
}

type TCPPortPoolCapacity struct {
	IngressPoolID    string
	ConfiguredPorts  int64
	ClaimedPorts     int64
	QuarantinedPorts int64
	AvailablePorts   int64
}

// AllocateTCPPort assigns one stable address to an enabled saved database URL.
// concurrent URLs race on the unique pool/port claim, never on the hostname.
func (d *Database) AllocateTCPPort(ctx context.Context, publicURLID string, now time.Time) (result TCPPortClaim, retErr error) {
	if !opaqueid.Valid(publicURLID, opaqueid.PublicURLPrefix) || now.IsZero() {
		return TCPPortClaim{}, ErrPublicURLInvalid
	}
	if err := d.requireOpen(); err != nil {
		return TCPPortClaim{}, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return TCPPortClaim{}, fmt.Errorf("controlstate: allocate TCP port: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "allocate TCP port", &retErr)()
	queries := controlstatedb.New(tx)
	if _, err := queries.LockLocalPublicURLTeamForMutation(ctx, publicURLID); errors.Is(err, pgx.ErrNoRows) {
		return TCPPortClaim{}, ErrPublicURLNotFound
	} else if err != nil {
		return TCPPortClaim{}, err
	}
	url, err := queries.LockTCPPortPublicURL(ctx, publicURLID)
	if errors.Is(err, pgx.ErrNoRows) {
		return TCPPortClaim{}, ErrPublicURLNotFound
	}
	if err != nil {
		return TCPPortClaim{}, err
	}
	if url.LifecycleState != string(PublicURLLifecycleEnabled) || url.ServiceProtocol != "postgres" && url.ServiceProtocol != "mysql" {
		return TCPPortClaim{}, ErrPublicURLInvalid
	}
	existing, err := queries.GetHeldTCPPortClaim(ctx, publicURLID)
	if err == nil {
		if existing.IngressPoolID != url.IngressPoolID || existing.CanonicalHostname != url.CanonicalHostname ||
			!url.PublicPort.Valid || url.PublicPort.Int32 != existing.Port {
			return TCPPortClaim{}, ErrPublicURLMutationStale
		}
		if err := tx.Commit(ctx); err != nil {
			return TCPPortClaim{}, err
		}
		return tcpPortClaim(existing), nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return TCPPortClaim{}, err
	}
	if url.PublicPort.Valid {
		return TCPPortClaim{}, ErrPublicURLMutationStale
	}
	claim, err := allocateTCPPortForURL(ctx, queries, publicURLID, url.IngressPoolID, url.CanonicalHostname, PublicURLServiceProtocol(url.ServiceProtocol), now)
	if err != nil {
		return TCPPortClaim{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return TCPPortClaim{}, err
	}
	return claim, nil
}

// allocateTCPPortForURL runs inside the caller's URL-locked transaction. a new
// URL creation also uses it, so the URL and its port become visible together.
func allocateTCPPortForURL(ctx context.Context, queries *controlstatedb.Queries, publicURLID, poolID, hostname string, protocol PublicURLServiceProtocol, now time.Time) (TCPPortClaim, error) {
	preferred := []int32{5432, 15432, 25432, 35432, 45432, 55432}
	if protocol == PublicURLServiceMySQL {
		preferred = []int32{3306, 13306, 23306, 33306, 43306, 53306, 63306}
	}
	for range 8 {
		port, err := queries.ChooseTCPPort(ctx, controlstatedb.ChooseTCPPortParams{
			IngressPoolID: poolID, CanonicalHostname: hostname,
			PreferredPorts: preferred, Seed: publicURLID,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return TCPPortClaim{}, ErrTCPPortPoolFull
		}
		if err != nil {
			return TCPPortClaim{}, fmt.Errorf("controlstate: choose TCP port: %w", err)
		}
		id, err := opaqueid.New(opaqueid.TCPPortClaimPrefix)
		if err != nil {
			return TCPPortClaim{}, err
		}
		claim, err := queries.InsertTCPPortClaim(ctx, controlstatedb.InsertTCPPortClaimParams{
			ID: id, PublicURLID: publicURLID, IngressPoolID: poolID,
			CanonicalHostname: hostname, Port: port, ClaimedAt: timestamptz(now),
		})
		if errors.Is(err, pgx.ErrNoRows) {
			// another URL claimed this port during selection; read a new snapshot.
			continue
		}
		if err != nil {
			return TCPPortClaim{}, fmt.Errorf("controlstate: reserve TCP port: %w", err)
		}
		updated, err := queries.SetPublicURLTCPPort(ctx, controlstatedb.SetPublicURLTCPPortParams{
			PublicURLID: publicURLID, Port: pgtype.Int4{Int32: port, Valid: true},
		})
		if err != nil || updated != 1 {
			return TCPPortClaim{}, ErrPublicURLMutationStale
		}
		return tcpPortClaim(claim), nil
	}
	return TCPPortClaim{}, ErrTCPPortPoolFull
}

func tcpPortClaim(row controlstatedb.ControlTcpPortClaim) TCPPortClaim {
	return TCPPortClaim{
		ID: row.ID, PublicURLID: row.PublicURLID, IngressPoolID: row.IngressPoolID,
		Hostname: row.CanonicalHostname, Port: uint16(row.Port), ClaimedAt: row.ClaimedAt.Time,
	}
}

func quarantineTCPPortClaim(ctx context.Context, queries *controlstatedb.Queries, publicURLID string, now time.Time) error {
	_, err := queries.QuarantineTCPPortClaim(ctx, controlstatedb.QuarantineTCPPortClaimParams{
		RetiredAt: timestamptz(now), ReusableAfter: timestamptz(now.Add(tcpPortQuarantine)), PublicURLID: publicURLID,
	})
	return err
}

func (d *Database) ReleaseQuarantinedTCPPortClaims(ctx context.Context, now time.Time) (int64, error) {
	if now.IsZero() {
		return 0, ErrPublicURLInvalid
	}
	if err := d.requireOpen(); err != nil {
		return 0, err
	}
	count, err := controlstatedb.New(d.pool).ReleaseQuarantinedTCPPortClaims(ctx, timestamptz(now))
	if err != nil {
		return 0, fmt.Errorf("controlstate: release quarantined TCP ports: %w", err)
	}
	return count, nil
}

func (d *Database) TCPPortPoolCapacities(ctx context.Context) ([]TCPPortPoolCapacity, error) {
	if err := d.requireOpen(); err != nil {
		return nil, err
	}
	rows, err := controlstatedb.New(d.pool).ListTCPPortPoolCapacity(ctx)
	if err != nil {
		return nil, fmt.Errorf("controlstate: read TCP port pool capacity: %w", err)
	}
	result := make([]TCPPortPoolCapacity, len(rows))
	for index, row := range rows {
		result[index] = TCPPortPoolCapacity{
			IngressPoolID: row.IngressPoolID, ConfiguredPorts: row.ConfiguredPorts,
			ClaimedPorts: row.ClaimedPorts, QuarantinedPorts: row.QuarantinedPorts,
			AvailablePorts: row.ConfiguredPorts - row.ClaimedPorts - row.QuarantinedPorts,
		}
	}
	return result, nil
}
