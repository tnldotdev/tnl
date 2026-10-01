package controlstate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
)

const MaximumIngressRoutingTablePageSize = 1000

// IngressRoutingTableEvent is one stored, ordered projection update.
type IngressRoutingTableEvent struct {
	RoutingTableRevision uint64
	Kind                 IngressRoutingTableEventKind
	PublicURLID          string
	PublishRunNumber     uint64
	CanonicalHostname    string
	EntryRevision        uint64
	Projection           IngressRoutingTableProjection
	PublicUrlExpiresAt   *time.Time
	CreatedAt            time.Time
}

// IngressRoutingTableSnapshot is a repeatable-read view through one revision.
type IngressRoutingTableSnapshot struct {
	RoutingTableRevision  uint64
	RetainedAfterRevision uint64
	Entries               []IngressRoutingTableEvent
}

// IngressRoutingTablePage is an ordered revision response.
type IngressRoutingTablePage struct {
	ThroughRevision       uint64
	RetainedAfterRevision uint64
	NextRevision          uint64
	More                  bool
	ResnapshotRequired    bool
	Events                []IngressRoutingTableEvent
}

// ReadIngressRoutingTableSnapshot returns the latest unexpired projection for
// each public URL or challenge as of one repeatable-read high-water revision.
func (d *Database) ReadIngressRoutingTableSnapshot(
	ctx context.Context,
	identity IngressLeaseIdentity,
	now time.Time,
) (result IngressRoutingTableSnapshot, retErr error) {
	defer d.observeOperation("ReadIngressRoutingTableSnapshot", &retErr)()
	if err := validateIngressLeaseIdentity(identity); err != nil {
		return IngressRoutingTableSnapshot{}, err
	}
	if err := d.requireOpen(); err != nil {
		return IngressRoutingTableSnapshot{}, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return IngressRoutingTableSnapshot{}, fmt.Errorf("controlstate: read ingress routing-table snapshot: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "read ingress routing-table snapshot", &retErr)()
	queries := controlstatedb.New(tx)
	if err := requireCurrentIngressLease(ctx, queries, identity, now); err != nil {
		return IngressRoutingTableSnapshot{}, err
	}
	clock, err := queries.ReadIngressRoutingTableClock(ctx)
	if err != nil {
		return IngressRoutingTableSnapshot{}, fmt.Errorf("controlstate: read ingress routing-table snapshot: read clock: %w", err)
	}
	if err := validateIngressRoutingTableClock(clock); err != nil {
		return IngressRoutingTableSnapshot{}, err
	}
	rows, err := queries.ListIngressRoutingTableSnapshot(ctx, controlstatedb.ListIngressRoutingTableSnapshotParams{
		Now: timestamptz(now), ThroughRevision: clock.CurrentRevision,
	})
	if err != nil {
		return IngressRoutingTableSnapshot{}, fmt.Errorf("controlstate: read ingress routing-table snapshot: list public_urls: %w", err)
	}
	snapshot := IngressRoutingTableSnapshot{
		RoutingTableRevision:  uint64(clock.CurrentRevision),
		RetainedAfterRevision: uint64(clock.RetainedAfterRevision),
		Entries:               make([]IngressRoutingTableEvent, 0, len(rows)),
	}
	for _, row := range rows {
		event, err := ingressRoutingTableEvent(
			row.ID, row.EventKind, row.PublicURLID, row.PublishRunNumber,
			row.CanonicalHostname, row.EntryRevision, row.Projection, row.PublicUrlExpiresAt, row.CreatedAt,
		)
		if err != nil {
			return IngressRoutingTableSnapshot{}, err
		}
		snapshot.Entries = append(snapshot.Entries, event)
	}
	if err := tx.Commit(ctx); err != nil {
		return IngressRoutingTableSnapshot{}, fmt.Errorf("controlstate: read ingress routing-table snapshot: commit: %w", err)
	}
	return snapshot, nil
}

// ReadIngressRoutingTableEvents returns a size-limited page after one revision.
func (d *Database) ReadIngressRoutingTableEvents(
	ctx context.Context,
	identity IngressLeaseIdentity,
	afterRevision uint64,
	pageSize int,
	now time.Time,
) (result IngressRoutingTablePage, retErr error) {
	defer d.observeOperation("ReadIngressRoutingTableEvents", &retErr)()
	if err := validateIngressLeaseIdentity(identity); err != nil {
		return IngressRoutingTablePage{}, err
	}
	if pageSize <= 0 || pageSize > MaximumIngressRoutingTablePageSize {
		return IngressRoutingTablePage{}, fmt.Errorf(
			"controlstate: ingress routing-table page size must be between 1 and %d",
			MaximumIngressRoutingTablePageSize,
		)
	}
	after, ok := nonnegativeInt64(afterRevision)
	if !ok {
		return IngressRoutingTablePage{}, errors.New("controlstate: ingress routing-table revision is too large")
	}
	if err := d.requireOpen(); err != nil {
		return IngressRoutingTablePage{}, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return IngressRoutingTablePage{}, fmt.Errorf("controlstate: read ingress routing-table events: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "read ingress routing-table events", &retErr)()
	queries := controlstatedb.New(tx)
	if err := requireCurrentIngressLease(ctx, queries, identity, now); err != nil {
		return IngressRoutingTablePage{}, err
	}
	clock, err := queries.ReadIngressRoutingTableClock(ctx)
	if err != nil {
		return IngressRoutingTablePage{}, fmt.Errorf("controlstate: read ingress routing-table events: read clock: %w", err)
	}
	if err := validateIngressRoutingTableClock(clock); err != nil {
		return IngressRoutingTablePage{}, err
	}
	page := IngressRoutingTablePage{
		ThroughRevision:       uint64(clock.CurrentRevision),
		RetainedAfterRevision: uint64(clock.RetainedAfterRevision),
		NextRevision:          afterRevision,
	}
	if after < clock.RetainedAfterRevision {
		page.ResnapshotRequired = true
		if err := tx.Commit(ctx); err != nil {
			return IngressRoutingTablePage{}, fmt.Errorf("controlstate: read ingress routing-table events: commit resnapshot: %w", err)
		}
		return page, nil
	}
	if after > clock.CurrentRevision {
		return IngressRoutingTablePage{}, errors.New("controlstate: ingress routing-table revision is ahead of the current revision")
	}
	rows, err := queries.ListIngressRoutingTableEvents(ctx, controlstatedb.ListIngressRoutingTableEventsParams{
		AfterRevision: after, ThroughRevision: clock.CurrentRevision, PageLimit: int32(pageSize),
	})
	if err != nil {
		return IngressRoutingTablePage{}, fmt.Errorf("controlstate: read ingress routing-table events: list events: %w", err)
	}
	page.Events = make([]IngressRoutingTableEvent, 0, len(rows))
	for _, row := range rows {
		event, err := ingressRoutingTableEvent(
			row.ID, row.EventKind, row.PublicURLID, row.PublishRunNumber,
			row.CanonicalHostname, row.EntryRevision, row.Projection, row.PublicUrlExpiresAt, row.CreatedAt,
		)
		if err != nil {
			return IngressRoutingTablePage{}, err
		}
		page.Events = append(page.Events, event)
		page.NextRevision = event.RoutingTableRevision
	}
	page.More = page.NextRevision < page.ThroughRevision
	if err := tx.Commit(ctx); err != nil {
		return IngressRoutingTablePage{}, fmt.Errorf("controlstate: read ingress routing-table events: commit: %w", err)
	}
	return page, nil
}

func validateIngressRoutingTableClock(clock controlstatedb.ControlIngressRoutingTableClock) error {
	if clock.CurrentRevision < 0 || clock.RetainedAfterRevision < 0 ||
		clock.RetainedAfterRevision > clock.CurrentRevision {
		return errors.New("controlstate: invalid ingress routing-table clock")
	}
	return nil
}

func ingressRoutingTableEvent(
	routingTableRevision int64,
	eventKind string,
	publicURLID string,
	publishRunNumber int64,
	canonicalHostname string,
	entryRevision int64,
	payload []byte,
	publicURLExpiresAt pgtype.Timestamptz,
	createdAt pgtype.Timestamptz,
) (IngressRoutingTableEvent, error) {
	if routingTableRevision <= 0 || publishRunNumber <= 0 || entryRevision <= 0 || !createdAt.Valid ||
		(eventKind != "public_url_upsert" && eventKind != "public_url_tombstone" &&
			eventKind != "challenge_upsert" && eventKind != "challenge_tombstone") {
		return IngressRoutingTableEvent{}, errors.New("controlstate: invalid ingress routing-table event row")
	}
	var projection IngressRoutingTableProjection
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&projection); err != nil {
		return IngressRoutingTableEvent{}, fmt.Errorf("controlstate: decode ingress routing-table projection: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return IngressRoutingTableEvent{}, errors.New("controlstate: ingress routing-table projection has trailing data")
	}
	if projection.PublicURLID != publicURLID || projection.PublishRunNumber != uint64(publishRunNumber) ||
		projection.CanonicalHostname != canonicalHostname {
		return IngressRoutingTableEvent{}, errors.New("controlstate: ingress routing-table projection identity mismatch")
	}
	var expiration *time.Time
	if publicURLExpiresAt.Valid {
		value := publicURLExpiresAt.Time
		expiration = &value
	}
	return IngressRoutingTableEvent{
		RoutingTableRevision: uint64(routingTableRevision), Kind: IngressRoutingTableEventKind(eventKind),
		PublicURLID: publicURLID, PublishRunNumber: uint64(publishRunNumber), CanonicalHostname: canonicalHostname,
		EntryRevision: uint64(entryRevision), Projection: projection,
		PublicUrlExpiresAt: expiration, CreatedAt: createdAt.Time,
	}, nil
}
