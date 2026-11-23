package state

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/internal/policy/ippolicy"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

var ErrServiceAuditAccess = errors.New("service audit access denied")

// SetServiceAuditActor binds database-normalized events to an authenticated
// management actor for this transaction only. never call it with client claims.
func SetServiceAuditActor(ctx context.Context, tx pgx.Tx, actor string) error {
	if !serviceaudit.ValidReference(actor) {
		return serviceaudit.ErrInvalid
	}
	_, err := tx.Exec(ctx, `SELECT set_config('tnl.audit_actor',$1,true)`, actor)
	return err
}

type ServiceAuditFilter struct {
	ServiceID string
	Service   string
	After     string
	Since     *time.Time
	Limit     int
}
type ServiceAuditPage struct {
	Events     []serviceaudit.Event `json:"events"`
	NextCursor string               `json:"next_cursor,omitempty"`
}

// RecordServiceAudit appends a safe management fact to the caller's transaction.
// requestID must identify the mutation, not contain configuration or credentials.
// callers authorize the operation before using this helper; service scope and
// actor syntax are independently checked here so a malformed scope rolls back.
func RecordServiceAudit(ctx context.Context, tx pgx.Tx, event serviceaudit.Event, requestID string) error {
	if requestID == "" || len(requestID) > 256 || event.TeamID != "" && !serviceaudit.ValidReference(event.TeamID) ||
		!serviceaudit.ValidReference(event.ServiceID) || event.ServiceKind != "service" || event.OccurredAt.IsZero() ||
		event.ActorIdentityID != "" && !serviceaudit.ValidReference(event.ActorIdentityID) ||
		event.DeviceID != "" && !opaqueid.Valid(event.DeviceID, "vdev_") ||
		event.PublisherIdentityID != "" && !opaqueid.Valid(event.PublisherIdentityID, opaqueid.PublisherIdentityPrefix) ||
		event.RunID != "" && !serviceaudit.ValidReference(event.RunID) ||
		event.ConfigurationRevision < 0 || event.SourceIP != "" || event.SourceDigest != "" || event.VisitorConnectionID != "" || event.Outcome != "" || event.Reason != "" {
		return serviceaudit.ErrInvalid
	}
	switch event.EventType {
	case "service.create", "service.update", "service.delete", "grant.create", "grant.revoke", "invitation.create", "invitation.accept", "invitation.revoke", "trust.update", "device.enroll", "device.revoke", "publisher.join", "publisher.revoke", "run.prepare", "run.start", "run.close", "apply", "deployment.update", "certificate.issue", "certificate.install", "certificate.client.issue":
	default:
		return serviceaudit.ErrInvalid
	}
	var team, guest pgtype.Text
	err := tx.QueryRow(ctx, `SELECT team_id,guest_id FROM control.services WHERE id=$1`, event.ServiceID).Scan(&team, &guest)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (team.String != event.TeamID || team.Valid == guest.Valid) {
		return ErrServiceAuditAccess
	}
	if err != nil {
		return err
	}
	if event.ActorIdentityID != "" {
		var exists bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.identities person WHERE person.id=$1 AND (
			EXISTS(SELECT 1 FROM control.team_memberships member WHERE member.identity_id=person.id AND member.team_id=$2 AND member.removed_at IS NULL)
			OR $4::text IN ('invitation.accept','grant.create','device.enroll','device.revoke','certificate.client.issue') AND (
			    EXISTS(SELECT 1 FROM control.visitor_grants g WHERE g.service_id=$3 AND g.identity_id=person.id)
			    OR EXISTS(SELECT 1 FROM control.public_service_visitors v WHERE v.service_id=$3 AND v.identity_id=person.id)
			    OR EXISTS(SELECT 1 FROM control.connector_peer_audit_bindings b WHERE b.service_id=$3 AND b.identity_id=person.id)
			)))`, event.ActorIdentityID, event.TeamID, event.ServiceID, event.EventType).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return ErrServiceAuditAccess
		}
	}
	if event.RunID != "" {
		var matches bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.service_runs WHERE id=$1 AND service_id=$2
			AND team_id IS NOT DISTINCT FROM $3::text AND guest_id IS NOT DISTINCT FROM $4::text)`, event.RunID, event.ServiceID, team, guest).Scan(&matches); err != nil {
			return err
		}
		if !matches {
			return ErrServiceAuditAccess
		}
	}
	if event.PublisherIdentityID != "" {
		var matches bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.publisher_identities WHERE id=$1
			AND team_id IS NOT DISTINCT FROM $2::text AND guest_id IS NOT DISTINCT FROM $3::text)`, event.PublisherIdentityID, team, guest).Scan(&matches); err != nil {
			return err
		}
		if !matches {
			return ErrServiceAuditAccess
		}
	}
	if event.DeviceID != "" {
		var matches bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.visitor_devices WHERE id=$1 AND identity_id=$2)`, event.DeviceID, event.ActorIdentityID).Scan(&matches); err != nil {
			return err
		}
		if !matches {
			return ErrServiceAuditAccess
		}
	}
	event.ID = serviceaudit.StableID(event.ServiceID, event.EventType, requestID)
	return insertServiceAudit(ctx, tx, event, time.Now().UTC())
}

func insertServiceAudit(ctx context.Context, tx pgx.Tx, e serviceaudit.Event, now time.Time) error {
	_, err := insertServiceAuditBatch(ctx, tx, []serviceaudit.Event{e}, now)
	return err
}

func insertServiceAuditBatch(ctx context.Context, tx pgx.Tx, events []serviceaudit.Event, now time.Time) (ServiceObservationResult, error) {
	if len(events) == 0 || len(events) > serviceaudit.MaxBatch {
		return ServiceObservationResult{}, serviceaudit.ErrInvalid
	}
	// validation and duplicate comparisons use PostgreSQL's timestamp precision,
	// just as single-event pgx parameters do. never change the caller's slice.
	unique := make([]serviceaudit.Event, 0, len(events))
	byID := make(map[string]serviceaudit.Event, len(events))
	services := make(map[string]struct{})
	var serviceIDs []string
	for _, event := range events {
		if event.SourceIP != "" {
			return ServiceObservationResult{}, serviceaudit.ErrInvalid
		}
		traffic := event.EventType == "connection.open" || event.EventType == "connection.close" || event.EventType == "http.decision"
		if traffic != (event.SourceDigest != "") {
			return ServiceObservationResult{}, serviceaudit.ErrInvalid
		}
		if event.SourceDigest != "" {
			if _, err := ippolicy.ParseDigest(event.SourceDigest); err != nil {
				return ServiceObservationResult{}, err
			}
		}
		event.OccurredAt = event.OccurredAt.Truncate(time.Microsecond)
		if previous, found := byID[event.ID]; found {
			if !sameServiceAuditEvent(previous, event) {
				return ServiceObservationResult{}, ErrServiceAuditAccess
			}
			continue
		}
		unique = append(unique, event)
		byID[event.ID] = event
		if _, found := services[event.ServiceID]; !found {
			services[event.ServiceID] = struct{}{}
			serviceIDs = append(serviceIDs, event.ServiceID)
		}
	}
	q := controlstatedb.New(tx)
	owners, err := q.ListServiceAuditOwners(ctx, serviceIDs)
	if err != nil {
		return ServiceObservationResult{}, err
	}
	if len(owners) != len(serviceIDs) {
		return ServiceObservationResult{}, ErrServiceAuditAccess
	}
	guests := make(map[string]pgtype.Text, len(owners))
	teams := make(map[string]pgtype.Text, len(owners))
	// serialize cursor allocation with commits once per owner, in the same
	// owner order as parent locking. sequence order alone can skip a slow commit.
	var locked controlstatedb.LockServiceAuditClockParams
	for _, owner := range owners {
		scope := controlstatedb.LockServiceAuditClockParams{TeamID: owner.TeamID, GuestID: owner.GuestID}
		if scope != locked {
			if err := q.LockServiceAuditClock(ctx, scope); err != nil {
				return ServiceObservationResult{}, err
			}
			locked = scope
		}
		guests[owner.ID], teams[owner.ID] = owner.GuestID, owner.TeamID
	}
	for _, event := range unique {
		if teams[event.ServiceID].String != event.TeamID {
			return ServiceObservationResult{}, ErrServiceAuditAccess
		}
	}
	payload, err := json.Marshal(unique)
	if err != nil {
		return ServiceObservationResult{}, err
	}
	inserted, err := q.InsertServiceAuditEvents(ctx, controlstatedb.InsertServiceAuditEventsParams{Events: payload, ReceivedAt: timestamptz(now)})
	if err != nil {
		return ServiceObservationResult{}, err
	}
	for _, id := range inserted {
		delete(byID, id)
	}
	if len(byID) != 0 {
		ids := make([]string, 0, len(byID))
		for id := range byID {
			ids = append(ids, id)
		}
		// use a new statement snapshot after ON CONFLICT has joined any
		// concurrent insertion, including a conflicting ID from another owner.
		saved, err := q.ListServiceAuditEventsByID(ctx, ids)
		if err != nil {
			return ServiceObservationResult{}, err
		}
		if len(saved) != len(ids) {
			return ServiceObservationResult{}, ErrServiceAuditAccess
		}
		for _, row := range saved {
			event := serviceaudit.Event{TeamID: row.TeamID.String, ServiceID: row.ServiceID, EventType: row.EventType,
				RunID: row.RunID.String, VisitorConnectionID: row.VisitorConnectionID.String,
				Outcome: row.Outcome.String, Reason: row.Reason.String, OccurredAt: row.OccurredAt.Time}
			event.SourceDigest = row.SourceDigest.String
			if row.GuestID != guests[row.ServiceID] || !sameServiceAuditEvent(byID[row.ID], event) {
				return ServiceObservationResult{}, ErrServiceAuditAccess
			}
		}
	}
	return ServiceObservationResult{Accepted: len(inserted), Duplicates: len(events) - len(inserted)}, nil
}

func sameServiceAuditEvent(a, b serviceaudit.Event) bool {
	if a.TeamID != b.TeamID || a.ServiceID != b.ServiceID || a.EventType != b.EventType ||
		a.RunID != b.RunID || a.VisitorConnectionID != b.VisitorConnectionID {
		return false
	}
	switch a.EventType {
	case "connection.open", "connection.close", "http.decision":
		return a.SourceDigest == b.SourceDigest && a.Outcome == b.Outcome && a.Reason == b.Reason && a.OccurredAt.Equal(b.OccurredAt)
	default:
		return true
	}
}

func auditPrivateMutation(ctx context.Context, tx pgx.Tx, service, actor, operation, request string, now time.Time) error {
	var team pgtype.Text
	var revision int64
	if err := tx.QueryRow(ctx, `SELECT team_id,trust_revision FROM control.services WHERE id=$1`, service).Scan(&team, &revision); err != nil {
		return err
	}
	return RecordServiceAudit(ctx, tx, serviceaudit.Event{TeamID: team.String, ServiceID: service, ServiceKind: "service", EventType: operation, OccurredAt: now, ActorIdentityID: actor, ConfigurationRevision: revision}, request)
}

func (d *Database) ListServiceAudit(ctx context.Context, team, actor string, f ServiceAuditFilter, now time.Time) (page ServiceAuditPage, retErr error) {
	if !serviceaudit.ValidReference(team) || !serviceaudit.ValidReference(actor) || f.Limit < 0 || f.Limit > 256 || len(f.Service) > 253 {
		return page, serviceaudit.ErrInvalid
	}
	after := int64(0)
	var err error
	if f.After != "" {
		after, err = strconv.ParseInt(f.After, 10, 64)
		if err != nil || after < 0 || strconv.FormatInt(after, 10) != f.After {
			return page, serviceaudit.ErrInvalid
		}
	}
	if f.ServiceID != "" && !serviceaudit.ValidReference(f.ServiceID) {
		return page, serviceaudit.ErrInvalid
	}
	if f.Limit == 0 {
		f.Limit = 100
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return page, err
	}
	defer rollback(ctx, tx, "list service audit", &retErr)()
	if err = serviceManager(ctx, tx, team, actor); err != nil {
		if errors.Is(err, ErrServiceAccess) {
			return page, ErrServiceAuditAccess
		}
		return page, err
	}
	if f.Service != "" {
		var ids []string
		err = tx.QueryRow(ctx, `SELECT ARRAY(SELECT id FROM control.services WHERE team_id=$1 AND (name=$2 OR certificate_hostname=$2) AND deleted_at IS NULL LIMIT 2)`, team, f.Service).Scan(&ids)
		if err != nil {
			return page, err
		}
		if len(ids) == 0 {
			return ServiceAuditPage{Events: []serviceaudit.Event{}}, nil
		}
		if len(ids) != 1 {
			return page, serviceaudit.ErrInvalid
		}
		id := ids[0]
		if f.ServiceID != "" && f.ServiceID != id {
			return page, serviceaudit.ErrInvalid
		}
		f.ServiceID = id
	}
	rows, err := controlstatedb.New(tx).ListServiceAuditEvents(ctx, controlstatedb.ListServiceAuditEventsParams{TeamID: text(team), AfterCursor: after, RetainedAfter: timestamptz(now.Add(-serviceaudit.Retention)), Since: nullableTime(f.Since), ServiceID: nullableText(f.ServiceID), PageLimit: int32(f.Limit + 1)})
	if err != nil {
		return page, err
	}
	page.Events = make([]serviceaudit.Event, 0, min(len(rows), f.Limit))
	for i, row := range rows {
		if i == f.Limit {
			page.NextCursor = page.Events[i-1].Cursor
			break
		}
		e := serviceaudit.Event{ID: row.ID, Cursor: strconv.FormatInt(row.Cursor, 10), TeamID: row.TeamID.String, ServiceID: row.ServiceID, ServiceKind: "service", EventType: row.EventType, OccurredAt: row.OccurredAt.Time, ActorIdentityID: row.ActorIdentityID.String, DeviceID: row.DeviceID.String, PublisherIdentityID: row.PublisherIdentityID.String, RunID: row.RunID.String, VisitorConnectionID: row.VisitorConnectionID.String, Outcome: row.Outcome.String, Reason: row.Reason.String, ConfigurationRevision: row.ConfigurationRevision.Int64}
		e.SourceDigest = row.SourceDigest.String
		page.Events = append(page.Events, e)
	}
	return page, tx.Commit(ctx)
}

// CleanupServiceAudit removes at most limit expired rows per worker call.
func (d *Database) CleanupServiceAudit(ctx context.Context, now time.Time, limit int) (removed int64, retErr error) {
	if limit < 1 || limit > 10000 {
		return 0, serviceaudit.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	q := controlstatedb.New(d.pool)
	removed, retErr = q.CleanupServiceAuditEvents(ctx, controlstatedb.CleanupServiceAuditEventsParams{BeforeTime: timestamptz(now.Add(-serviceaudit.Retention)), BatchSize: int32(limit)})
	if retErr != nil || removed == int64(limit) {
		return removed, retErr
	}
	return removed, nil
}

func validateObservationBatch(batch serviceaudit.Batch, now time.Time) error {
	if len(batch.Events) < 1 || len(batch.Events) > serviceaudit.MaxBatch {
		return serviceaudit.ErrInvalid
	}
	for _, e := range batch.Events {
		if e.Validate() != nil || e.OccurredAt.Before(now.Add(-24*time.Hour)) || e.OccurredAt.After(now.Add(time.Minute)) {
			return serviceaudit.ErrInvalid
		}
	}
	return nil
}

type ServiceObservationResult struct {
	Accepted   int `json:"accepted"`
	Duplicates int `json:"duplicates"`
}

const serviceObservationDeliveryGrace = 2 * time.Minute

func observationEvent(o serviceaudit.Observation) serviceaudit.Event {
	return serviceaudit.Event{ID: o.EventID, ServiceID: o.ServiceID, ServiceKind: o.ServiceKind, EventType: o.EventType, OccurredAt: o.OccurredAt, RunID: o.RunID, VisitorConnectionID: o.VisitorConnectionID, SourceIP: o.SourceIP, Outcome: o.Outcome, Reason: o.Reason}
}

func (d *Database) IngestIngressServiceObservations(ctx context.Context, lease IngressLeaseIdentity, batch serviceaudit.Batch, now time.Time) (result ServiceObservationResult, retErr error) {
	clock := newAuthorizationClock(now)
	if err := validateIngressLeaseIdentity(lease); err != nil {
		return result, err
	}
	if err := validateObservationBatch(batch, now); err != nil {
		return result, err
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "ingest ingress service audit", &retErr)()
	q := controlstatedb.New(tx)
	// reject a stale sender before reading its receipts, without holding the
	// ingress row ahead of service parents. repeat under lock before commit.
	if err := requireCurrentIngressLease(ctx, q, lease, clock.current()); err != nil {
		return result, err
	}
	ids := make(map[string]struct{})
	for _, o := range batch.Events {
		if o.ServiceKind != "service" || o.PairID != "" || o.EventType != "connection.open" && o.EventType != "connection.close" {
			return ServiceObservationResult{}, ErrServiceAuditAccess
		}
		ids[o.ServiceID] = struct{}{}
	}
	parents, err := q.ListServiceAuditOwners(ctx, slices.Collect(maps.Keys(ids)))
	if err != nil {
		return result, err
	}
	if len(parents) != len(ids) {
		return result, ErrServiceAuditAccess
	}
	// the query orders owners, then services. keep that order for parent locks,
	// first-use privacy keys, and cursor allocation, even across reversed batches.
	order := make(map[string]int, len(parents))
	for i, parent := range parents {
		if i == 0 || parents[i-1].TeamID != parent.TeamID || parents[i-1].GuestID != parent.GuestID {
			if err := lockServiceOwner(ctx, tx, parent.ID); err != nil {
				return result, err
			}
		}
		order[parent.ID] = i
	}
	for _, parent := range parents {
		// delayed evidence can belong to a disabled or closed service. wait for
		// its writer, then verify the receipt, without requiring it to serve now.
		if err := queueRunReader(ctx, tx, parent.ID); err != nil {
			return result, err
		}
		if _, err := q.ObservePublisherEnrollmentService(ctx, parent.ID); err != nil {
			return result, publisherLookupError(err, ErrServiceAuditAccess)
		}
	}
	events := make([]serviceaudit.Event, 0, len(batch.Events))
	for _, o := range batch.Events {
		e := observationEvent(o)
		sourceDigest := ""
		if len(o.RoutingAuthority) == 0 {
			source, sourceErr := netip.ParseAddr(o.SourceIP)
			if sourceErr != nil {
				return ServiceObservationResult{}, ErrServiceAuditAccess
			}
			sourceDigest, err = d.readServiceIPDigest(ctx, q, o.ServiceID, publicVisitorIPKeyPurpose, source)
			if err != nil {
				return ServiceObservationResult{}, errors.Join(ErrServiceAuditAccess, err)
			}
		}
		if o.RunID == "" {
			if o.RunNumber != 0 || o.EventType != "connection.open" || o.Outcome != "denied" ||
				o.Reason != "capacity" && o.Reason != "unavailable" && o.Reason != "invalid_request" && o.Reason != "ip_policy" {
				return ServiceObservationResult{}, ErrServiceAuditAccess
			}
			if len(o.RoutingAuthority) != 0 {
				e.TeamID, err = d.ingressSelectionDenialOwner(ctx, tx, lease, o, clock.current())
			} else {
				// native selection still has a control admission receipt. recover
				// only its owner; it selected no serving run or visitor identity.
				err = tx.QueryRow(ctx, `SELECT service.team_id
				FROM control.public_service_visitors visitor JOIN control.services service ON service.id=visitor.service_id
				WHERE visitor.visitor_connection_id=$1 AND visitor.service_id=$2
				AND visitor.ingress_id=$3 AND visitor.ingress_run_id=$4 AND visitor.ingress_lease_revision=$5
				AND visitor.source_digest=$6 AND visitor.identity_id IS NULL AND visitor.device_id IS NULL
				AND visitor.workload_session_id IS NULL AND visitor.promoted_at IS NULL
				AND visitor.created_at<=$7 AND visitor.valid_until>=$8`,
					o.VisitorConnectionID, o.ServiceID, lease.IngressID, lease.IngressRunID, int64(lease.IngressLeaseRevision),
					sourceDigest, o.OccurredAt.Add(time.Second), o.OccurredAt.Add(-serviceObservationDeliveryGrace)).Scan((*nullableAuditString)(&e.TeamID))
			}
		} else {
			// direct admission identity is recovered
			// only from the publisher-authenticated record, never the report.
			err = tx.QueryRow(ctx, `SELECT s.team_id,v.identity_id,v.device_id,r.publisher_identity_id FROM control.public_service_visitors v
				JOIN control.services s ON s.id=v.service_id JOIN control.service_runs r ON r.id=v.service_run_id
				WHERE v.visitor_connection_id=$1 AND v.service_id=$2 AND v.service_run_id=$3 AND v.run_number=$4
				AND v.ingress_id=$5 AND v.ingress_run_id=$6 AND v.ingress_lease_revision=$7 AND v.source_digest=$8
				AND($9<>'allowed' OR v.identity_id IS NOT NULL OR v.workload_session_id IS NOT NULL)`, o.VisitorConnectionID, o.ServiceID, o.RunID, o.RunNumber, lease.IngressID, lease.IngressRunID, int64(lease.IngressLeaseRevision), sourceDigest, o.Outcome).Scan((*nullableAuditString)(&e.TeamID), (*nullableAuditString)(&e.ActorIdentityID), (*nullableAuditString)(&e.DeviceID), &e.PublisherIdentityID)
		}
		if errors.Is(err, pgx.ErrNoRows) {
			return ServiceObservationResult{}, ErrServiceAuditAccess
		}
		if err != nil {
			return ServiceObservationResult{}, err
		}
		events = append(events, e)
	}
	sort.SliceStable(events, func(i, j int) bool {
		return order[events[i].ServiceID] < order[events[j].ServiceID]
	})
	current, err := lockCurrentIngressLease(ctx, q, lease, clock.current())
	if err != nil {
		return result, err
	}
	result, err = d.insertServiceObservationBatch(ctx, tx, events, now)
	if err != nil {
		return ServiceObservationResult{}, err
	}
	if !current.LeaseExpiresAt.Time.After(clock.current()) {
		return ServiceObservationResult{}, ErrIngressLeaseStale
	}
	if err = tx.Commit(ctx); err != nil {
		return ServiceObservationResult{}, err
	}
	d.activity.metrics.Load().ServiceAuditCount("accepted", uint64(result.Accepted))
	d.activity.metrics.Load().ServiceAuditCount("duplicate", uint64(result.Duplicates))
	return result, nil
}

func (d *Database) ingressSelectionDenialOwner(ctx context.Context, tx pgx.Tx, lease IngressLeaseIdentity, o serviceaudit.Observation, now time.Time) (string, error) {
	authority, err := tunnelv1.ReadVisitorSourceAuthority(o.RoutingAuthority)
	if err != nil || authority.ServiceID != o.ServiceID || authority.IngressID != lease.IngressID ||
		authority.IngressRunID != lease.IngressRunID || authority.IngressLeaseRevision != lease.IngressLeaseRevision ||
		now.After(time.Unix(authority.ValidUntil, 0).Add(serviceObservationDeliveryGrace)) {
		return "", ErrServiceAuditAccess
	}
	var team nullableAuditString
	var secretDigest []byte
	var ready time.Time
	err = tx.QueryRow(ctx, `SELECT service.team_id,run.run_token_digest,run.ready_at
		FROM control.services service JOIN control.service_runs run ON run.service_id=service.id
		WHERE service.id=$1 AND service.protocol='http' AND run.id=$2 AND run.run_number=$3 AND run.ready_at IS NOT NULL`,
		o.ServiceID, authority.ServiceRunID, authority.RunNumber).Scan(&team, &secretDigest, &ready)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrServiceAuditAccess
	}
	if err != nil {
		return "", err
	}
	master, err := visitortoken.ServiceVisitorSourceKey(secretDigest, authority.ServiceRunID, authority.RunNumber)
	if err != nil || o.OccurredAt.Before(ready.Add(-time.Second)) ||
		visitortoken.VerifyVisitorSourceAuthority(master, authority, o.OccurredAt) != nil {
		return "", ErrServiceAuditAccess
	}
	// ingress reports its observed socket source under this exact delegation.
	// persist only the denial, source and owner, not the routing evidence, candidate
	// run, publisher or a visitor identity. reporting cannot authorize traffic.
	return string(team), nil
}

type nullableAuditString string

func (s *nullableAuditString) ScanText(v pgtype.Text) error {
	*s = nullableAuditString(v.String)
	return nil
}

type deviceAuditService struct{ team, id string }

// device writes acquire identity/device foreign-key locks. collect and lock
// their audit parents first, in the same owner -> service order as admission.
func lockDeviceAuditServices(ctx context.Context, tx pgx.Tx, identity, device string) ([]deviceAuditService, error) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT s.team_id,s.id FROM control.services s WHERE
		EXISTS(SELECT 1 FROM control.team_memberships m WHERE m.team_id=s.team_id AND m.identity_id=$1 AND m.removed_at IS NULL)
		OR EXISTS(SELECT 1 FROM control.visitor_grants g WHERE g.service_id=s.id AND g.identity_id=$1)
		OR EXISTS(SELECT 1 FROM control.public_service_visitors v WHERE v.service_id=s.id AND v.device_id=$2)
		OR EXISTS(SELECT 1 FROM control.connector_peer_audit_bindings b WHERE b.service_id=s.id AND b.device_id=$2)
		ORDER BY s.team_id,s.id`, identity, device)
	if err != nil {
		return nil, err
	}
	var scopes []deviceAuditService
	for rows.Next() {
		var s deviceAuditService
		if err = rows.Scan(&s.team, &s.id); err != nil {
			rows.Close()
			return nil, err
		}
		scopes = append(scopes, s)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	q := controlstatedb.New(tx)
	var owner string
	for _, s := range scopes {
		if owner != s.team {
			// retained device history may still name a deleted team. this
			// lock orders audit writes; it grants no service permission.
			var locked string
			if err := tx.QueryRow(ctx, `SELECT id FROM control.teams WHERE id=$1 FOR SHARE`, s.team).Scan(&locked); err != nil {
				return nil, err
			}
			owner = s.team
		}
		if _, err := q.LockService(ctx, s.id); err != nil {
			return nil, err
		}
	}
	return scopes, nil
}

func auditDeviceMutation(ctx context.Context, tx pgx.Tx, scopes []deviceAuditService, identity, device, operation string, now time.Time) error {
	for _, s := range scopes {
		if err := RecordServiceAudit(ctx, tx, serviceaudit.Event{TeamID: s.team, ServiceID: s.id, ServiceKind: "service", EventType: operation, OccurredAt: now, ActorIdentityID: identity, DeviceID: device}, device); err != nil {
			return err
		}
	}
	return nil
}
