package state

import (
	"context"
	"encoding/hex"
	"errors"
	"net/netip"
	"sort"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/internal/security/credentials"
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
	if requestID == "" || len(requestID) > 256 || !serviceaudit.ValidReference(event.TeamID) ||
		!serviceaudit.ValidReference(event.ServiceID) || event.ServiceKind != "public_url" && event.ServiceKind != "service" || event.OccurredAt.IsZero() ||
		event.ActorIdentityID != "" && !serviceaudit.ValidReference(event.ActorIdentityID) ||
		event.DeviceID != "" && !opaqueid.Valid(event.DeviceID, "vdev_") ||
		event.PublisherIdentityID != "" && !opaqueid.Valid(event.PublisherIdentityID, opaqueid.PublisherIdentityPrefix) ||
		event.RunID != "" && !serviceaudit.ValidReference(event.RunID) ||
		event.ConfigurationRevision < 0 || event.SourceIP != "" || event.VisitorConnectionID != "" || event.Outcome != "" || event.Reason != "" {
		return serviceaudit.ErrInvalid
	}
	switch event.EventType {
	case "service.create", "service.update", "service.delete", "grant.create", "grant.revoke", "invitation.create", "invitation.accept", "invitation.revoke", "trust.update", "device.enroll", "device.revoke", "publisher.join", "publisher.revoke", "run.prepare", "run.start", "run.close", "apply", "group.update", "certificate.issue", "certificate.install", "certificate.client.issue":
	default:
		return serviceaudit.ErrInvalid
	}
	var team string
	err := tx.QueryRow(ctx, `SELECT team_id FROM control.public_urls WHERE id=$1 AND $2='public_url' UNION ALL SELECT team_id FROM control.services WHERE id=$1 AND $2='service'`, event.ServiceID, event.ServiceKind).Scan(&team)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && team != event.TeamID {
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
			    OR EXISTS(SELECT 1 FROM control.visitor_grants g WHERE g.public_url_id=$3 AND g.identity_id=person.id)
			    OR EXISTS(SELECT 1 FROM control.connector_sessions c WHERE c.service_id=$3 AND c.identity_id=person.id)
			)))`, event.ActorIdentityID, event.TeamID, event.ServiceID, event.EventType).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return ErrServiceAuditAccess
		}
	}
	if event.RunID != "" {
		var matches bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.publish_runs WHERE id=$1 AND public_url_id=$2 AND team_id=$3 UNION ALL SELECT 1 FROM control.service_runs WHERE id=$1 AND service_id=$2 AND team_id=$3)`, event.RunID, event.ServiceID, event.TeamID).Scan(&matches); err != nil {
			return err
		}
		if !matches {
			return ErrServiceAuditAccess
		}
	}
	if event.PublisherIdentityID != "" {
		var matches bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.publisher_identities WHERE id=$1 AND team_id=$2)`, event.PublisherIdentityID, event.TeamID).Scan(&matches); err != nil {
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
	_, err := insertServiceAuditCount(ctx, tx, e, now)
	return err
}

func insertServiceAuditCount(ctx context.Context, tx pgx.Tx, e serviceaudit.Event, now time.Time) (int64, error) {
	// serialize cursor allocation with commits for this team. sequence order
	// alone would lose a slow transaction behind a pagination cursor.
	q := controlstatedb.New(tx)
	if err := q.LockServiceAuditClock(ctx, e.TeamID); err != nil {
		return 0, err
	}
	var ip *netip.Addr
	if e.SourceIP != "" {
		addr, err := netip.ParseAddr(e.SourceIP)
		if err != nil {
			return 0, serviceaudit.ErrInvalid
		}
		ip = &addr
	}
	n, err := q.InsertServiceAuditEvent(ctx, controlstatedb.InsertServiceAuditEventParams{ID: e.ID, TeamID: e.TeamID, ServiceID: e.ServiceID, ServiceKind: e.ServiceKind, EventType: e.EventType, OccurredAt: timestamptz(e.OccurredAt), ReceivedAt: timestamptz(now), ActorIdentityID: nullableText(e.ActorIdentityID), DeviceID: nullableText(e.DeviceID), PublisherIdentityID: nullableText(e.PublisherIdentityID), RunID: nullableText(e.RunID), VisitorConnectionID: nullableText(e.VisitorConnectionID), SourceIp: ip, Outcome: nullableText(e.Outcome), Reason: nullableText(e.Reason), ConfigurationRevision: pgtype.Int8{Int64: e.ConfigurationRevision, Valid: e.ConfigurationRevision > 0}})
	if err != nil || n != 0 {
		return n, err
	}
	var same bool
	err = tx.QueryRow(ctx, `SELECT team_id=$2 AND service_id=$3 AND service_kind=$4 AND event_type=$5
		AND COALESCE(run_id,'')=$6 AND COALESCE(visitor_connection_id,'')=$7
		AND (event_type NOT IN ('connection.open','connection.close','http.decision') OR
		(COALESCE(host(source_ip),'')=$8 AND COALESCE(outcome,'')=$9 AND COALESCE(reason,'')=$10 AND occurred_at=$11))
		FROM control.service_audit_events WHERE id=$1`, e.ID, e.TeamID, e.ServiceID, e.ServiceKind, e.EventType, e.RunID, e.VisitorConnectionID, e.SourceIP, e.Outcome, e.Reason, e.OccurredAt).Scan(&same)
	if err != nil {
		return 0, err
	}
	if !same {
		return 0, ErrServiceAuditAccess
	}
	return 0, nil
}

func auditPrivateMutation(ctx context.Context, tx pgx.Tx, service, actor, operation, request string, now time.Time) error {
	var team string
	var revision int64
	if err := tx.QueryRow(ctx, `SELECT team_id,trust_revision FROM control.services WHERE id=$1`, service).Scan(&team, &revision); err != nil {
		return err
	}
	return RecordServiceAudit(ctx, tx, serviceaudit.Event{TeamID: team, ServiceID: service, ServiceKind: "service", EventType: operation, OccurredAt: now, ActorIdentityID: actor, ConfigurationRevision: revision}, request)
}

func auditPublicMutation(ctx context.Context, tx pgx.Tx, service, actor, operation, request string, now time.Time) error {
	var team string
	var revision int64
	if err := tx.QueryRow(ctx, `SELECT team_id,mutation_revision FROM control.public_urls WHERE id=$1`, service).Scan(&team, &revision); err != nil {
		return err
	}
	return RecordServiceAudit(ctx, tx, serviceaudit.Event{TeamID: team, ServiceID: service, ServiceKind: "public_url", EventType: operation, OccurredAt: now, ActorIdentityID: actor, ConfigurationRevision: revision}, request)
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
		err = tx.QueryRow(ctx, `SELECT ARRAY(SELECT id FROM control.services WHERE team_id=$1 AND (name=$2 OR certificate_hostname=$2) AND deleted_at IS NULL UNION ALL SELECT id FROM control.public_urls WHERE team_id=$1 AND canonical_hostname=$2 AND lifecycle_state<>'deleted' LIMIT 2)`, team, f.Service).Scan(&ids)
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
	rows, err := controlstatedb.New(tx).ListServiceAuditEvents(ctx, controlstatedb.ListServiceAuditEventsParams{TeamID: team, AfterCursor: after, RetainedAfter: timestamptz(now.Add(-serviceaudit.Retention)), Since: nullableTime(f.Since), ServiceID: nullableText(f.ServiceID), PageLimit: int32(f.Limit + 1)})
	if err != nil {
		return page, err
	}
	page.Events = make([]serviceaudit.Event, 0, min(len(rows), f.Limit))
	for i, row := range rows {
		if i == f.Limit {
			page.NextCursor = page.Events[i-1].Cursor
			break
		}
		e := serviceaudit.Event{ID: row.ID, Cursor: strconv.FormatInt(row.Cursor, 10), TeamID: row.TeamID, ServiceID: row.ServiceID, ServiceKind: row.ServiceKind, EventType: row.EventType, OccurredAt: row.OccurredAt.Time, ActorIdentityID: row.ActorIdentityID.String, DeviceID: row.DeviceID.String, PublisherIdentityID: row.PublisherIdentityID.String, RunID: row.RunID.String, VisitorConnectionID: row.VisitorConnectionID.String, Outcome: row.Outcome.String, Reason: row.Reason.String, ConfigurationRevision: row.ConfigurationRevision.Int64}
		if row.SourceIp != nil && row.SourceIp.IsValid() {
			e.SourceIP = row.SourceIp.Unmap().String()
		}
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
	n, err := q.CleanupServiceManagementAudit(ctx, controlstatedb.CleanupServiceManagementAuditParams{BeforeTime: timestamptz(now.Add(-serviceaudit.Retention)), BatchSize: int32(limit) - int32(removed)})
	return removed + n, err
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

// audit delivery does not authorize traffic or renew anything. an exact old run
// token may finish its bounded batch after close/revocation, but cannot report a
// decision timestamp after that run's authority ended or for another run.
func lockServiceAuditPublishRun(ctx context.Context, tx pgx.Tx, auth PublishRunAuthentication, now time.Time) (controlstatedb.ControlPublishRun, time.Time, error) {
	if err := validatePublishRunAuthentication(auth); err != nil {
		return controlstatedb.ControlPublishRun{}, time.Time{}, err
	}
	run, err := controlstatedb.New(tx).LockPublishRun(ctx, auth.PublishRunID)
	if errors.Is(err, pgx.ErrNoRows) {
		return run, time.Time{}, ErrPublishRunCredential
	}
	if err != nil {
		return run, time.Time{}, err
	}
	id, digest, err := credentials.ParsePublishRunToken(auth.PublishRunToken)
	if err != nil || id.String() != run.PublishRunTokenID || !credentials.SecretHashMatches(run.PublishRunTokenDigest, digest) || run.PublicURLID != auth.PublicURLID || run.PublishRunNumber != int64(auth.PublishRunNumber) {
		return run, time.Time{}, ErrPublishRunCredential
	}
	until := run.PublisherExpiresAt.Time
	if run.ClosedAt.Valid && run.ClosedAt.Time.Before(until) {
		until = run.ClosedAt.Time
	}
	if run.PublisherIdentityID.Valid {
		err = tx.QueryRow(ctx, `SELECT LEAST($4::timestamptz,p.revoked_at,g.revoked_at,g.expires_at)
			FROM control.publisher_identities AS p JOIN control.publisher_grants AS g ON g.publisher_identity_id=p.id
			WHERE p.id=$1 AND g.id=$2 AND p.team_id=$3`, run.PublisherIdentityID.String, run.PublisherGrantID.String, run.TeamID, until).Scan(&until)
		if errors.Is(err, pgx.ErrNoRows) {
			return run, time.Time{}, ErrPublishRunCredential
		}
		if err != nil {
			return run, time.Time{}, err
		}
	}
	if !run.ReadyAt.Valid || now.After(until.Add(serviceObservationDeliveryGrace)) {
		return run, time.Time{}, ErrPublishRunStale
	}
	return run, until, nil
}

func (d *Database) IngestPublisherServiceObservations(ctx context.Context, auth PublishRunAuthentication, batch serviceaudit.Batch, now time.Time) (result ServiceObservationResult, retErr error) {
	if err := validateObservationBatch(batch, now); err != nil {
		return result, err
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "ingest publisher service audit", &retErr)()
	run, until, err := lockServiceAuditPublishRun(ctx, tx, auth, now)
	if err != nil {
		return result, err
	}
	for _, o := range batch.Events {
		if o.ServiceKind != "public_url" || o.ServiceID != run.PublicURLID || o.RunID != run.ID || o.RunNumber != run.PublishRunNumber || o.EventType != "http.decision" {
			return ServiceObservationResult{}, ErrServiceAuditAccess
		}
		if o.OccurredAt.Before(run.CreatedAt.Time.Add(-time.Second)) || o.OccurredAt.After(until) {
			return ServiceObservationResult{}, ErrServiceAuditAccess
		}
		e := observationEvent(o)
		e.TeamID = run.TeamID
		e.PublisherIdentityID = run.PublisherIdentityID.String
		n, err := insertServiceAuditCount(ctx, tx, e, now)
		if err != nil {
			return ServiceObservationResult{}, err
		}
		result.Accepted += int(n)
		result.Duplicates += 1 - int(n)
	}
	if err = tx.Commit(ctx); err != nil {
		return ServiceObservationResult{}, err
	}
	d.activity.metrics.Load().ServiceAuditCount("accepted", uint64(result.Accepted))
	d.activity.metrics.Load().ServiceAuditCount("duplicate", uint64(result.Duplicates))
	return result, nil
}

func observationEvent(o serviceaudit.Observation) serviceaudit.Event {
	return serviceaudit.Event{ID: o.EventID, ServiceID: o.ServiceID, ServiceKind: o.ServiceKind, EventType: o.EventType, OccurredAt: o.OccurredAt, RunID: o.RunID, VisitorConnectionID: o.VisitorConnectionID, SourceIP: o.SourceIP, Outcome: o.Outcome, Reason: o.Reason}
}

func (d *Database) IngestIngressServiceObservations(ctx context.Context, lease IngressLeaseIdentity, batch serviceaudit.Batch, now time.Time) (result ServiceObservationResult, retErr error) {
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
	if _, err = lockCurrentIngressLease(ctx, controlstatedb.New(tx), lease, now); err != nil {
		return result, err
	}
	events := make([]serviceaudit.Event, 0, len(batch.Events))
	for _, o := range batch.Events {
		if o.EventType != "connection.open" && o.EventType != "connection.close" {
			return ServiceObservationResult{}, ErrServiceAuditAccess
		}
		e := observationEvent(o)
		if o.ServiceKind == "public_url" {
			if o.RunID == "" {
				err = tx.QueryRow(ctx, `SELECT team_id FROM control.public_urls WHERE id=$1`, o.ServiceID).Scan(&e.TeamID)
			} else {
				err = tx.QueryRow(ctx, `SELECT r.team_id,r.publisher_identity_id FROM control.publish_runs r JOIN control.public_urls s ON s.id=r.public_url_id
				WHERE r.id=$1 AND r.public_url_id=$2 AND r.publish_run_number=$3 AND r.created_at<=$4::timestamptz+interval '1 minute'`, o.RunID, o.ServiceID, o.RunNumber, o.OccurredAt).Scan(&e.TeamID, (*nullableAuditString)(&e.PublisherIdentityID))
			}
		} else if o.RunID == "" {
			// a denied visitor entry has no verified run. scope it only to
			// the saved service of the authenticated connector session;
			// never attach a visitor-chosen run or publisher identity.
			err = tx.QueryRow(ctx, `SELECT s.team_id,c.identity_id,c.device_id FROM control.connector_sessions c
				JOIN control.services s ON s.id=c.service_id
				WHERE c.id=$1 AND c.service_id=$2 AND c.ingress_id=$3 AND c.ingress_run_id=$4 AND c.ingress_lease_revision=$5
				AND host(c.source_ip)=$6 AND c.bound_at IS NOT NULL AND c.bound_at<=$7::timestamptz+interval '1 minute'
				AND NOT EXISTS(SELECT 1 FROM control.service_audit_events WHERE visitor_connection_id=$8 AND service_id=$2 AND event_type='connection.open' AND outcome='allowed')`,
				o.ConnectorSessionID, o.ServiceID, lease.IngressID, lease.IngressRunID, int64(lease.IngressLeaseRevision), o.SourceIP, o.OccurredAt, o.VisitorConnectionID).
				Scan(&e.TeamID, (*nullableAuditString)(&e.ActorIdentityID), (*nullableAuditString)(&e.DeviceID))
		} else if o.ConnectorSessionID == "" {
			// direct traffic holds an exact ingress allocation. the publisher's
			// one-way promotion supplies only an immutable attribution reference;
			// control derives human names/IDs from its issuance or sign-in facts.
			err = tx.QueryRow(ctx, `SELECT s.team_id,r.publisher_identity_id FROM control.services s
				JOIN control.service_runs r ON r.service_id=s.id AND r.id=$3 AND r.run_number=$4
				JOIN control.stream_capacity_allocations a ON a.resource_kind='service' AND a.resource_id=s.id AND a.run_id=r.id AND a.run_number=r.run_number
				WHERE s.id=$2 AND a.id=$1 AND a.ingress_id=$5 AND a.ingress_run_id=$6 AND a.ingress_lease_revision=$7
				AND a.publisher_observed_at IS NOT NULL AND a.issued_at<=$8::timestamptz+interval '1 minute'
				AND r.created_at<=$8::timestamptz+interval '1 minute'
				AND ($9<>'connection.open' OR $10<>'allowed' OR ($8<=a.valid_until AND $8<=r.publisher_expires_at AND (r.closed_at IS NULL OR $8<=r.closed_at)))`,
				o.StreamAllocationID, o.ServiceID, o.RunID, o.RunNumber, lease.IngressID, lease.IngressRunID, int64(lease.IngressLeaseRevision), o.OccurredAt, o.EventType, o.Outcome).Scan(&e.TeamID, &e.PublisherIdentityID)
			if err == nil && (o.Outcome == "allowed" || o.EventType == "connection.close") {
				err = resolveDirectAuditVisitor(ctx, tx, o, &e)
			}
		} else {
			// immutable session facts supply identity and source; the authenticated
			// allocation binds the reported run to this exact ingress process. a
			// visitor-chosen actor, run, or another ingress's allocation cannot
			// manufacture private audit scope, including after revocation.
			err = tx.QueryRow(ctx, `SELECT s.team_id,c.identity_id,c.device_id,r.publisher_identity_id
				FROM control.connector_sessions c JOIN control.services s ON s.id=c.service_id
				JOIN control.service_runs r ON r.service_id=s.id AND r.id=$3 AND r.run_number=$4
				JOIN control.stream_capacity_allocations a ON a.resource_kind='service' AND a.resource_id=s.id AND a.run_id=r.id AND a.run_number=r.run_number
				WHERE c.service_id=$2 AND c.id=$9 AND host(c.source_ip)=$8 AND c.bound_at IS NOT NULL
				AND c.ingress_id=$5 AND c.ingress_run_id=$6 AND c.ingress_lease_revision=$7
				AND a.id=$1 AND a.ingress_id=$5 AND a.ingress_run_id=$6 AND a.ingress_lease_revision=$7
				AND a.publisher_observed_at IS NOT NULL AND a.issued_at<=$10::timestamptz+interval '1 minute'
				AND c.bound_at<=$10::timestamptz+interval '1 minute' AND r.created_at<=$10::timestamptz+interval '1 minute'
				AND ($11<>'connection.open' OR $12<>'allowed' OR ($10<=a.valid_until AND $10<=c.expires_at AND $10<=r.publisher_expires_at AND (r.closed_at IS NULL OR $10<=r.closed_at)))`,
				o.StreamAllocationID, o.ServiceID, o.RunID, o.RunNumber, lease.IngressID, lease.IngressRunID, int64(lease.IngressLeaseRevision), o.SourceIP, o.ConnectorSessionID, o.OccurredAt, o.EventType, o.Outcome).
				Scan(&e.TeamID, (*nullableAuditString)(&e.ActorIdentityID), (*nullableAuditString)(&e.DeviceID), &e.PublisherIdentityID)
		}
		if errors.Is(err, pgx.ErrNoRows) {
			return ServiceObservationResult{}, ErrServiceAuditAccess
		}
		if err != nil {
			return ServiceObservationResult{}, err
		}
		events = append(events, e)
	}
	// batches can span teams. acquire audit clocks in one order to avoid two
	// ingress reporters holding opposite teams while waiting for each other.
	sort.SliceStable(events, func(i, j int) bool { return events[i].TeamID < events[j].TeamID })
	for _, e := range events {
		n, err := insertServiceAuditCount(ctx, tx, e, now)
		if err != nil {
			return ServiceObservationResult{}, err
		}
		result.Accepted += int(n)
		result.Duplicates += 1 - int(n)
	}
	if err = tx.Commit(ctx); err != nil {
		return ServiceObservationResult{}, err
	}
	d.activity.metrics.Load().ServiceAuditCount("accepted", uint64(result.Accepted))
	d.activity.metrics.Load().ServiceAuditCount("duplicate", uint64(result.Duplicates))
	return result, nil
}

func resolveDirectAuditVisitor(ctx context.Context, tx pgx.Tx, observation serviceaudit.Observation, event *serviceaudit.Event) error {
	reference := observation.VisitorReference
	if !reference.Valid() {
		return ErrServiceAuditAccess
	}
	switch reference.Kind {
	case "certificate":
		digest, err := hex.DecodeString(reference.ID)
		if err != nil {
			return ErrServiceAuditAccess
		}
		return tx.QueryRow(ctx, `SELECT identity_id,device_id FROM control.visitor_certificate_facts
		    WHERE certificate_digest=$1 AND service_id=$2 AND issued_at<=$3::timestamptz+interval '1 minute'`, digest, observation.ServiceID, observation.OccurredAt).
			Scan((*nullableAuditString)(&event.ActorIdentityID), (*nullableAuditString)(&event.DeviceID))
	case "browser_session":
		return tx.QueryRow(ctx, `SELECT parent.identity_id FROM control.control_sessions parent
		    WHERE parent.id=$1 AND parent.created_at<=$4::timestamptz+interval '1 minute'
		    AND EXISTS(SELECT 1 FROM control.service_http_browser_sessions browser WHERE browser.control_session_id=parent.id AND browser.service_id=$2 AND $3=ANY(browser.run_ids))`, reference.ID, observation.ServiceID, observation.RunID, observation.OccurredAt).Scan(&event.ActorIdentityID)
	case "grant":
		// a bearer grant does not identify the person presenting it. its issuer
		// is not a verified visitor or feedback author.
		var found string
		return tx.QueryRow(ctx, `SELECT id FROM control.service_http_grants WHERE id=$1 AND service_id=$2`, reference.ID, observation.ServiceID).Scan(&found)
	default:
		return ErrServiceAuditAccess
	}
}

type nullableAuditString string

func (s *nullableAuditString) ScanText(v pgtype.Text) error {
	*s = nullableAuditString(v.String)
	return nil
}

func auditDeviceMutation(ctx context.Context, tx pgx.Tx, identity, device, operation string, now time.Time) error {
	rows, err := tx.Query(ctx, `SELECT DISTINCT s.team_id,s.id FROM control.services s WHERE
		EXISTS(SELECT 1 FROM control.team_memberships m WHERE m.team_id=s.team_id AND m.identity_id=$1 AND m.removed_at IS NULL)
		OR EXISTS(SELECT 1 FROM control.visitor_grants g WHERE g.service_id=s.id AND g.identity_id=$1)
		OR EXISTS(SELECT 1 FROM control.connector_sessions c WHERE c.service_id=s.id AND c.device_id=$2)
		ORDER BY s.team_id,s.id`, identity, device)
	if err != nil {
		return err
	}
	type scope struct{ team, id string }
	var scopes []scope
	for rows.Next() {
		var s scope
		if err = rows.Scan(&s.team, &s.id); err != nil {
			rows.Close()
			return err
		}
		scopes = append(scopes, s)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, s := range scopes {
		if err = RecordServiceAudit(ctx, tx, serviceaudit.Event{TeamID: s.team, ServiceID: s.id, ServiceKind: "service", EventType: operation, OccurredAt: now, ActorIdentityID: identity, DeviceID: device}, device); err != nil {
			return err
		}
	}
	return nil
}
