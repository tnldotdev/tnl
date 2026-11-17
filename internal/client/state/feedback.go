package state

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"math"
	"time"

	"github.com/tnldotdev/tnl/internal/client/state/clientstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// FeedbackAuthorize obtains a fresh content-free control decision. it is composed
// by the publisher or signed-in client, never supplied by browser input.
type FeedbackAuthorize func(context.Context, string, string) (controlv1.FeedbackAuthorization, error)

// FeedbackStore owns content for exactly one local directory, server and preview.
// it shares client state's connection and transaction/cleanup ownership.
type FeedbackStore struct {
	store            *Store
	project, preview string
	authorize        FeedbackAuthorize
}

func (s *Store) Feedback(ctx context.Context, root, preview string, authorize FeedbackAuthorize) (*FeedbackStore, error) {
	project, _, err := s.database.LocalProjectIdentity(ctx, root)
	if err != nil {
		return nil, err
	}
	return s.feedback(ctx, project, preview, authorize)
}

func (s *Store) DemoFeedback(ctx context.Context, preview string, authorize FeedbackAuthorize) (*FeedbackStore, error) {
	return s.feedback(ctx, "demo/"+preview, preview, authorize)
}

func (s *Store) feedback(ctx context.Context, project, preview string, authorize FeedbackAuthorize) (*FeedbackStore, error) {
	if authorize == nil || !opaqueid.Valid(preview, opaqueid.PreviewPrefix) {
		return nil, ErrFeedbackInvalid
	}
	if err := s.database.queries.PruneExpiredLocalFeedback(ctx, sql.NullInt64{Int64: s.database.now().UnixNano(), Valid: true}); err != nil {
		return nil, err
	}
	if err := s.database.queries.EnsureFeedbackClock(ctx, clientstatedb.EnsureFeedbackClockParams{ServerOrigin: s.controlEndpoint, ProjectRoot: project, PreviewID: preview}); err != nil {
		return nil, err
	}
	return &FeedbackStore{store: s, project: project, preview: preview, authorize: authorize}, nil
}

// DiscardDemoFeedback is run cleanup, not a browser deletion capability.
// the exact demo-only scope cannot select a project/worktree's retained feedback.
func (s *Store) DiscardDemoFeedback(ctx context.Context, preview string) error {
	if !opaqueid.Valid(preview, opaqueid.PreviewPrefix) {
		return ErrFeedbackInvalid
	}
	return s.database.queries.DiscardDemoFeedback(ctx, clientstatedb.DiscardDemoFeedbackParams{
		ServerOrigin: s.controlEndpoint, ProjectRoot: "demo/" + preview, PreviewID: preview,
	})
}

func (f *FeedbackStore) checked(ctx context.Context, service, operation string) (controlv1.FeedbackAuthorization, error) {
	a, err := f.authorize(ctx, service, operation)
	if err != nil {
		return a, err
	}
	now := f.store.database.now()
	if a.ServiceId != service || a.PreviewId != f.preview || string(a.Operation) != operation || !a.ExpiresAt.After(now) ||
		a.ExpiresAt.After(now.Add(5*time.Second)) || a.Actor != "reviewer" && a.Actor != "implementer" {
		return controlv1.FeedbackAuthorization{}, ErrFeedbackAccess
	}
	if operation != "read" && (a.Author.IdentityId == nil || *a.Author.IdentityId == "" || !a.Author.Verified || a.Author.DisplayName == "") {
		return controlv1.FeedbackAuthorization{}, ErrFeedbackAccess
	}
	if !localFeedbackPermits(a.Actor, operation) {
		return controlv1.FeedbackAuthorization{}, ErrFeedbackAccess
	}
	return a, nil
}

// authorization may refresh a control session in this same database. never call
// it while holding SQLite's connection or a transaction. lock waits spend the
// original decision deadline; they cannot renew it.
func (f *FeedbackStore) begin(ctx context.Context, decisions ...controlv1.FeedbackAuthorization) (context.Context, *sql.Tx, context.CancelFunc, error) {
	now := f.store.database.now()
	budget := 5 * time.Second
	for _, a := range decisions {
		if !a.ExpiresAt.After(now) {
			return nil, nil, nil, ErrFeedbackAccess
		}
		budget = min(budget, a.ExpiresAt.Sub(now))
	}
	bounded, stop := context.WithTimeout(ctx, budget)
	tx, err := f.store.database.db.BeginTx(bounded, nil)
	if err != nil {
		stop()
		if ctx.Err() == nil && feedbackDecisionsExpired(decisions, f.store.database.now()) {
			err = errors.Join(ErrFeedbackAccess, err)
		}
		return nil, nil, nil, err
	}
	now = f.store.database.now()
	for _, a := range decisions {
		if !a.ExpiresAt.After(now) {
			err = ErrFeedbackAccess
			rollbackFeedback(tx, &err)
			stop()
			return nil, nil, nil, err
		}
	}
	return bounded, tx, stop, nil
}

func feedbackDecisionsExpired(decisions []controlv1.FeedbackAuthorization, now time.Time) bool {
	for _, a := range decisions {
		if !a.ExpiresAt.After(now) {
			return true
		}
	}
	return false
}

func (f *FeedbackStore) readDecisions(ctx context.Context, service string) (map[string]controlv1.FeedbackAuthorization, []controlv1.FeedbackAuthorization, error) {
	services := []string{service}
	if service == "" {
		var err error
		services, err = f.store.database.queries.LocalFeedbackServices(ctx, clientstatedb.LocalFeedbackServicesParams{ServerOrigin: f.store.controlEndpoint, ProjectRoot: f.project, PreviewID: f.preview})
		if err != nil {
			return nil, nil, err
		}
	}
	byService := map[string]controlv1.FeedbackAuthorization{}
	var decisions []controlv1.FeedbackAuthorization
	for _, service := range services {
		a, err := f.checked(ctx, service, "read")
		if err != nil {
			return nil, nil, err
		}
		byService[service] = a
		decisions = append(decisions, a)
	}
	return byService, decisions, nil
}

func (f *FeedbackStore) commit(ctx context.Context, tx *sql.Tx, decisions ...controlv1.FeedbackAuthorization) error {
	for _, a := range decisions {
		if f.project == "demo/"+f.preview {
			if a.ContentExpiresAt == nil || !a.ContentExpiresAt.After(f.store.database.now()) {
				return ErrFeedbackAccess
			}
			if err := f.store.database.queries.WithTx(tx).SetDemoFeedbackRetention(ctx, clientstatedb.SetDemoFeedbackRetentionParams{
				ExpiresAt:    sql.NullInt64{Int64: a.ContentExpiresAt.UnixNano(), Valid: true},
				ServerOrigin: f.store.controlEndpoint, ProjectRoot: f.project, PreviewID: f.preview,
			}); err != nil {
				return err
			}
		}
	}
	now := f.store.database.now()
	for _, a := range decisions {
		if !a.ExpiresAt.After(now) {
			return ErrFeedbackAccess
		}
	}
	// the transaction's context is bounded by the original decision deadline.
	// the final check follows every statement; commit grants no later operation.
	if err := ctx.Err(); err != nil {
		return err
	}
	err := tx.Commit()
	now = f.store.database.now()
	for _, a := range decisions {
		if !a.ExpiresAt.After(now) {
			return errors.Join(ErrFeedbackAccess, err)
		}
	}
	return err
}

func rollbackFeedback(tx *sql.Tx, retErr *error) {
	if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
		*retErr = errors.Join(*retErr, err)
	}
}

func (f *FeedbackStore) queryID(id string) clientstatedb.GetLocalFeedbackThreadParams {
	return clientstatedb.GetLocalFeedbackThreadParams{ServerOrigin: f.store.controlEndpoint, ProjectRoot: f.project, PreviewID: f.preview, ID: id}
}
func (f *FeedbackStore) reserve(ctx context.Context, q *clientstatedb.Queries) (int64, error) {
	return q.ReserveLocalFeedbackCursor(ctx, clientstatedb.ReserveLocalFeedbackCursorParams{ServerOrigin: f.store.controlEndpoint, ProjectRoot: f.project, PreviewID: f.preview})
}
func (f *FeedbackStore) highWater(ctx context.Context, q *clientstatedb.Queries) (int64, error) {
	return q.LocalFeedbackHighWater(ctx, clientstatedb.LocalFeedbackHighWaterParams{ServerOrigin: f.store.controlEndpoint, ProjectRoot: f.project, PreviewID: f.preview})
}
func localFeedbackThread(row clientstatedb.FeedbackThread) (controlv1.FeedbackThread, error) {
	var result controlv1.FeedbackThread
	err := json.Unmarshal([]byte(row.Report), &result)
	result.State = controlv1.FeedbackThreadState(row.State)
	result.MessageCount = row.MessageCount
	result.LatestEventCursor = row.LatestEventCursor
	return result, err
}
func feedbackLookup(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrFeedbackNotFound
	}
	return err
}

// Create validates and normalizes locally before authorization. no submitted
// content, request digest or thread ID is sent to control.
func (f *FeedbackStore) Create(ctx context.Context, service, run, key string, body controlv1.CreateFeedbackReportRequest) (result controlv1.FeedbackThread, retErr error) {
	if !opaqueid.Valid(service, opaqueid.ServicePrefix) || !opaqueid.Valid(run, opaqueid.ServiceRunPrefix) ||
		body.PreviewId != f.preview || !naming.ValidServiceName(body.Service) || !validFeedbackPath(body.PagePath) ||
		!validFeedbackText(body.Report.Text, 4000) || !validFeedbackKey(key) || body.RunNumber < 1 ||
		body.PageTitle != nil && len([]rune(*body.PageTitle)) > 256 {
		return result, ErrFeedbackInvalid
	}
	anchor, err := json.Marshal(body.Anchor)
	if err != nil {
		return result, ErrFeedbackInvalid
	}
	anchor, err = normalizeFeedbackAnchor(anchor)
	if err != nil {
		return result, err
	}
	evidence, err := json.Marshal(body.Evidence)
	if err != nil {
		return result, ErrFeedbackInvalid
	}
	evidence, err = normalizeFeedbackEvidence(evidence)
	if err != nil {
		return result, err
	}
	source, err := json.Marshal(body.SourceAtReport)
	if err != nil {
		return result, ErrFeedbackInvalid
	}
	source, err = normalizeSourceState(source)
	if err != nil {
		return result, err
	}
	a, err := f.checked(ctx, service, "report")
	if err != nil {
		return result, err
	}
	if a.Actor != "reviewer" || a.ServiceRunId != run || a.RunNumber != body.RunNumber {
		return result, ErrFeedbackAccess
	}
	ctx, tx, stop, err := f.begin(ctx, a)
	if err != nil {
		return result, err
	}
	defer stop()
	defer rollbackFeedback(tx, &retErr)
	q := f.store.database.queries.WithTx(tx)
	result = controlv1.FeedbackThread{
		SchemaVersion: 1, State: controlv1.Open, MessageCount: 1,
		Scope:  controlv1.FeedbackScope{PreviewId: f.preview, ServiceId: service, ServiceRunId: run, RunNumber: body.RunNumber, Service: body.Service, PagePath: body.PagePath, PageTitle: body.PageTitle},
		Report: controlv1.FeedbackReport{Text: body.Report.Text, Author: &a.Author},
	}
	if len(anchor) != 0 {
		if err = json.Unmarshal(anchor, &result.Anchor); err != nil {
			return result, err
		}
	}
	if err = json.Unmarshal(evidence, &result.Evidence); err != nil {
		return result, err
	}
	if err = json.Unmarshal(source, &result.SourceAtReport); err != nil {
		return result, err
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return result, err
	}
	digest := sha256.Sum256(raw)
	existing, err := q.LocalFeedbackReportRetry(ctx, clientstatedb.LocalFeedbackReportRetryParams{ServerOrigin: f.store.controlEndpoint, ProjectRoot: f.project, PreviewID: f.preview, ServiceID: service, ServiceRunID: run, ActorReference: *a.Author.IdentityId, IdempotencyKey: key})
	if err == nil {
		if subtle.ConstantTimeCompare(existing.RequestDigest, digest[:]) != 1 {
			return result, ErrFeedbackIdempotency
		}
		result, err = localFeedbackThread(existing)
		if err != nil {
			return result, err
		}
		return result, f.commit(ctx, tx, a)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return result, err
	}
	id, err := opaqueid.New(opaqueid.FeedbackPrefix)
	if err != nil {
		return result, err
	}
	cursor, err := f.reserve(ctx, q)
	if err != nil {
		return result, err
	}
	now := f.store.database.now().UTC()
	result.Id, result.LatestEventCursor, result.Report.CreatedAt = id, cursor, now
	raw, err = json.Marshal(result)
	if err != nil {
		return result, err
	}
	if err = q.CreateLocalFeedbackThread(ctx, clientstatedb.CreateLocalFeedbackThreadParams{ID: id, ServerOrigin: f.store.controlEndpoint, ProjectRoot: f.project, PreviewID: f.preview, ServiceID: service, ServiceRunID: run, PagePath: body.PagePath, LatestEventCursor: cursor, Report: string(raw), ActorReference: *a.Author.IdentityId, IdempotencyKey: key, RequestDigest: digest[:]}); err != nil {
		return result, err
	}
	event := controlv1.FeedbackEvent{SchemaVersion: 1, Cursor: cursor, FeedbackId: id, Type: controlv1.FeedbackEventType("thread.created"), Actor: controlv1.FeedbackEventActor(a.Actor), Author: &a.Author, At: now}
	if err = insertLocalFeedbackEvent(ctx, q, event, key, digest[:]); err != nil {
		return result, err
	}
	return result, f.commit(ctx, tx, a)
}

func insertLocalFeedbackEvent(ctx context.Context, q *clientstatedb.Queries, event controlv1.FeedbackEvent, key string, digest []byte) error {
	raw, err := json.Marshal(event)
	if err != nil {
		return err
	}
	return q.InsertLocalFeedbackEvent(ctx, clientstatedb.InsertLocalFeedbackEventParams{FeedbackID: event.FeedbackId, Cursor: event.Cursor, ActorKind: string(event.Actor), ActorReference: *event.Author.IdentityId, IdempotencyKey: key, RequestDigest: digest, Event: string(raw)})
}

func (f *FeedbackStore) GetFeedbackThread(ctx context.Context, id string) (result controlv1.FeedbackThread, retErr error) {
	if !opaqueid.Valid(id, opaqueid.FeedbackPrefix) {
		return result, ErrFeedbackNotFound
	}
	candidate, err := f.store.database.queries.GetLocalFeedbackThread(ctx, f.queryID(id))
	if err != nil {
		return result, feedbackLookup(err)
	}
	a, err := f.checked(ctx, candidate.ServiceID, "read")
	if err != nil {
		return result, err
	}
	ctx, tx, stop, err := f.begin(ctx, a)
	if err != nil {
		return result, err
	}
	defer stop()
	defer rollbackFeedback(tx, &retErr)
	row, err := f.store.database.queries.WithTx(tx).GetLocalFeedbackThread(ctx, f.queryID(id))
	if err != nil {
		return result, feedbackLookup(err)
	}
	if row.ServiceID != a.ServiceId {
		return result, ErrFeedbackAccess
	}
	result, err = localFeedbackThread(row)
	if err != nil {
		return result, err
	}
	return result, f.commit(ctx, tx, a)
}

func (f *FeedbackStore) AppendFeedbackEvent(ctx context.Context, id, key string, body controlv1.AppendFeedbackEventRequest) (result controlv1.FeedbackEvent, retErr error) {
	operation := string(body.Type)
	if !opaqueid.Valid(id, opaqueid.FeedbackPrefix) || !validFeedbackKey(key) || !body.Type.Valid() || body.Text != nil && !validFeedbackText(*body.Text, 4000) ||
		(operation == "reply" || operation == "update") && body.Text == nil || (operation == "update") != (body.SourceState != nil) {
		return result, ErrFeedbackInvalid
	}
	if body.Evidence != nil {
		raw, err := json.Marshal(body.Evidence)
		if err != nil {
			return result, ErrFeedbackInvalid
		}
		raw, err = normalizeFeedbackEvidence(raw)
		if err != nil {
			return result, err
		}
		if err = json.Unmarshal(raw, &body.Evidence); err != nil {
			return result, err
		}
	}
	if body.SourceState != nil {
		raw, err := json.Marshal(body.SourceState)
		if err != nil {
			return result, ErrFeedbackInvalid
		}
		if _, err = normalizeSourceState(raw); err != nil {
			return result, err
		}
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return result, ErrFeedbackInvalid
	}
	digest := sha256.Sum256(raw)
	candidate, err := f.store.database.queries.GetLocalFeedbackThread(ctx, f.queryID(id))
	if err != nil {
		return result, feedbackLookup(err)
	}
	a, err := f.checked(ctx, candidate.ServiceID, operation)
	if err != nil {
		return result, err
	}
	ctx, tx, stop, err := f.begin(ctx, a)
	if err != nil {
		return result, err
	}
	defer stop()
	defer rollbackFeedback(tx, &retErr)
	q := f.store.database.queries.WithTx(tx)
	row, err := q.GetLocalFeedbackThread(ctx, f.queryID(id))
	if err != nil {
		return result, feedbackLookup(err)
	}
	if row.ServiceID != a.ServiceId {
		return result, ErrFeedbackAccess
	}
	existing, err := q.LocalFeedbackEventRetry(ctx, clientstatedb.LocalFeedbackEventRetryParams{FeedbackID: id, ActorKind: a.Actor, ActorReference: *a.Author.IdentityId, IdempotencyKey: key})
	if err == nil {
		if subtle.ConstantTimeCompare(existing.RequestDigest, digest[:]) != 1 {
			return result, ErrFeedbackIdempotency
		}
		if err = json.Unmarshal([]byte(existing.Event), &result); err != nil {
			return result, err
		}
		return result, f.commit(ctx, tx, a)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return result, err
	}
	next, err := FeedbackThreadState(row.State).transition(FeedbackEventType(operation))
	if err != nil {
		return result, err
	}
	cursor, err := f.reserve(ctx, q)
	if err != nil {
		return result, err
	}
	result = controlv1.FeedbackEvent{SchemaVersion: 1, Cursor: cursor, FeedbackId: id, Type: controlv1.FeedbackEventType(body.Type), Actor: controlv1.FeedbackEventActor(a.Actor), Author: &a.Author, At: f.store.database.now().UTC(), Text: body.Text, Evidence: body.Evidence, SourceState: body.SourceState}
	if err = insertLocalFeedbackEvent(ctx, q, result, key, digest[:]); err != nil {
		return result, err
	}
	var add int64
	if operation == "reply" || operation == "update" {
		add = 1
	}
	if err = q.UpdateLocalFeedbackActivity(ctx, clientstatedb.UpdateLocalFeedbackActivityParams{ID: id, NextState: string(next), Cursor: cursor, AddMessage: add}); err != nil {
		return result, err
	}
	return result, f.commit(ctx, tx, a)
}

func (f *FeedbackStore) Delete(ctx context.Context, id string) (retErr error) {
	if !opaqueid.Valid(id, opaqueid.FeedbackPrefix) {
		return ErrFeedbackNotFound
	}
	candidate, err := f.store.database.queries.GetLocalFeedbackThread(ctx, f.queryID(id))
	if err != nil {
		return feedbackLookup(err)
	}
	a, err := f.checked(ctx, candidate.ServiceID, "delete")
	if err != nil {
		return err
	}
	ctx, tx, stop, err := f.begin(ctx, a)
	if err != nil {
		return err
	}
	defer stop()
	defer rollbackFeedback(tx, &retErr)
	q := f.store.database.queries.WithTx(tx)
	row, err := q.GetLocalFeedbackThread(ctx, f.queryID(id))
	if err != nil {
		return feedbackLookup(err)
	}
	if row.ServiceID != a.ServiceId {
		return ErrFeedbackAccess
	}
	if _, err = q.DeleteLocalFeedbackThread(ctx, clientstatedb.DeleteLocalFeedbackThreadParams{ServerOrigin: f.store.controlEndpoint, ProjectRoot: f.project, PreviewID: f.preview, ID: id, ServiceID: row.ServiceID}); err != nil {
		return err
	}
	return f.commit(ctx, tx, a)
}

func (f *FeedbackStore) List(ctx context.Context, service, path, state, cursor string) (result controlv1.FeedbackThreadPage, retErr error) {
	result = controlv1.FeedbackThreadPage{SchemaVersion: 1, Threads: []controlv1.FeedbackThreadSummary{}}
	if path != "" && !validFeedbackPath(path) || state != "" && state != "open" && state != "resolved" || cursor != "" && !opaqueid.Valid(cursor, opaqueid.FeedbackPrefix) {
		return result, ErrFeedbackInvalid
	}
	decisions, checked, err := f.readDecisions(ctx, service)
	if err != nil {
		return result, err
	}
	ctx, tx, stop, err := f.begin(ctx, checked...)
	if err != nil {
		return result, err
	}
	defer stop()
	defer rollbackFeedback(tx, &retErr)
	q := f.store.database.queries.WithTx(tx)
	result.EventCursor, err = f.highWater(ctx, q)
	if err != nil {
		return result, err
	}
	rows, err := q.ListLocalFeedbackThreads(ctx, clientstatedb.ListLocalFeedbackThreadsParams{ServerOrigin: f.store.controlEndpoint, ProjectRoot: f.project, PreviewID: f.preview, ServiceID: service, PagePath: path, ThreadState: state, AfterID: cursor})
	if err != nil {
		return result, err
	}
	for index, row := range rows {
		if index == 100 {
			id := rows[index-1].ID
			result.NextCursor = &id
			break
		}
		if _, ok := decisions[row.ServiceID]; !ok {
			return result, ErrFeedbackState
		}
		thread, err := localFeedbackThread(row)
		if err != nil {
			return result, err
		}
		result.Threads = append(result.Threads, controlv1.FeedbackThreadSummary{SchemaVersion: thread.SchemaVersion, Id: thread.Id, State: thread.State, Scope: thread.Scope, Report: thread.Report, Anchor: thread.Anchor, MessageCount: thread.MessageCount, LatestEventCursor: thread.LatestEventCursor})
	}
	return result, f.commit(ctx, tx, checked...)
}

func (f *FeedbackStore) Events(ctx context.Context, service, id string, after uint64) (result controlv1.FeedbackEventPage, retErr error) {
	result = controlv1.FeedbackEventPage{SchemaVersion: 1, Events: []controlv1.FeedbackEvent{}}
	if after > math.MaxInt64 || id != "" && !opaqueid.Valid(id, opaqueid.FeedbackPrefix) {
		return result, ErrFeedbackInvalid
	}
	if id != "" {
		row, err := f.store.database.queries.GetLocalFeedbackThread(ctx, f.queryID(id))
		if err != nil {
			return result, feedbackLookup(err)
		}
		if service != "" && service != row.ServiceID {
			return result, ErrFeedbackNotFound
		}
		service = row.ServiceID
	}
	decisions, checked, err := f.readDecisions(ctx, service)
	if err != nil {
		return result, err
	}
	ctx, tx, stop, err := f.begin(ctx, checked...)
	if err != nil {
		return result, err
	}
	defer stop()
	defer rollbackFeedback(tx, &retErr)
	q := f.store.database.queries.WithTx(tx)
	if id != "" {
		if _, err := q.GetLocalFeedbackThread(ctx, f.queryID(id)); err != nil {
			return result, feedbackLookup(err)
		}
	}
	result.EventCursor, err = f.highWater(ctx, q)
	if err != nil {
		return result, err
	}
	rows, err := q.ListLocalFeedbackEvents(ctx, clientstatedb.ListLocalFeedbackEventsParams{ServerOrigin: f.store.controlEndpoint, ProjectRoot: f.project, PreviewID: f.preview, ServiceID: service, FeedbackID: id, AfterCursor: int64(after)})
	if err != nil {
		return result, err
	}
	for index, row := range rows {
		if index == 25 {
			cursor := rows[index-1].Cursor
			result.NextCursor = &cursor
			break
		}
		thread, err := q.GetLocalFeedbackThread(ctx, f.queryID(row.FeedbackID))
		if err != nil {
			return result, feedbackLookup(err)
		}
		if _, ok := decisions[thread.ServiceID]; !ok {
			return result, ErrFeedbackState
		}
		var event controlv1.FeedbackEvent
		if err = json.Unmarshal([]byte(row.Event), &event); err != nil {
			return result, err
		}
		result.Events = append(result.Events, event)
	}
	return result, f.commit(ctx, tx, checked...)
}
