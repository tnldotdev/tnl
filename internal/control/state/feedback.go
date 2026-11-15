package state

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

var (
	ErrFeedbackNotFound    = errors.New("controlstate: feedback thread not found")
	ErrFeedbackInvalid     = errors.New("controlstate: feedback request is invalid")
	ErrFeedbackAccess      = errors.New("controlstate: feedback access denied")
	ErrFeedbackIdempotency = errors.New("controlstate: feedback idempotency conflict")
	ErrFeedbackState       = errors.New("controlstate: feedback state changed")
)

type FeedbackThreadState string

const (
	FeedbackOpen     FeedbackThreadState = "open"
	FeedbackResolved FeedbackThreadState = "resolved"
)

type FeedbackEventType string

const (
	FeedbackCreated        FeedbackEventType = "thread.created"
	FeedbackReply          FeedbackEventType = "reply"
	FeedbackUpdate         FeedbackEventType = "update"
	FeedbackThreadResolved FeedbackEventType = "thread.resolved"
	FeedbackThreadReopened FeedbackEventType = "thread.reopened"
)

type FeedbackActor struct {
	SourceIP            string
	ServiceRun          *ServiceHTTPRun
	Kind                string
	IdentityID          string
	DisplayName         string
	BrowserCookieSecret []byte
	TeamMember          bool
	ShareID             string
	CookieSecret        []byte
	ShareSecret         []byte
	VisitAllowed        bool
	VisitProof          FeedbackVisitProof
}

type feedbackActorKind string

const (
	feedbackReviewer    feedbackActorKind = "reviewer"
	feedbackImplementer feedbackActorKind = "implementer"
)

type feedbackPermissions uint8

const (
	feedbackCanReport feedbackPermissions = 1 << iota
	feedbackCanReply
	feedbackCanUpdate
	feedbackCanResolve
	feedbackCanReopen
	reviewerFeedbackPermissions    = feedbackCanReport | feedbackCanReply | feedbackCanResolve | feedbackCanReopen
	implementerFeedbackPermissions = feedbackCanReply | feedbackCanUpdate | feedbackCanResolve | feedbackCanReopen
)

// authorizedFeedbackActor contains only transaction-checked facts. submitted
// credentials and implementer assertions never pass through to persistence.
type authorizedFeedbackActor struct {
	kind                               feedbackActorKind
	identityID, displayName, reference string
	permissions                        feedbackPermissions
	expiresAt                          time.Time
}

func (a authorizedFeedbackActor) permits(event FeedbackEventType) bool {
	var required feedbackPermissions
	switch event {
	case FeedbackCreated:
		required = feedbackCanReport
	case FeedbackReply:
		required = feedbackCanReply
	case FeedbackUpdate:
		required = feedbackCanUpdate
	case FeedbackThreadResolved:
		required = feedbackCanResolve
	case FeedbackThreadReopened:
		required = feedbackCanReopen
	default:
		return false
	}
	return a.permissions&required != 0
}

type FeedbackThread struct {
	SchemaVersion     int
	ID                string
	PreviewID         string
	TeamID            string
	GuestID           string
	ServiceID         string
	ServiceRunID      string
	RunNumber         int64
	Service           string
	PagePath          string
	PageTitle         string
	MessageCount      uint64
	LatestEventCursor uint64
	State             FeedbackThreadState
	ReportText        string
	AuthorDisplayName string
	AuthorIdentityID  string
	AuthorVerified    bool
	Anchor            json.RawMessage
	Evidence          json.RawMessage
	SourceAtReport    json.RawMessage
	CreatedAt         time.Time
	StateUpdatedAt    time.Time
}

type FeedbackEvent struct {
	SchemaVersion     int
	Cursor            uint64
	FeedbackID        string
	TeamID            string
	GuestID           string
	Type              FeedbackEventType
	ActorKind         string
	ActorReference    string
	AuthorDisplayName string
	AuthorIdentityID  string
	AuthorVerified    bool
	Text              string
	Evidence          json.RawMessage
	SourceState       json.RawMessage
	At                time.Time
}

type FeedbackThreadPage struct {
	Threads     []FeedbackThread
	NextCursor  string
	EventCursor uint64
}

type FeedbackEventPage struct {
	Events      []FeedbackEvent
	NextCursor  uint64
	EventCursor uint64
}

type CreateFeedbackRequest struct {
	PreviewID         string
	Service           string
	PagePath          string
	PageTitle         string
	ReportText        string
	AuthorDisplayName string
	Anchor            json.RawMessage
	Evidence          json.RawMessage
	SourceAtReport    json.RawMessage
	IdempotencyKey    string
	Actor             FeedbackActor
}

type AppendFeedbackRequest struct {
	FeedbackID     string
	Type           FeedbackEventType
	Text           string
	Evidence       json.RawMessage
	SourceState    json.RawMessage
	IdempotencyKey string
	Actor          FeedbackActor
}

func (d *Database) CreateFeedback(ctx context.Context, auth ServiceHTTPRun, request CreateFeedbackRequest, now time.Time) (result FeedbackThread, retErr error) {
	clock := newAuthorizationClock(now)
	if !auth.valid() {
		return FeedbackThread{}, ErrServiceAccess
	}
	if !opaqueid.Valid(request.PreviewID, opaqueid.PreviewPrefix) || !naming.ValidServiceName(request.Service) ||
		!validFeedbackPath(request.PagePath) || len([]rune(request.PageTitle)) > 256 || !validFeedbackText(request.ReportText, 4000) ||
		request.AuthorDisplayName != "" && !validFeedbackText(request.AuthorDisplayName, 64) ||
		!validFeedbackKey(request.IdempotencyKey) ||
		request.Actor.Kind != "reviewer" {
		return FeedbackThread{}, ErrFeedbackInvalid
	}
	var err error
	request.Anchor, err = normalizeFeedbackAnchor(request.Anchor)
	if err != nil {
		return FeedbackThread{}, err
	}
	request.Evidence, err = normalizeFeedbackEvidence(request.Evidence)
	if err != nil {
		return FeedbackThread{}, err
	}
	request.SourceAtReport, err = normalizeSourceState(request.SourceAtReport)
	if err != nil {
		return FeedbackThread{}, err
	}
	if err := d.requireOpen(); err != nil {
		return FeedbackThread{}, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return FeedbackThread{}, fmt.Errorf("controlstate: create feedback: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "create feedback", &retErr)()
	queries := controlstatedb.New(tx)
	if err = d.lockServiceHTTPRun(ctx, tx, auth, clock.current()); err != nil {
		return FeedbackThread{}, err
	}
	scope, err := queries.FeedbackRunScope(ctx, controlstatedb.FeedbackRunScopeParams{
		ServiceID: auth.Subject.ID, ServiceRunID: auth.RunID, PreviewID: request.PreviewID,
		RunNumber: auth.Number, Now: timestamptz(clock.current()),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return FeedbackThread{}, ErrFeedbackAccess
	}
	if err != nil {
		return FeedbackThread{}, fmt.Errorf("controlstate: resolve report service run: %w", err)
	}
	service, err := queries.GetService(ctx, auth.Subject.ID)
	if err != nil {
		return FeedbackThread{}, err
	}
	request.Actor.ServiceRun = &auth
	actor, err := d.currentReviewer(ctx, tx, service, request.Actor, clock)
	if err != nil {
		return FeedbackThread{}, err
	}
	if !actor.permits(FeedbackCreated) {
		return FeedbackThread{}, ErrFeedbackAccess
	}
	if err := requireFeedbackAuthor(ctx, queries, scope.TeamID.String, scope.GuestID.String, actor); err != nil {
		return FeedbackThread{}, err
	}
	if actor.identityID != "" {
		request.AuthorDisplayName = actor.displayName
	}
	digestInput, err := json.Marshal(struct {
		PreviewID, Service, PagePath, PageTitle, ReportText, AuthorDisplayName, AuthorIdentityID string
		Anchor, Evidence, SourceAtReport                                                         json.RawMessage
	}{request.PreviewID, request.Service, request.PagePath, request.PageTitle, request.ReportText, request.AuthorDisplayName,
		actor.identityID, request.Anchor, request.Evidence, request.SourceAtReport})
	if err != nil {
		return FeedbackThread{}, ErrFeedbackInvalid
	}
	digest := sha256.Sum256(digestInput)
	id, err := opaqueid.New(opaqueid.FeedbackPrefix)
	if err != nil {
		return FeedbackThread{}, fmt.Errorf("controlstate: create feedback ID: %w", err)
	}
	stored, err := queries.CreateFeedbackThread(ctx, controlstatedb.CreateFeedbackThreadParams{
		ID: id, PreviewID: request.PreviewID, TeamID: scope.TeamID,
		ServiceID: scope.ServiceID, ServiceRunID: auth.RunID,
		RunNumber: auth.Number, Service: request.Service, PagePath: request.PagePath, PageTitle: request.PageTitle,
		ReportText: request.ReportText, AuthorDisplayName: nullableText(request.AuthorDisplayName),
		AuthorIdentityID: nullableText(actor.identityID), AuthorVerified: actor.identityID != "",
		Anchor: request.Anchor, Evidence: request.Evidence, SourceAtReport: request.SourceAtReport,
		CreatedAt: timestamptz(now), StateUpdatedAt: timestamptz(now),
		IdempotencyKey: request.IdempotencyKey, RequestDigest: digest[:],
	})
	if err != nil {
		return FeedbackThread{}, fmt.Errorf("controlstate: save feedback report: %w", err)
	}
	if subtle.ConstantTimeCompare(stored.RequestDigest, digest[:]) != 1 || stored.PreviewID != request.PreviewID {
		return FeedbackThread{}, ErrFeedbackIdempotency
	}
	if stored.ID == id {
		cursor, err := queries.ReserveFeedbackEventCursor(ctx)
		if err != nil {
			return FeedbackThread{}, fmt.Errorf("controlstate: reserve feedback cursor: %w", err)
		}
		if _, err := queries.InsertFeedbackEvent(ctx, controlstatedb.InsertFeedbackEventParams{
			Cursor: cursor, FeedbackID: id, TeamID: scope.TeamID, EventType: string(FeedbackCreated),
			ActorKind: string(actor.kind), ActorReference: actor.reference,
			IdempotencyKey: request.IdempotencyKey, RequestDigest: digest[:], OccurredAt: timestamptz(now),
			AuthorIdentityID: nullableText(actor.identityID), AuthorDisplayName: nullableText(actor.displayName),
			AuthorVerified: actor.identityID != "",
		}); err != nil {
			return FeedbackThread{}, fmt.Errorf("controlstate: record feedback creation: %w", err)
		}
		if err := queries.RecordFeedbackActivity(ctx, controlstatedb.RecordFeedbackActivityParams{FeedbackID: id, EventCursor: cursor, AddMessage: false}); err != nil {
			return FeedbackThread{}, err
		}
		stored.LatestEventCursor = cursor
	}
	if err := commitFeedback(ctx, tx, clock, actor.expiresAt); err != nil {
		return FeedbackThread{}, fmt.Errorf("controlstate: commit feedback report: %w", err)
	}
	return feedbackThreadFromRow(stored), nil
}

func (d *Database) AppendFeedback(ctx context.Context, request AppendFeedbackRequest, now time.Time) (result FeedbackEvent, retErr error) {
	clock := newAuthorizationClock(now)
	if !opaqueid.Valid(request.FeedbackID, opaqueid.FeedbackPrefix) || !validFeedbackKey(request.IdempotencyKey) ||
		!validFeedbackEventPayload(request) {
		return FeedbackEvent{}, ErrFeedbackInvalid
	}
	var err error
	if len(request.Evidence) != 0 {
		request.Evidence, err = normalizeFeedbackEvidence(request.Evidence)
		if err != nil {
			return FeedbackEvent{}, err
		}
	}
	if len(request.SourceState) != 0 {
		request.SourceState, err = normalizeSourceState(request.SourceState)
		if err != nil {
			return FeedbackEvent{}, err
		}
	}
	if err := d.requireOpen(); err != nil {
		return FeedbackEvent{}, err
	}
	digestInput, err := json.Marshal(struct {
		Type        FeedbackEventType
		Text        string
		Evidence    json.RawMessage
		SourceState json.RawMessage
	}{request.Type, request.Text, request.Evidence, request.SourceState})
	if err != nil {
		return FeedbackEvent{}, ErrFeedbackInvalid
	}
	digest := sha256.Sum256(digestInput)
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return FeedbackEvent{}, fmt.Errorf("controlstate: append feedback: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "append feedback", &retErr)()
	queries := controlstatedb.New(tx)
	candidate, err := queries.GetFeedbackThread(ctx, request.FeedbackID)
	if errors.Is(err, pgx.ErrNoRows) {
		return FeedbackEvent{}, ErrFeedbackNotFound
	}
	if err != nil {
		return FeedbackEvent{}, err
	}
	var actor authorizedFeedbackActor
	if request.Actor.Kind == "reviewer" {
		if request.Actor.ServiceRun == nil || request.Actor.ServiceRun.Subject.ID != candidate.ServiceID {
			return FeedbackEvent{}, ErrFeedbackAccess
		}
		if err = d.lockServiceHTTPRun(ctx, tx, *request.Actor.ServiceRun, clock.current()); err != nil {
			return FeedbackEvent{}, err
		}
		if _, err := queries.FeedbackRunScope(ctx, controlstatedb.FeedbackRunScopeParams{
			ServiceID: candidate.ServiceID, ServiceRunID: request.Actor.ServiceRun.RunID, PreviewID: candidate.PreviewID,
			RunNumber: request.Actor.ServiceRun.Number, Now: timestamptz(clock.current()),
		}); err != nil {
			return FeedbackEvent{}, publisherLookupError(err, ErrFeedbackAccess)
		}
		service, err := queries.GetService(ctx, candidate.ServiceID)
		if err != nil {
			return FeedbackEvent{}, err
		}
		actor, err = d.currentReviewer(ctx, tx, service, request.Actor, clock)
		if err != nil {
			return FeedbackEvent{}, err
		}
	} else {
		actor, err = d.authorizeImplementerFeedbackActor(ctx, tx, candidate, request.Actor, clock.current())
		if err != nil {
			return FeedbackEvent{}, err
		}
	}
	if err := requireFeedbackAuthor(ctx, queries, candidate.TeamID.String, candidate.GuestID.String, actor); err != nil {
		return FeedbackEvent{}, err
	}
	thread, err := queries.LockFeedbackThread(ctx, request.FeedbackID)
	if errors.Is(err, pgx.ErrNoRows) {
		return FeedbackEvent{}, ErrFeedbackNotFound
	}
	if err != nil {
		return FeedbackEvent{}, fmt.Errorf("controlstate: lock feedback thread: %w", err)
	}
	existing, err := queries.GetFeedbackEventByActorKey(ctx, controlstatedb.GetFeedbackEventByActorKeyParams{
		FeedbackID: thread.ID, ActorKind: string(actor.kind), ActorReference: actor.reference,
		IdempotencyKey: request.IdempotencyKey,
	})
	if err == nil {
		if !actor.expiresAt.IsZero() && !actor.expiresAt.After(clock.current()) {
			return FeedbackEvent{}, ErrFeedbackAccess
		}
		if subtle.ConstantTimeCompare(existing.RequestDigest, digest[:]) != 1 {
			return FeedbackEvent{}, ErrFeedbackIdempotency
		}
		return feedbackEventFromRow(existing), nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return FeedbackEvent{}, fmt.Errorf("controlstate: read feedback retry: %w", err)
	}
	if !actor.permits(request.Type) {
		return FeedbackEvent{}, ErrFeedbackState
	}
	next, err := FeedbackThreadState(thread.State).transition(request.Type)
	if err != nil {
		return FeedbackEvent{}, err
	}
	cursor, err := queries.ReserveFeedbackEventCursor(ctx)
	if err != nil {
		return FeedbackEvent{}, fmt.Errorf("controlstate: reserve feedback cursor: %w", err)
	}
	stored, err := queries.InsertFeedbackEvent(ctx, controlstatedb.InsertFeedbackEventParams{
		Cursor: cursor, FeedbackID: thread.ID, TeamID: thread.TeamID,
		EventType: string(request.Type), ActorKind: string(actor.kind), ActorReference: actor.reference,
		IdempotencyKey: request.IdempotencyKey, RequestDigest: digest[:], Text: nullableText(request.Text),
		Evidence: request.Evidence, SourceState: request.SourceState, OccurredAt: timestamptz(now),
		AuthorIdentityID: nullableText(verifiedFeedbackAuthorID(actor)), AuthorDisplayName: nullableText(actor.displayName),
		AuthorVerified: actor.identityID != "" && actor.displayName != "",
	})
	if err != nil {
		return FeedbackEvent{}, fmt.Errorf("controlstate: save feedback event: %w", err)
	}
	if err := queries.RecordFeedbackActivity(ctx, controlstatedb.RecordFeedbackActivityParams{FeedbackID: thread.ID, EventCursor: cursor, AddMessage: request.Type == FeedbackReply || request.Type == FeedbackUpdate}); err != nil {
		return FeedbackEvent{}, err
	}
	if next != FeedbackThreadState(thread.State) {
		if _, err := queries.UpdateFeedbackThreadState(ctx, controlstatedb.UpdateFeedbackThreadStateParams{
			NextState: string(next), UpdatedAt: timestamptz(now), FeedbackID: thread.ID,
			ExpectedState: thread.State,
		}); errors.Is(err, pgx.ErrNoRows) {
			return FeedbackEvent{}, ErrFeedbackState
		} else if err != nil {
			return FeedbackEvent{}, fmt.Errorf("controlstate: update feedback state: %w", err)
		}
	}
	if err := commitFeedback(ctx, tx, clock, actor.expiresAt); err != nil {
		return FeedbackEvent{}, fmt.Errorf("controlstate: commit feedback event: %w", err)
	}
	return feedbackEventFromRow(stored), nil
}

func verifiedFeedbackAuthorID(actor authorizedFeedbackActor) string {
	if actor.displayName == "" {
		return ""
	}
	return actor.identityID
}

// management reads include retained service tombstones. the same stored
// membership and ownership predicate used by service mutations authorizes them.
func (d *Database) AuthorizeFeedbackService(ctx context.Context, service, identity string, now time.Time) (retErr error) {
	tx, err := d.beginServiceAccess(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "authorize feedback management", &retErr)()
	if err := authorizeFeedbackService(ctx, tx, service, identity, now); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func authorizeFeedbackService(ctx context.Context, tx pgx.Tx, service, identity string, now time.Time) error {
	q := controlstatedb.New(tx)
	candidate, err := q.GetFeedbackService(ctx, service)
	if err != nil {
		return publisherLookupError(err, ErrFeedbackAccess)
	}
	if candidate.GuestID.Valid || !candidate.TeamID.Valid {
		return ErrFeedbackAccess
	}
	if _, err = q.LockLocalTeamForMutation(ctx, candidate.TeamID.String); err != nil {
		return publisherLookupError(err, ErrFeedbackAccess)
	}
	member, err := serviceMembershipForActor(ctx, tx, candidate.TeamID.String, identity, now)
	if err != nil {
		return err
	}
	row, err := q.LockService(ctx, service)
	if err != nil {
		return publisherLookupError(err, ErrFeedbackAccess)
	}
	if row.TeamID != candidate.TeamID {
		return ErrFeedbackAccess
	}
	return requireStoredServiceManagement(ctx, tx, row, member, true)
}

func (d *Database) authorizeImplementerFeedbackActor(ctx context.Context, tx pgx.Tx, thread controlstatedb.ControlFeedbackThread, actor FeedbackActor, now time.Time) (authorizedFeedbackActor, error) {
	if actor.Kind != "implementer" || actor.IdentityID == "" {
		return authorizedFeedbackActor{}, ErrFeedbackAccess
	}
	if err := authorizeFeedbackService(ctx, tx, thread.ServiceID, actor.IdentityID, now); err != nil {
		if errors.Is(err, ErrServiceAccess) || errors.Is(err, ErrAuthorityAccess) {
			err = errors.Join(ErrFeedbackAccess, err)
		}
		return authorizedFeedbackActor{}, err
	}
	queries := controlstatedb.New(tx)
	identity, err := queries.LockVisitorIdentity(ctx, actor.IdentityID)
	if errors.Is(err, pgx.ErrNoRows) {
		return authorizedFeedbackActor{}, ErrVisitorSignIn
	}
	if err != nil {
		return authorizedFeedbackActor{}, err
	}
	return authorizedFeedbackActor{kind: feedbackImplementer, identityID: identity.ID, displayName: identity.DisplayName, reference: actor.IdentityID, permissions: implementerFeedbackPermissions}, nil
}

func (d *Database) ReviewerFeedbackScope(ctx context.Context, auth ServiceHTTPRun, previewID string, actor FeedbackActor, now time.Time) (teamID, serviceID string, retErr error) {
	clock := newAuthorizationClock(now)
	if !auth.valid() {
		return "", "", ErrServiceAccess
	}
	if !opaqueid.Valid(previewID, opaqueid.PreviewPrefix) {
		return "", "", ErrFeedbackInvalid
	}
	if err := d.requireOpen(); err != nil {
		return "", "", err
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return "", "", err
	}
	defer rollback(ctx, tx, "read current reviewer scope", &retErr)()
	queries := controlstatedb.New(tx)
	if err = d.lockServiceHTTPRun(ctx, tx, auth, clock.current()); err != nil {
		return "", "", err
	}
	scope, err := queries.FeedbackRunScope(ctx, controlstatedb.FeedbackRunScopeParams{
		ServiceID: auth.Subject.ID, ServiceRunID: auth.RunID, PreviewID: previewID,
		RunNumber: auth.Number, Now: timestamptz(clock.current()),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", ErrFeedbackAccess
	}
	if err != nil {
		return "", "", fmt.Errorf("controlstate: read reviewer preview: %w", err)
	}
	if scope.ServiceID != auth.Subject.ID {
		return "", "", ErrFeedbackAccess
	}
	service, err := queries.GetService(ctx, auth.Subject.ID)
	if err != nil {
		return "", "", err
	}
	actor.ServiceRun = &auth
	checked, err := d.currentReviewer(ctx, tx, service, actor, clock)
	if err != nil {
		return "", "", err
	}
	if err := commitFeedback(ctx, tx, clock, checked.expiresAt); err != nil {
		return "", "", err
	}
	return scope.TeamID.String, scope.ServiceID, nil
}

func (state FeedbackThreadState) transition(event FeedbackEventType) (FeedbackThreadState, error) {
	switch event {
	case FeedbackReply, FeedbackUpdate:
		if state == FeedbackOpen {
			return state, nil
		}
	case FeedbackThreadReopened:
		if state == FeedbackResolved {
			return FeedbackOpen, nil
		}
	case FeedbackThreadResolved:
		if state == FeedbackOpen {
			return FeedbackResolved, nil
		}
	}
	return "", ErrFeedbackState
}

func validFeedbackEventPayload(request AppendFeedbackRequest) bool {
	if request.Type == FeedbackCreated || request.Actor.Kind != "reviewer" && request.Actor.Kind != "implementer" ||
		request.Text != "" && !validFeedbackText(request.Text, 4000) ||
		len(request.Evidence) > 0 && !validFeedbackJSON(request.Evidence, 16384) ||
		len(request.SourceState) > 0 && !validFeedbackJSON(request.SourceState, 16384) {
		return false
	}
	if request.Type == FeedbackReply || request.Type == FeedbackUpdate {
		if request.Text == "" {
			return false
		}
	}
	if request.Type == FeedbackUpdate {
		return request.Actor.Kind == "implementer" && len(request.SourceState) > 0
	}
	return len(request.SourceState) == 0 && (request.Type == FeedbackReply ||
		request.Type == FeedbackThreadResolved || request.Type == FeedbackThreadReopened)
}

func validFeedbackPath(value string) bool {
	if len(value) < 1 || len(value) > 2048 || value[0] != '/' || strings.ContainsAny(value, "\x00\r\n#") {
		return false
	}
	parsed, err := url.ParseRequestURI(value)
	return err == nil && !parsed.IsAbs() && parsed.Host == "" && strings.HasPrefix(parsed.Path, "/")
}

func validFeedbackKey(value string) bool {
	return len(value) >= 1 && len(value) <= 128 && strings.TrimSpace(value) == value
}

func validFeedbackText(value string, maxLength int) bool {
	return strings.TrimSpace(value) != "" && len([]rune(value)) <= maxLength && !strings.ContainsRune(value, '\x00')
}

func validFeedbackJSON(value json.RawMessage, maxBytes int) bool {
	return len(value) >= 2 && len(value) <= maxBytes && value[0] == '{' && json.Valid(value)
}

func feedbackThreadFromRow(row controlstatedb.ControlFeedbackThread) FeedbackThread {
	return FeedbackThread{
		PageTitle: row.PageTitle, MessageCount: uint64(row.MessageCount), LatestEventCursor: uint64(row.LatestEventCursor),
		ID: row.ID, PreviewID: row.PreviewID, TeamID: row.TeamID.String, GuestID: row.GuestID.String, ServiceID: row.ServiceID,
		ServiceRunID: row.ServiceRunID, RunNumber: row.RunNumber,
		Service: row.ServiceName, PagePath: row.PagePath, State: FeedbackThreadState(row.State),
		ReportText: row.ReportText, AuthorDisplayName: row.AuthorDisplayName.String,
		AuthorIdentityID: row.AuthorIdentityID.String, AuthorVerified: row.AuthorVerified,
		SchemaVersion: int(row.SchemaVersion), Anchor: slices.Clone(row.Pin), Evidence: slices.Clone(row.Evidence),
		SourceAtReport: slices.Clone(row.ReportSourceState),
		CreatedAt:      row.CreatedAt.Time, StateUpdatedAt: row.StateUpdatedAt.Time,
	}
}

func feedbackEventFromRow(row controlstatedb.ControlFeedbackEvent) FeedbackEvent {
	return FeedbackEvent{
		SchemaVersion: int(row.SchemaVersion),
		Cursor:        uint64(row.Cursor), FeedbackID: row.FeedbackID, TeamID: row.TeamID.String, GuestID: row.GuestID.String,
		Type: FeedbackEventType(row.EventType), ActorKind: row.ActorKind, ActorReference: row.ActorReference,
		AuthorIdentityID: row.AuthorIdentityID.String, AuthorDisplayName: row.AuthorDisplayName.String, AuthorVerified: row.AuthorVerified,
		Text: row.Text.String, Evidence: slices.Clone(row.Evidence), SourceState: slices.Clone(row.SourceState),
		At: row.OccurredAt.Time,
	}
}
