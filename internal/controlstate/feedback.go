package controlstate

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
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

var (
	ErrFeedbackNotFound    = errors.New("controlstate: feedback thread not found")
	ErrFeedbackInvalid     = errors.New("controlstate: feedback request is invalid")
	ErrFeedbackAccess      = errors.New("controlstate: feedback access denied")
	ErrFeedbackIdempotency = errors.New("controlstate: feedback idempotency conflict")
	ErrFeedbackState       = errors.New("controlstate: feedback state changed")
)

type FeedbackThreadState string

// feedback authorization includes retained public URL tombstones, without
// exposing them through ordinary public URL reads or publishing operations.
func (d *Database) GetPublicURLForFeedbackAuthorization(ctx context.Context, id string) (PublicURL, error) {
	if err := d.requireOpen(); err != nil {
		return PublicURL{}, err
	}
	row, err := controlstatedb.New(d.pool).GetFeedbackPublicURL(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return PublicURL{}, ErrPublicURLNotFound
	}
	if err != nil {
		return PublicURL{}, err
	}
	return publicURLFromModel(row, ""), nil
}

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
	Kind                     string
	IdentityID               string
	ShareID                  string
	CookieSecret             []byte
	AllowedIP                bool
	AuthorityIssuer          string
	PolicyRevision           uint64
	ExpectedMutationRevision uint64
}

type FeedbackThread struct {
	SchemaVersion     int
	ID                string
	PreviewID         string
	TeamID            string
	PublicURLID       string
	PublishRunID      string
	PublishRunNumber  uint64
	Service           string
	PagePath          string
	PageTitle         string
	MessageCount      uint64
	LatestEventCursor uint64
	State             FeedbackThreadState
	ReportText        string
	AuthorDisplayName string
	Anchor            json.RawMessage
	Evidence          json.RawMessage
	SourceAtReport    json.RawMessage
	CreatedAt         time.Time
	StateUpdatedAt    time.Time
}

type FeedbackEvent struct {
	SchemaVersion  int
	Cursor         uint64
	FeedbackID     string
	TeamID         string
	Type           FeedbackEventType
	ActorKind      string
	ActorReference string
	Text           string
	Evidence       json.RawMessage
	SourceState    json.RawMessage
	At             time.Time
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

func (d *Database) CreateFeedback(ctx context.Context, auth PublishRunAuthentication, request CreateFeedbackRequest, now time.Time) (result FeedbackThread, retErr error) {
	if err := validatePublishRunAuthentication(auth); err != nil {
		return FeedbackThread{}, err
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
	digestInput, err := json.Marshal(struct {
		PreviewID, Service, PagePath, PageTitle, ReportText, AuthorDisplayName string
		Anchor, Evidence, SourceAtReport                                       json.RawMessage
	}{request.PreviewID, request.Service, request.PagePath, request.PageTitle, request.ReportText, request.AuthorDisplayName,
		request.Anchor, request.Evidence, request.SourceAtReport})
	if err != nil {
		return FeedbackThread{}, ErrFeedbackInvalid
	}
	digest := sha256.Sum256(digestInput)
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return FeedbackThread{}, fmt.Errorf("controlstate: create feedback: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "create feedback", &retErr)()
	queries := controlstatedb.New(tx)
	// follow public URL -> publish run -> thread order during demo cleanup.
	if _, err := queries.LockPublicURLForRun(ctx, auth.PublicURLID); err != nil {
		return FeedbackThread{}, ErrFeedbackAccess
	}
	scope, err := queries.FeedbackRunScope(ctx, controlstatedb.FeedbackRunScopeParams{
		PublishRunID: auth.PublishRunID, PreviewID: request.PreviewID,
		PublishRunNumber: int64(auth.PublishRunNumber), Now: timestamptz(now),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return FeedbackThread{}, ErrFeedbackAccess
	}
	if err != nil {
		return FeedbackThread{}, fmt.Errorf("controlstate: resolve report publish run: %w", err)
	}
	actorRef, err := reviewerReference(ctx, queries, scope.PublicURLID, request.Actor, now)
	if err != nil {
		return FeedbackThread{}, err
	}
	id, err := opaqueid.New(opaqueid.FeedbackPrefix)
	if err != nil {
		return FeedbackThread{}, fmt.Errorf("controlstate: create feedback ID: %w", err)
	}
	stored, err := queries.CreateFeedbackThread(ctx, controlstatedb.CreateFeedbackThreadParams{
		ID: id, PreviewID: request.PreviewID, TeamID: scope.TeamID,
		PublicURLID: scope.PublicURLID, PublishRunID: auth.PublishRunID,
		PublishRunNumber: int64(auth.PublishRunNumber), Service: request.Service, PagePath: request.PagePath, PageTitle: request.PageTitle,
		ReportText: request.ReportText, AuthorDisplayName: nullableText(request.AuthorDisplayName),
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
			ActorKind: "reviewer", ActorReference: actorRef,
			IdempotencyKey: request.IdempotencyKey, RequestDigest: digest[:], OccurredAt: timestamptz(now),
		}); err != nil {
			return FeedbackThread{}, fmt.Errorf("controlstate: record feedback creation: %w", err)
		}
		if err := queries.RecordFeedbackActivity(ctx, controlstatedb.RecordFeedbackActivityParams{FeedbackID: id, EventCursor: cursor, AddMessage: false}); err != nil {
			return FeedbackThread{}, err
		}
		stored.LatestEventCursor = cursor
	}
	if err := tx.Commit(ctx); err != nil {
		return FeedbackThread{}, fmt.Errorf("controlstate: commit feedback report: %w", err)
	}
	return feedbackThreadFromRow(stored), nil
}

func (d *Database) AppendFeedback(ctx context.Context, request AppendFeedbackRequest, now time.Time) (result FeedbackEvent, retErr error) {
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
	if request.Actor.Kind == "reviewer" {
		if _, err := queries.LockPublicURLForRun(ctx, candidate.PublicURLID); err != nil {
			return FeedbackEvent{}, ErrFeedbackAccess
		}
	}
	actorRef, err := d.authorizeFeedbackActor(ctx, queries, candidate, request.Actor, now)
	if err != nil {
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
		FeedbackID: thread.ID, ActorKind: request.Actor.Kind, ActorReference: actorRef,
		IdempotencyKey: request.IdempotencyKey,
	})
	if err == nil {
		if subtle.ConstantTimeCompare(existing.RequestDigest, digest[:]) != 1 {
			return FeedbackEvent{}, ErrFeedbackIdempotency
		}
		return feedbackEventFromRow(existing), nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return FeedbackEvent{}, fmt.Errorf("controlstate: read feedback retry: %w", err)
	}
	next, err := nextFeedbackState(FeedbackThreadState(thread.State), request.Type, request.Actor.Kind)
	if err != nil {
		return FeedbackEvent{}, err
	}
	cursor, err := queries.ReserveFeedbackEventCursor(ctx)
	if err != nil {
		return FeedbackEvent{}, fmt.Errorf("controlstate: reserve feedback cursor: %w", err)
	}
	stored, err := queries.InsertFeedbackEvent(ctx, controlstatedb.InsertFeedbackEventParams{
		Cursor: cursor, FeedbackID: thread.ID, TeamID: thread.TeamID,
		EventType: string(request.Type), ActorKind: request.Actor.Kind, ActorReference: actorRef,
		IdempotencyKey: request.IdempotencyKey, RequestDigest: digest[:], Text: nullableText(request.Text),
		Evidence: request.Evidence, SourceState: request.SourceState, OccurredAt: timestamptz(now),
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
	if err := tx.Commit(ctx); err != nil {
		return FeedbackEvent{}, fmt.Errorf("controlstate: commit feedback event: %w", err)
	}
	return feedbackEventFromRow(stored), nil
}

func (d *Database) authorizeFeedbackActor(ctx context.Context, queries *controlstatedb.Queries, thread controlstatedb.ControlFeedbackThread, actor FeedbackActor, now time.Time) (string, error) {
	if actor.Kind == "reviewer" {
		return reviewerReference(ctx, queries, thread.PublicURLID, actor, now)
	}
	if actor.Kind != "implementer" || actor.IdentityID == "" || actor.PolicyRevision == 0 || actor.ExpectedMutationRevision == 0 {
		return "", ErrFeedbackAccess
	}
	revision := positive(actor.PolicyRevision)
	if actor.AuthorityIssuer == "" {
		if _, err := queries.LockLocalTeamForMutation(ctx, thread.TeamID); err != nil {
			return "", ErrFeedbackAccess
		}
	} else if _, err := queries.ObserveAuthorityRevision(ctx, controlstatedb.ObserveAuthorityRevisionParams{
		Issuer: actor.AuthorityIssuer, TeamID: thread.TeamID,
		PolicyRevision: revision, UpdatedAt: timestamptz(now),
	}); err != nil {
		return "", ErrFeedbackAccess
	}
	route, err := queries.LockPublicURLForRun(ctx, thread.PublicURLID)
	if err != nil || route.TeamID != thread.TeamID ||
		route.MutationRevision != int64(actor.ExpectedMutationRevision) || route.PolicyRevision > revision {
		return "", ErrFeedbackAccess
	}
	if actor.AuthorityIssuer == "" {
		membership, err := queries.GetActivePublishRunMembership(ctx, controlstatedb.GetActivePublishRunMembershipParams{
			TeamID: thread.TeamID, IdentityID: actor.IdentityID,
		})
		if err != nil || membership.PolicyRevision != revision ||
			route.PublicURLScope == string(PublicURLScopeMember) && (!route.MembershipID.Valid || membership.ID != route.MembershipID.String) ||
			route.PublicURLScope == string(PublicURLScopeShared) && membership.Role != "admin" && membership.Role != "owner" {
			return "", ErrFeedbackAccess
		}
	}
	return actor.IdentityID, nil
}

func reviewerReference(ctx context.Context, queries *controlstatedb.Queries, publicURLID string, actor FeedbackActor, now time.Time) (string, error) {
	if actor.Kind != "reviewer" {
		return "", ErrFeedbackAccess
	}
	if actor.AllowedIP {
		return "allowed_ip", nil
	}
	if !opaqueid.Valid(actor.ShareID, opaqueid.SharePrefix) || len(actor.CookieSecret) != 32 {
		return "", ErrFeedbackAccess
	}
	digest := sha256.Sum256(actor.CookieSecret)
	if _, err := queries.ReviewerShareCookieValid(ctx, controlstatedb.ReviewerShareCookieValidParams{
		ShareID: actor.ShareID, PublicURLID: publicURLID,
		TokenDigest: digest[:], Now: timestamptz(now),
	}); err != nil {
		return "", ErrFeedbackAccess
	}
	return actor.ShareID, nil
}

func (d *Database) ReviewerFeedbackScope(ctx context.Context, auth PublishRunAuthentication, previewID string, actor FeedbackActor, now time.Time) (string, string, error) {
	if err := validatePublishRunAuthentication(auth); err != nil {
		return "", "", err
	}
	if !opaqueid.Valid(previewID, opaqueid.PreviewPrefix) {
		return "", "", ErrFeedbackInvalid
	}
	if err := d.requireOpen(); err != nil {
		return "", "", err
	}
	queries := controlstatedb.New(d.pool)
	scope, err := queries.FeedbackRunScope(ctx, controlstatedb.FeedbackRunScopeParams{
		PublishRunID: auth.PublishRunID, PreviewID: previewID,
		PublishRunNumber: int64(auth.PublishRunNumber), Now: timestamptz(now),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", ErrFeedbackAccess
	}
	if err != nil {
		return "", "", fmt.Errorf("controlstate: read reviewer preview: %w", err)
	}
	if _, err := reviewerReference(ctx, queries, scope.PublicURLID, actor, now); err != nil {
		return "", "", err
	}
	return scope.TeamID, scope.PublicURLID, nil
}

func nextFeedbackState(state FeedbackThreadState, event FeedbackEventType, actorKind string) (FeedbackThreadState, error) {
	switch event {
	case FeedbackReply:
		if state == FeedbackOpen {
			return state, nil
		}
	case FeedbackUpdate:
		if actorKind == "implementer" && state == FeedbackOpen {
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
		ID: row.ID, PreviewID: row.PreviewID, TeamID: row.TeamID, PublicURLID: row.PublicURLID,
		PublishRunID: row.PublishRunID, PublishRunNumber: uint64(row.PublishRunNumber),
		Service: row.Service, PagePath: row.PagePath, State: FeedbackThreadState(row.State),
		ReportText: row.ReportText, AuthorDisplayName: row.AuthorDisplayName.String,
		SchemaVersion: int(row.SchemaVersion), Anchor: slices.Clone(row.Anchor), Evidence: slices.Clone(row.Evidence),
		SourceAtReport: slices.Clone(row.SourceAtReport),
		CreatedAt:      row.CreatedAt.Time, StateUpdatedAt: row.StateUpdatedAt.Time,
	}
}

func feedbackEventFromRow(row controlstatedb.ControlFeedbackEvent) FeedbackEvent {
	return FeedbackEvent{
		SchemaVersion: int(row.SchemaVersion),
		Cursor:        uint64(row.Cursor), FeedbackID: row.FeedbackID, TeamID: row.TeamID,
		Type: FeedbackEventType(row.EventType), ActorKind: row.ActorKind, ActorReference: row.ActorReference,
		Text: row.Text.String, Evidence: slices.Clone(row.Evidence), SourceState: slices.Clone(row.SourceState),
		At: row.OccurredAt.Time,
	}
}
