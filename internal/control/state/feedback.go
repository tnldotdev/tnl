package state

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

var (
	ErrFeedbackInvalid = errors.New("controlstate: feedback request is invalid")
	ErrFeedbackAccess  = errors.New("controlstate: feedback access denied")
)

type FeedbackActor struct {
	SourceIP                      string
	ServiceRun                    *ServiceHTTPRun
	Kind, IdentityID, DisplayName string
	BrowserCookieSecret           []byte
	TeamMember                    bool
	ShareID                       string
	CookieSecret, ShareSecret     []byte
	VisitAllowed                  bool
	VisitProof                    FeedbackVisitProof
}

type feedbackActorKind string

const (
	feedbackReviewer    feedbackActorKind = "reviewer"
	feedbackImplementer feedbackActorKind = "implementer"
)

type authorizedFeedbackActor struct {
	kind                               feedbackActorKind
	identityID, displayName, reference string
	expiresAt                          time.Time
}

// each decision is used for one local operation, never cached as preview access.
// it contains no report, path, evidence, source state, thread ID, or reply.
func feedbackDecision(preview, service, run string, number int64, operation string, actor authorizedFeedbackActor, now time.Time) (controlv1.FeedbackAuthorization, error) {
	until := now.Add(5 * time.Second)
	if !actor.expiresAt.IsZero() {
		until = minTime(until, actor.expiresAt)
	}
	if !until.After(now) {
		return controlv1.FeedbackAuthorization{}, ErrFeedbackAccess
	}
	author := controlv1.FeedbackAuthor{DisplayName: "Visitor", Verified: false}
	if actor.identityID != "" {
		author = controlv1.FeedbackAuthor{IdentityId: &actor.identityID, DisplayName: actor.displayName, Verified: true}
	}
	return controlv1.FeedbackAuthorization{
		PreviewId: preview, ServiceId: service, ServiceRunId: run, RunNumber: number,
		Operation: controlv1.FeedbackOperation(operation), Actor: string(actor.kind),
		Author:    author,
		ExpiresAt: until,
	}, nil
}

func validFeedbackOperation(operation string, reviewer bool) bool {
	switch operation {
	case "read", "reply", "thread.resolved", "thread.reopened":
		return true
	case "report":
		return reviewer
	case "update", "delete":
		return !reviewer
	}
	return false
}

func (d *Database) AuthorizeReviewerFeedback(ctx context.Context, auth ServiceHTTPRun, preview, operation string, actor FeedbackActor, now time.Time) (result controlv1.FeedbackAuthorization, retErr error) {
	clock := newAuthorizationClock(now)
	if !auth.valid() || !opaqueid.Valid(preview, opaqueid.PreviewPrefix) || !validFeedbackOperation(operation, true) {
		return result, ErrFeedbackInvalid
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "authorize local reviewer feedback", &retErr)()
	q := controlstatedb.New(tx)
	run, err := d.observeServiceHTTPRun(ctx, tx, auth, clock)
	if err != nil {
		return result, err
	}
	scope, err := q.FeedbackRunScope(ctx, controlstatedb.FeedbackRunScopeParams{ServiceID: auth.Subject.ID, ServiceRunID: auth.RunID, PreviewID: preview, RunNumber: auth.Number, Now: timestamptz(clock.current())})
	if err != nil {
		return result, publisherLookupError(err, ErrFeedbackAccess)
	}
	service, err := q.GetService(ctx, auth.Subject.ID)
	if err != nil {
		return result, err
	}
	actor.ServiceRun = &auth
	checked, err := d.currentReviewer(ctx, tx, service, run, actor, clock)
	if err != nil {
		return result, err
	}
	// reads preserve visitor access without requiring feedback author eligibility.
	// writes always derive the author from the checked browser sign-in.
	if operation != "read" {
		if err = requireFeedbackAuthor(ctx, q, scope.TeamID.String, scope.GuestID.String, checked); err != nil {
			return result, err
		}
	}
	result, err = feedbackDecision(preview, service.ID, auth.RunID, auth.Number, operation, checked, clock.current())
	if err != nil {
		return result, err
	}
	if scope.DemoServiceRunID.Valid {
		if scope.DemoServiceRunID.String != auth.RunID || !service.ExpiresAt.Valid {
			return controlv1.FeedbackAuthorization{}, ErrFeedbackAccess
		}
		deadline := service.ExpiresAt.Time
		if service.GuestID.Valid {
			serving, err := q.GuestServiceServingDeadline(ctx, controlstatedb.GuestServiceServingDeadlineParams{ServiceID: service.ID, Now: timestamptz(clock.current())})
			if err != nil {
				return controlv1.FeedbackAuthorization{}, err
			}
			if !serving.Valid {
				return controlv1.FeedbackAuthorization{}, ErrFeedbackAccess
			}
			deadline = minTime(deadline, serving.Time)
		}
		result.ContentExpiresAt = &deadline
	}
	if err = commitFeedback(ctx, tx, clock, result.ExpiresAt); err != nil {
		return controlv1.FeedbackAuthorization{}, err
	}
	return result, nil
}

func (d *Database) AuthorizeImplementerFeedback(ctx context.Context, identity, service, preview, operation string, now time.Time) (result controlv1.FeedbackAuthorization, retErr error) {
	clock := newAuthorizationClock(now)
	if identity == "" || !opaqueid.Valid(preview, opaqueid.PreviewPrefix) || !validFeedbackOperation(operation, false) {
		return result, ErrFeedbackInvalid
	}
	tx, err := d.beginServiceAccess(ctx, pgx.TxOptions{})
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "authorize local implementer feedback", &retErr)()
	if err = authorizeFeedbackService(ctx, tx, service, identity, clock); err != nil {
		return result, err
	}
	q := controlstatedb.New(tx)
	scope, err := q.FeedbackServiceScope(ctx, controlstatedb.FeedbackServiceScopeParams{ServiceID: service, PreviewID: preview})
	if err != nil {
		return result, publisherLookupError(err, ErrFeedbackAccess)
	}
	person, err := q.LockVisitorIdentity(ctx, identity)
	if err != nil {
		return result, publisherLookupError(err, ErrVisitorSignIn)
	}
	checked := authorizedFeedbackActor{kind: feedbackImplementer, identityID: person.ID, displayName: person.DisplayName, reference: person.ID}
	if operation != "read" && operation != "delete" {
		if err = requireFeedbackAuthor(ctx, q, scope.TeamID.String, scope.GuestID.String, checked); err != nil {
			return result, err
		}
	}
	// the control principal's parent deadline is checked again under the same
	// transaction rather than turning an HTTP authentication into renewed access.
	principal, ok := ctx.Value(controlPrincipalKey{}).(ControlPrincipal)
	if !ok || principal.IdentityID != identity {
		return result, ErrFeedbackAccess
	}
	until, err := currentVisitorParentSession(ctx, tx, principal, clock.current())
	if err != nil {
		return result, err
	}
	checked.expiresAt = until
	result, err = feedbackDecision(preview, service, "", 0, operation, checked, clock.current())
	if err != nil {
		return result, err
	}
	if err = commitFeedback(ctx, tx, clock, result.ExpiresAt); err != nil {
		return controlv1.FeedbackAuthorization{}, err
	}
	return result, nil
}

func authorizeFeedbackService(ctx context.Context, tx pgx.Tx, service, identity string, clock authorizationClock) error {
	q := controlstatedb.New(tx)
	candidate, err := q.GetFeedbackService(ctx, service)
	if err != nil {
		return publisherLookupError(err, ErrFeedbackAccess)
	}
	if candidate.GuestID.Valid || !candidate.TeamID.Valid {
		return ErrFeedbackAccess
	}
	if _, err = q.LockLocalTeamForSession(ctx, candidate.TeamID.String); err != nil {
		return publisherLookupError(err, ErrFeedbackAccess)
	}
	member, err := serviceMembershipUnderTeamGuard(ctx, tx, candidate.TeamID.String, identity, clock)
	if err != nil {
		return err
	}
	if err := queueRunReader(ctx, tx, service); err != nil {
		return err
	}
	row, err := q.ObservePublisherEnrollmentService(ctx, service)
	if err != nil {
		return publisherLookupError(err, ErrFeedbackAccess)
	}
	if row.TeamID != candidate.TeamID {
		return ErrFeedbackAccess
	}
	return requireStoredServiceManagement(ctx, tx, row, member, true)
}
