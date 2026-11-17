package state

import (
	"context"
	"encoding/base64"
	"errors"
	"net/netip"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
)

// feedback may combine a verified browser author with service-scoped share
// permission. submitted identity and visit booleans are never authority.
func (d *Database) currentReviewer(ctx context.Context, tx pgx.Tx, service controlstatedb.ControlService, actor FeedbackActor, clock authorizationClock) (authorizedFeedbackActor, error) {
	now := clock.current()
	if actor.Kind != "reviewer" || service.Protocol != "http" || actor.ServiceRun == nil ||
		!actor.ServiceRun.valid() || actor.ServiceRun.Subject.ID != service.ID {
		return authorizedFeedbackActor{}, ErrFeedbackAccess
	}
	explicitShare := actor.ShareID != "" || len(actor.ShareSecret) != 0 || len(actor.CookieSecret) != 0
	if actor.VisitProof != nil && explicitShare ||
		explicitShare && (actor.ShareID == "" ||
			!(len(actor.ShareSecret) == 32 && len(actor.CookieSecret) == 0 ||
				len(actor.CookieSecret) == 32 && len(actor.ShareSecret) == 0)) {
		return authorizedFeedbackActor{}, ErrFeedbackAccess
	}
	if service.GuestID.Valid {
		trial, err := controlstatedb.New(tx).GetGuestTrialByID(ctx, service.GuestID.String)
		if err != nil {
			return authorizedFeedbackActor{}, publisherLookupError(err, ErrFeedbackAccess)
		}
		if service.TeamID.Valid || !guestPublicationEligible(trial, now) ||
			trial.ActiveServiceRunID.String != actor.ServiceRun.RunID {
			return authorizedFeedbackActor{}, ErrFeedbackAccess
		}
	}
	q := controlstatedb.New(tx)
	run, err := q.LockServiceRun(ctx, controlstatedb.LockServiceRunParams{ID: actor.ServiceRun.RunID, ServiceID: service.ID})
	if err != nil {
		return authorizedFeedbackActor{}, publisherLookupError(err, ErrFeedbackAccess)
	}
	until := minTime(run.PublisherExpiresAt.Time, run.CertificateExpiresAt.Time)
	publisherUntil, err := serviceRunPublisherPermission(ctx, tx, run, clock.current())
	if err != nil {
		return authorizedFeedbackActor{}, err
	}
	if publisherUntil.Valid && publisherUntil.InfinityModifier == 0 {
		until = minTime(until, publisherUntil.Time)
	}
	if service.ExpiresAt.Valid {
		until = minTime(until, service.ExpiresAt.Time)
	}
	if service.GuestID.Valid {
		deadline, err := q.GuestServiceServingDeadline(ctx, controlstatedb.GuestServiceServingDeadlineParams{ServiceID: service.ID, Now: timestamptz(clock.current())})
		if err != nil {
			return authorizedFeedbackActor{}, publisherLookupError(err, ErrFeedbackAccess)
		}
		if !deadline.Valid {
			return authorizedFeedbackActor{}, ErrFeedbackAccess
		}
		until = minTime(until, deadline.Time)
	}
	source, err := netip.ParseAddr(actor.SourceIP)
	if err != nil || source.Zone() != "" || source.IsUnspecified() {
		return authorizedFeedbackActor{}, ErrFeedbackAccess
	}
	mode, err := d.serviceHTTPSourcePolicy(ctx, controlstatedb.New(tx), service.ID, source)
	if err != nil {
		if errors.Is(err, ErrServiceAccess) {
			err = errors.Join(ErrFeedbackAccess, err)
		}
		return authorizedFeedbackActor{}, err
	}
	if len(actor.BrowserCookieSecret) != 0 && len(actor.BrowserCookieSecret) != 32 ||
		len(actor.BrowserCookieSecret) == 0 && actor.IdentityID != "" {
		return authorizedFeedbackActor{}, ErrVisitorSignIn
	}
	permission := VisitorPermission{}
	if len(actor.BrowserCookieSecret) != 0 {
		digest, _ := browserDigest(base64.RawURLEncoding.EncodeToString(actor.BrowserCookieSecret))
		permission, err = d.serviceBrowserPermission(ctx, tx, service.ID, digest, clock.current())
		if err != nil {
			return authorizedFeedbackActor{}, err
		}
		if permission.ExpiresAt != nil {
			until = minTime(until, *permission.ExpiresAt)
		}
	}
	reference := permission.Reason
	sharePermission := false
	if actor.VisitProof != nil {
		visit, err := d.verifyFeedbackVisitProof(ctx, tx, *actor.ServiceRun, actor.VisitProof, source, clock)
		if err != nil {
			return authorizedFeedbackActor{}, err
		}
		until = minTime(until, visit.ExpiresAt)
		switch subject := visit.Subject.(type) {
		case visitortoken.Share:
			sharePermission, reference = true, subject.ShareID
		case visitortoken.Grant:
			reference = subject.GrantID
		case visitortoken.Browser:
			reference = "browser:" + subject.SessionID
		case visitortoken.Device:
			reference = subject.DeviceID
		case visitortoken.Workload:
			reference = subject.SessionID
		case visitortoken.RegisteredKey:
			reference = subject.AuthorityID()
		}
		permission.VisitAllowed = true
	} else if explicitShare {
		raw := actor.ShareSecret
		cookie := len(actor.CookieSecret) == 32
		if cookie {
			raw = actor.CookieSecret
		}
		shareUntil, err := d.shareVisitorPermission(ctx, tx, service.ID, actor.ServiceRun.RunID, actor.ShareID,
			base64.RawURLEncoding.EncodeToString(raw), cookie, clock.current())
		if err != nil {
			if errors.Is(err, ErrVisitorPermission) {
				err = errors.Join(ErrFeedbackAccess, err)
			}
			return authorizedFeedbackActor{}, err
		}
		until = minTime(until, shareUntil)
		permission.VisitAllowed, sharePermission, reference = true, true, actor.ShareID
	} else if mode == VisitorAccessAnonymous {
		permission.VisitAllowed, reference = true, "anonymous"
	}
	// guest publication still requires its actual current share. neither a
	// token grant, device nor verified browser author becomes a guest manager.
	if !permission.VisitAllowed || service.GuestID.Valid && !sharePermission || !until.After(clock.current()) {
		return authorizedFeedbackActor{}, ErrFeedbackAccess
	}
	if permission.IdentityID != "" {
		reference = "identity:" + permission.IdentityID
	}
	return authorizedFeedbackActor{kind: feedbackReviewer, identityID: permission.IdentityID,
		displayName: permission.DisplayName, reference: reference, permissions: reviewerFeedbackPermissions, expiresAt: until}, nil
}
