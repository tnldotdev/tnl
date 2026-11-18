package state

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
)

// FeedbackVisitProof is publisher-supplied evidence of the selected admission.
// the API contract owns its wire shape; browser request bodies cannot supply it.
type FeedbackVisitProof interface{ feedbackVisitProof() }

type FeedbackBearerVisitProof struct{ Token visitortoken.Token }

func (FeedbackBearerVisitProof) feedbackVisitProof() {}
func (FeedbackBearerVisitProof) String() string      { return "feedback bearer visit proof" }
func (FeedbackBearerVisitProof) GoString() string    { return "feedback bearer visit proof" }

type FeedbackConnectorVisitProof struct {
	PairID             string
	DeliveryGeneration int64
	PermissionToken    visitortoken.Token
}

func (FeedbackConnectorVisitProof) feedbackVisitProof() {}
func (FeedbackConnectorVisitProof) String() string      { return "feedback connector visit proof" }
func (FeedbackConnectorVisitProof) GoString() string    { return "feedback connector visit proof" }

// callers retain lockServiceHTTPRun and the current preview scope in this
// transaction. returned permission is visit authority only, never authorship.
func (d *Database) verifyFeedbackVisitProof(ctx context.Context, tx pgx.Tx, auth ServiceHTTPRun, proof FeedbackVisitProof, source netip.Addr, clock authorizationClock) (visitortoken.Permission, error) {
	update, err := d.readVisitorPolicy(ctx, tx, auth.Subject, 0, clock.current())
	if err != nil {
		return visitortoken.Permission{}, err
	}
	if auth.Hostname != "" {
		hostname, err := selectServiceHTTPHostname(ctx, controlstatedb.New(tx), auth.Subject.ID, update.Policy.Hostname, auth.Hostname, clock.current())
		if err != nil {
			return visitortoken.Permission{}, errors.Join(ErrFeedbackAccess, err)
		}
		update.Policy.Hostname = hostname
		if update.Policy.PublicEndpoint != nil {
			update.Policy.PublicEndpoint.Hostname = hostname
		}
	}
	policy, err := visitorlease.Decode(update)
	if err != nil {
		return visitortoken.Permission{}, err
	}
	if !policy.Enabled || !source.IsValid() || source.IsUnspecified() || source.Zone() != "" ||
		policy.IP != nil && !policy.IP.Allows(source) {
		return visitortoken.Permission{}, ErrFeedbackAccess
	}
	var permission visitortoken.Permission
	var until time.Time
	switch supplied := proof.(type) {
	case FeedbackBearerVisitProof:
		verified, err := visitortoken.VerifyBearer(supplied.Token, policy.View, clock.current())
		if err != nil {
			return visitortoken.Permission{}, errors.Join(ErrFeedbackAccess, err)
		}
		permission = verified.Facts()
		switch subject := permission.Subject.(type) {
		case visitortoken.Grant:
			grant, err := currentServiceHTTPGrantAuthority(ctx, tx, auth.Subject.ID, subject.GrantID, clock.current())
			if err != nil {
				return visitortoken.Permission{}, errors.Join(ErrFeedbackAccess, err)
			}
			if grant.subject != subject {
				return visitortoken.Permission{}, ErrFeedbackAccess
			}
			until = grant.expiresAt
		case visitortoken.Share:
			_, until, err = d.currentShareVisitorAuthority(ctx, tx, auth.Subject.ID, subject.ShareID, clock.current())
			if err != nil {
				return visitortoken.Permission{}, errors.Join(ErrFeedbackAccess, err)
			}
		case visitortoken.Browser:
			principal := ControlPrincipal{IdentityID: subject.IdentityID, SessionID: subject.SessionID}
			until, err = currentVisitorParentSession(ctx, tx, principal, clock.current())
			if err != nil {
				return visitortoken.Permission{}, errors.Join(ErrFeedbackAccess, err)
			}
			current, err := d.serviceHTTPIdentityPermission(WithControlPrincipal(ctx, principal), tx, auth.Subject.ID, subject.IdentityID, clock.current())
			if err != nil {
				return visitortoken.Permission{}, err
			}
			if !current.VisitAllowed {
				return visitortoken.Permission{}, ErrFeedbackAccess
			}
			if current.ExpiresAt != nil {
				until = minTime(until, *current.ExpiresAt)
			}
		default:
			return visitortoken.Permission{}, ErrFeedbackAccess
		}
	case FeedbackConnectorVisitProof:
		// connector authority cannot be rebound to a public exact-run alias.
		var canonical string
		if err := tx.QueryRow(ctx, `SELECT certificate_hostname FROM control.services WHERE id=$1`, auth.Subject.ID).Scan(&canonical); err != nil {
			return visitortoken.Permission{}, err
		}
		if auth.Hostname != "" && auth.Hostname != canonical {
			return visitortoken.Permission{}, ErrFeedbackAccess
		}
		if !opaqueid.Valid(supplied.PairID, "cpp_") || supplied.DeliveryGeneration < 1 {
			return visitortoken.Permission{}, ErrFeedbackAccess
		}
		permission, err = visitortoken.CheckConnectorPermission(supplied.PermissionToken, policy.View, clock.current())
		if err != nil {
			return visitortoken.Permission{}, errors.Join(ErrFeedbackAccess, err)
		}
		q := controlstatedb.New(tx)
		run, err := q.LockServiceRun(ctx, controlstatedb.LockServiceRunParams{ID: auth.RunID, ServiceID: auth.Subject.ID})
		if err != nil {
			return visitortoken.Permission{}, publisherLookupError(err, ErrFeedbackAccess)
		}
		if run.RunNumber != auth.Number {
			return visitortoken.Permission{}, ErrFeedbackAccess
		}
		pair, err := q.LockConnectorPeerPairForLegClaim(ctx, supplied.PairID)
		if err != nil {
			return visitortoken.Permission{}, publisherLookupError(err, ErrFeedbackAccess)
		}
		if pair.DeliveryGeneration != supplied.DeliveryGeneration {
			return visitortoken.Permission{}, ErrFeedbackAccess
		}
		binding, err := d.connectorPeerPairBinding(ctx, tx, run, pair, clock.current())
		if err != nil {
			return visitortoken.Permission{}, errors.Join(ErrFeedbackAccess, err)
		}
		subject, err := visitortoken.ConnectorSubject(permission.Subject)
		if err != nil || subject != binding.subject || !binding.claimsCurrent ||
			!binding.preparedUntil.After(clock.current()) || binding.source != source.Unmap() {
			return visitortoken.Permission{}, ErrFeedbackAccess
		}
		digest, err := visitortoken.KeyDigest(binding.publicKey)
		if err != nil {
			return visitortoken.Permission{}, err
		}
		var expected string
		switch subject := permission.Subject.(type) {
		case visitortoken.Device:
			if subject.SessionID != pair.ParentControlSessionID.String {
				return visitortoken.Permission{}, ErrFeedbackAccess
			}
			expected = subject.KeySHA256
		case visitortoken.Workload:
			expected = subject.KeySHA256
		case visitortoken.RegisteredKey:
			expected = subject.KeySHA256
		}
		if expected == "" || digest != expected {
			return visitortoken.Permission{}, ErrFeedbackAccess
		}
		until = minTime(binding.expiresAt, minTime(binding.preparedUntil, binding.recheckAt))
	default:
		return visitortoken.Permission{}, ErrFeedbackAccess
	}
	permission.ExpiresAt = minTime(permission.ExpiresAt, minTime(until, policy.View.ValidUntil))
	if !permission.ExpiresAt.After(clock.current()) {
		return visitortoken.Permission{}, ErrFeedbackAccess
	}
	return permission, nil
}

// deferred writes and lock waits spend the same original authorization budget.
// rollback retains its own uncanceled cleanup context and joins real failures.
func commitFeedback(ctx context.Context, tx pgx.Tx, clock authorizationClock, until time.Time) error {
	if _, err := tx.Exec(ctx, "SET CONSTRAINTS ALL IMMEDIATE"); err != nil {
		return err
	}
	if until.IsZero() {
		return tx.Commit(ctx)
	}
	if !until.After(clock.current()) {
		return ErrFeedbackAccess
	}
	commit, stop := context.WithDeadline(ctx, clock.started.Add(until.Sub(clock.entered)))
	defer stop()
	if err := tx.Commit(commit); err != nil {
		if !until.After(clock.current()) {
			return errors.Join(ErrFeedbackAccess, err)
		}
		return err
	}
	if !until.After(clock.current()) {
		return ErrFeedbackAccess
	}
	return nil
}
