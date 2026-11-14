package state

import (
	"context"
	"crypto/ed25519"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// connectorPeerPairSubjectKey restores only the subject and exact parent saved by
// authenticated pair creation. relay and publisher contexts are not human proof.
// callers hold resource admission and pair locks through key delivery.
func (d *Database) connectorPeerPairSubjectKey(ctx context.Context, tx pgx.Tx, pair controlstatedb.ControlConnectorPeerPair, now time.Time) (VisitorSubject, ed25519.PublicKey, time.Time, error) {
	subject := VisitorSubject{Kind: pair.SubjectKind}
	var parentUntil time.Time
	switch subject.Kind {
	case tunnelv1.VisitorHumanDevice:
		if !pair.ParentControlSessionID.Valid || pair.ParentControlSessionID.String == "" {
			return VisitorSubject{}, nil, time.Time{}, ErrServiceAccess
		}
		subject.DeviceID = pair.SubjectID
		if err := tx.QueryRow(ctx, `SELECT identity_id FROM control.visitor_devices WHERE id=$1 AND revoked_at IS NULL FOR SHARE`, pair.SubjectID).Scan(&subject.IdentityID); err != nil {
			return VisitorSubject{}, nil, time.Time{}, publisherLookupError(err, ErrServiceAccess)
		}
		parent, err := controlstatedb.New(tx).GetVisitorParentSession(ctx, pair.ParentControlSessionID.String)
		if err != nil {
			return VisitorSubject{}, nil, time.Time{}, publisherLookupError(err, ErrServiceAccess)
		}
		if parent.IdentityID != subject.IdentityID || parent.RevokedAt.Valid || !parent.AccessExpiresAt.Time.After(now) || !parent.RefreshExpiresAt.Time.After(now) {
			return VisitorSubject{}, nil, time.Time{}, ErrServiceAccess
		}
		parentUntil = minTime(parent.AccessExpiresAt.Time, parent.RefreshExpiresAt.Time)
		ctx = WithControlPrincipal(ctx, ControlPrincipal{IdentityID: subject.IdentityID, SessionID: parent.ID})
	case tunnelv1.VisitorWorkloadSession:
		subject.WorkloadSessionID = pair.SubjectID
	case tunnelv1.VisitorRegisteredKey:
		var ok bool
		subject.GrantID, subject.KeyID, ok = strings.Cut(pair.SubjectID, ".")
		if !ok || subject.Validate() != nil {
			return VisitorSubject{}, nil, time.Time{}, ErrServiceAccess
		}
	default:
		return VisitorSubject{}, nil, time.Time{}, ErrServiceAccess
	}
	if pair.PublicURLID != "" {
		// public URLs reuse their current native source decision, including
		// the preview selected by original creation. a relay cannot select a
		// different preview or substitute a service/workload permission.
		if subject.Kind != tunnelv1.VisitorHumanDevice {
			return VisitorSubject{}, nil, time.Time{}, ErrServiceAccess
		}
		source := DeviceTokenSource{DeviceID: subject.DeviceID, PreviewID: pair.PreviewID.String}
		authority, err := d.visitorAuthorityForSource(ctx, tx, visitorscope.Scope{Kind: visitorscope.PublicURL, ID: pair.PublicURLID}, source, newAuthorizationClock(now))
		if err != nil {
			return VisitorSubject{}, nil, time.Time{}, err
		}
		current, err := visitortoken.ConnectorSubject(authority.Permission.Subject)
		if err != nil || current != subject {
			return VisitorSubject{}, nil, time.Time{}, ErrServiceAccess
		}
		until := minTime(parentUntil, minTime(authority.Permission.ExpiresAt, authority.ConnectorUntil))
		if !until.After(now) {
			return VisitorSubject{}, nil, time.Time{}, ErrServiceAccess
		}
		return subject, authority.PublicKey, until, nil
	}
	key, until, err := AuthenticateVisitorSubjectKey(ctx, tx, subject, pair.ServiceID, now)
	if err != nil {
		return VisitorSubject{}, nil, time.Time{}, err
	}
	if !parentUntil.IsZero() {
		until = minTime(until, parentUntil)
	}
	if !until.After(now) {
		return VisitorSubject{}, nil, time.Time{}, ErrServiceAccess
	}
	return subject, key, until, nil
}
