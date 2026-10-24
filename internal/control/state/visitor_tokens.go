package state

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
)

var ErrVisitorPermission = errors.New("visitor permission is denied")

// VisitorTokenSource is closed: supplied credentials select exactly one source.
// authentication and current parent facts are checked before anonymous policy.
type VisitorTokenSource interface{ visitorTokenSource() }
type BrowserTokenSource struct{ PreviewID string }

func (BrowserTokenSource) visitorTokenSource() {}

type BrowserSessionTokenSource struct{ Secret string }

func (BrowserSessionTokenSource) visitorTokenSource() {}
func (BrowserSessionTokenSource) String() string      { return "browser sign-in token source" }
func (BrowserSessionTokenSource) GoString() string    { return "browser sign-in token source" }

type DeviceTokenSource struct{ DeviceID string }

func (DeviceTokenSource) visitorTokenSource() {}

type WorkloadTokenSource struct{ Credential string }

func (WorkloadTokenSource) visitorTokenSource() {}
func (WorkloadTokenSource) String() string      { return "workload visitor token source" }
func (WorkloadTokenSource) GoString() string    { return "workload visitor token source" }

type ShareTokenSource struct{ ShareID, Secret string }

func (ShareTokenSource) visitorTokenSource() {}
func (ShareTokenSource) String() string      { return "share visitor token source" }
func (ShareTokenSource) GoString() string    { return "share visitor token source" }

type ShareSessionTokenSource struct{ ShareID, Secret string }

func (ShareSessionTokenSource) visitorTokenSource() {}
func (ShareSessionTokenSource) String() string      { return "share session token source" }
func (ShareSessionTokenSource) GoString() string    { return "share session token source" }

type GrantTokenSource struct{ Credential string }

func (GrantTokenSource) visitorTokenSource() {}
func (GrantTokenSource) String() string      { return "grant visitor token source" }
func (GrantTokenSource) GoString() string    { return "grant visitor token source" }

type IssuedVisitorToken struct {
	Token      visitortoken.Token
	Permission visitortoken.Permission
}

type visitorResource struct {
	Scope            visitorscope.Scope
	TeamID, Hostname string
	IngressPoolID    string
	Port             uint16
	Revision         int64
	Anonymous        bool
	ExpiresAt        time.Time
}

// resource admission holds the existing team/resource guards. permission is
// independent of a selected run, routing snapshot, or per-connection database row.
func lockVisitorResource(ctx context.Context, tx pgx.Tx, scope visitorscope.Scope, now time.Time) (visitorResource, error) {
	resource := visitorResource{Scope: scope}
	if !scope.Valid() {
		return resource, ErrVisitorPermission
	}
	q := controlstatedb.New(tx)
	switch scope.Kind {
	case visitorscope.PublicURL:
		row, err := lockVisitorURL(ctx, q, scope.ID)
		if err != nil {
			return resource, err
		}
		if row.Purpose != "app" && row.Purpose != "alias" && row.Purpose != "demo" || row.ExpiresAt.Valid && !row.ExpiresAt.Time.After(now) {
			return resource, ErrVisitorPermission
		}
		resource.TeamID, resource.Hostname, resource.Port, resource.Anonymous = row.TeamID, row.CanonicalHostname, 443, row.AccessMode == "anonymous"
		resource.IngressPoolID = row.IngressPoolID
		if row.ExpiresAt.Valid {
			resource.ExpiresAt = row.ExpiresAt.Time
		}
	case visitorscope.Service:
		if err := lockServiceAdmission(ctx, tx, scope.ID); err != nil {
			return resource, err
		}
		row, err := q.GetService(ctx, scope.ID)
		if err != nil {
			return resource, err
		}
		if !row.Enabled || row.DeletedAt.Valid || row.CertificateHostname == "" || !row.ServicePort.Valid || row.ServicePort.Int32 < 1024 || row.ServicePort.Int32 > 65535 {
			return resource, ErrVisitorPermission
		}
		resource.TeamID, resource.Hostname, resource.Port = row.TeamID, row.CertificateHostname, uint16(row.ServicePort.Int32)
		resource.IngressPoolID = row.IngressPoolID
	}
	var err error
	resource.Revision, err = q.ReadVisitorPolicyRevision(ctx, controlstatedb.ReadVisitorPolicyRevisionParams{ResourceKind: string(scope.Kind), ResourceID: scope.ID})
	return resource, err
}

func (r visitorResource) permission(subject visitortoken.Subject, until, now time.Time) visitortoken.Permission {
	until = minTime(until, now.Add(visitortoken.RenewableLifetime))
	if !r.ExpiresAt.IsZero() {
		until = minTime(until, r.ExpiresAt)
	}
	return visitortoken.Permission{Scope: r.Scope, Hostname: r.Hostname, Port: r.Port, VisitorPolicyRevision: r.Revision, Subject: subject, ExpiresAt: until.Truncate(time.Second)}
}

// IssueVisitorToken is the authority-facing preparation boundary. it reads one
// scoped permission model and current authentication facts, then records signing
// key retention in the same transaction. serving processes never call this while
// admitting a prepared visitor connection or request.
func (d *Database) IssueVisitorToken(ctx context.Context, issuer string, scope visitorscope.Scope, source VisitorTokenSource, now time.Time) (IssuedVisitorToken, error) {
	for attempt := range 8 {
		if attempt > 0 {
			now = time.Now()
		}
		issued, err := d.issueVisitorTokenTransaction(ctx, issuer, scope, source, now)
		if err == nil || !retryableVisitorTokenTransaction(err) || attempt == 7 {
			return issued, err
		}
		// retry the entire repeatable-read decision against fresh authority facts.
		// sharing one signing key with other preparers cannot turn a safe
		// serialization conflict into a visitor-facing internal error.
		timer := time.NewTimer(time.Duration(attempt+1) * 5 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return IssuedVisitorToken{}, context.Cause(ctx)
		case <-timer.C:
		}
	}
	return IssuedVisitorToken{}, ErrVisitorSigningKey
}

func retryableVisitorTokenTransaction(err error) bool {
	var postgres *pgconn.PgError
	return errors.As(err, &postgres) && (postgres.Code == "40001" || postgres.Code == "40P01")
}

func (d *Database) issueVisitorTokenTransaction(ctx context.Context, issuer string, scope visitorscope.Scope, source VisitorTokenSource, now time.Time) (result IssuedVisitorToken, retErr error) {
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "issue visitor token", &retErr)()
	result, err = d.issueVisitorToken(ctx, tx, issuer, scope, source, now)
	if err != nil {
		return IssuedVisitorToken{}, err
	}
	return result, tx.Commit(ctx)
}

func (d *Database) issueVisitorToken(ctx context.Context, tx pgx.Tx, issuer string, scope visitorscope.Scope, source VisitorTokenSource, now time.Time) (result IssuedVisitorToken, retErr error) {
	permission, err := d.visitorPermissionForSource(ctx, tx, scope, source, now)
	if err != nil {
		return result, err
	}
	token, err := d.signVisitorPermission(ctx, tx, issuer, permission, now)
	if err != nil {
		return result, err
	}
	return IssuedVisitorToken{Token: token, Permission: permission}, nil
}

func (d *Database) visitorPermissionForSource(ctx context.Context, tx pgx.Tx, scope visitorscope.Scope, source VisitorTokenSource, now time.Time) (result visitortoken.Permission, retErr error) {
	var err error
	// workload authentication owns the team guard and fixed session facts. it
	// deliberately cannot create a human control principal.
	workloadID := ""
	if workload, ok := source.(WorkloadTokenSource); ok {
		workloadID, err = lockWorkloadCredential(ctx, tx, workload.Credential, now)
		if err != nil {
			return result, err
		}
	}
	resource, err := lockVisitorResource(ctx, tx, scope, now)
	if err != nil {
		return result, err
	}
	q := controlstatedb.New(tx)
	var subject visitortoken.Subject
	var until time.Time
	explicitLifetime := false
	switch supplied := source.(type) {
	case BrowserTokenSource, DeviceTokenSource, BrowserSessionTokenSource:
		principal, _ := ctx.Value(controlPrincipalKey{}).(ControlPrincipal)
		preview := ""
		var browserDeadline time.Time
		if browser, ok := supplied.(BrowserSessionTokenSource); ok {
			facts, err := d.browserTokenFacts(ctx, tx, scope, browser.Secret, now)
			if err != nil {
				return result, err
			}
			principal, preview, browserDeadline = facts.Principal, facts.PreviewID, facts.ExpiresAt
		}
		if !opaqueid.Valid(principal.IdentityID, opaqueid.IdentityPrefix) || !opaqueid.Valid(principal.SessionID, opaqueid.ControlSessionPrefix) {
			return result, ErrVisitorPermission
		}
		session, err := q.GetVisitorParentSession(ctx, principal.SessionID)
		if err != nil {
			return result, publisherLookupError(err, ErrVisitorPermission)
		}
		if session.IdentityID != principal.IdentityID || session.RevokedAt.Valid || !session.AccessExpiresAt.Time.After(now) || !session.RefreshExpiresAt.Time.After(now) {
			return result, ErrVisitorPermission
		}
		if browser, ok := supplied.(BrowserTokenSource); ok {
			preview = browser.PreviewID
		}
		decision, err := q.VisitorPermission(ctx, controlstatedb.VisitorPermissionParams{ResourceKind: string(scope.Kind), ResourceID: scope.ID, IdentityID: principal.IdentityID, ControlSessionID: principal.SessionID, PreviewID: preview, Now: timestamptz(now)})
		if errors.Is(err, pgx.ErrNoRows) && resource.Anonymous {
			// a valid signed-in person may visit an explicitly anonymous URL.
			// malformed, revoked, or expired source credentials already failed.
			var active bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.identities WHERE id=$1 AND disabled_at IS NULL)`, principal.IdentityID).Scan(&active); err != nil {
				return result, err
			}
			if !active {
				return result, ErrVisitorPermission
			}
		} else if err != nil {
			return result, publisherLookupError(err, ErrVisitorPermission)
		}
		until = minTime(session.AccessExpiresAt.Time, session.RefreshExpiresAt.Time)
		if !browserDeadline.IsZero() {
			until = minTime(until, browserDeadline)
		}
		if decision.ExpiresAt.Valid && decision.ExpiresAt.InfinityModifier == 0 {
			until = minTime(until, decision.ExpiresAt.Time)
		}
		subject = visitortoken.Browser{IdentityID: principal.IdentityID, SessionID: principal.SessionID}
		if device, ok := supplied.(DeviceTokenSource); ok {
			if scope.Kind != visitorscope.Service {
				return result, ErrVisitorPermission
			}
			var public []byte
			if err := tx.QueryRow(ctx, `SELECT public_key FROM control.visitor_devices WHERE id=$1 AND identity_id=$2 AND revoked_at IS NULL FOR SHARE`, device.DeviceID, principal.IdentityID).Scan(&public); err != nil {
				return result, publisherLookupError(err, ErrVisitorPermission)
			}
			if len(public) != ed25519.PublicKeySize {
				return result, ErrVisitorPermission
			}
			digest, err := visitortoken.KeyDigest(ed25519.PublicKey(public))
			if err != nil {
				return result, err
			}
			subject = visitortoken.Device{IdentityID: principal.IdentityID, SessionID: principal.SessionID, DeviceID: device.DeviceID, KeySHA256: digest}
		}
	case WorkloadTokenSource:
		if scope.Kind != visitorscope.Service || workloadID == "" {
			return result, ErrVisitorPermission
		}
		var public []byte
		// selected-service membership is an authority-confirmed workload fact,
		// independent of human grants and of which publisher run is ready.
		err := tx.QueryRow(ctx, `SELECT w.public_key,LEAST(w.lease_expires_at,w.expires_at) FROM control.workload_sessions w
		    JOIN control.workload_session_services selected ON selected.workload_session_id=w.id AND selected.service_id=$2
		    JOIN control.teams team ON team.id=w.team_id AND team.deleted_at IS NULL
		    JOIN control.applied_projects project ON project.team_id=w.team_id AND project.project_key=w.project_key
		    WHERE w.id=$1 AND w.team_id=$3 AND w.revoked_at IS NULL AND w.lease_expires_at>$4 AND w.expires_at>$4`, workloadID, scope.ID, resource.TeamID, now).Scan(&public, &until)
		if err != nil {
			return result, publisherLookupError(err, ErrVisitorPermission)
		}
		if len(public) != ed25519.PublicKeySize {
			return result, ErrVisitorPermission
		}
		digest, err := visitortoken.KeyDigest(ed25519.PublicKey(public))
		if err != nil {
			return result, err
		}
		subject = visitortoken.Workload{SessionID: workloadID, KeySHA256: digest}
	case ShareTokenSource, ShareSessionTokenSource:
		var shareID, sourceSecret string
		var session bool
		switch value := supplied.(type) {
		case ShareTokenSource:
			shareID, sourceSecret = value.ShareID, value.Secret
		case ShareSessionTokenSource:
			shareID, sourceSecret, session = value.ShareID, value.Secret, true
		}
		if scope.Kind != visitorscope.PublicURL || !opaqueid.Valid(shareID, opaqueid.SharePrefix) || len(sourceSecret) != 43 {
			return result, ErrVisitorPermission
		}
		secret, err := base64.RawURLEncoding.Strict().DecodeString(sourceSecret)
		if err != nil || len(secret) != 32 {
			return result, ErrVisitorPermission
		}
		digest := sha256.Sum256(secret)
		var stored []byte
		var issuerID, guestID string
		err = tx.QueryRow(ctx, `SELECT share.secret_digest,share.expires_at,share.created_by_identity_id,COALESCE(share.guest_id,'') FROM control.shares share
		    JOIN control.share_public_urls included ON included.share_id=share.id AND included.public_url_id=$2
		    WHERE share.id=$1 AND share.revoked_at IS NULL AND share.expires_at>$3
		    AND (share.scope<>'guest' OR control.guest_share_live(share.guest_id,$3)) FOR SHARE OF share`, shareID, scope.ID, now).Scan(&stored, &until, &issuerID, &guestID)
		if err != nil {
			return result, publisherLookupError(err, ErrVisitorPermission)
		}
		if session {
			var deadline time.Time
			err := tx.QueryRow(ctx, `SELECT expires_at FROM control.share_cookies
			    WHERE token_digest=$1 AND share_id=$2 AND public_url_id=$3 AND expires_at>$4 FOR SHARE`, digest[:], shareID, scope.ID, now).Scan(&deadline)
			if err != nil {
				return result, publisherLookupError(err, ErrVisitorPermission)
			}
			until = minTime(until, deadline)
		} else if subtle.ConstantTimeCompare(stored, digest[:]) != 1 {
			return result, ErrVisitorPermission
		}
		if guestID == "" {
			// a share depends on the issuer retaining management authority, not
			// merely holding an unrelated visitor grant on the same resource.
			var authorized bool
			err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.public_urls url
			    JOIN control.teams team ON team.id=url.team_id AND team.deleted_at IS NULL
			    JOIN control.identities person ON person.id=$2 AND person.disabled_at IS NULL
			    JOIN control.team_memberships member ON member.team_id=url.team_id AND member.identity_id=person.id
			    WHERE url.id=$1 AND control.active_membership(member.id,$3)
			    AND control.active_team_subject(url.team_id,person.id,$3)
			    AND ((url.public_url_scope='member' AND member.id=url.membership_id)
			        OR (url.public_url_scope='shared' AND member.role IN ('owner','admin'))))`, scope.ID, issuerID, now).Scan(&authorized)
			if err != nil {
				return result, err
			}
			if !authorized {
				return result, ErrVisitorPermission
			}
		} else {
			var deadline time.Time
			if err := tx.QueryRow(ctx, `SELECT expires_at FROM control.guest_trials WHERE id=$1`, guestID).Scan(&deadline); err != nil {
				return result, err
			}
			until = minTime(until, deadline)
		}
		subject = visitortoken.Share{ShareID: shareID}
	case GrantTokenSource:
		if scope.Kind != visitorscope.Service {
			return result, ErrVisitorPermission
		}
		grantID, digest, err := visitorRefreshDigest(supplied.Credential)
		if err != nil {
			return result, err
		}
		var creator, session string
		err = tx.QueryRow(ctx, `SELECT created_by_identity_id,COALESCE(control_session_id,''),expires_at FROM control.service_http_grants
		    WHERE id=$1 AND service_id=$2 AND secret_digest=$3 AND revoked_at IS NULL AND expires_at>$4 FOR SHARE`, grantID, scope.ID, digest[:], now).Scan(&creator, &session, &until)
		if err != nil {
			return result, publisherLookupError(err, ErrVisitorPermission)
		}
		if session != "" {
			parent, err := q.GetVisitorParentSession(ctx, session)
			if err != nil {
				return result, publisherLookupError(err, ErrVisitorPermission)
			}
			if parent.IdentityID != creator || parent.RevokedAt.Valid || !parent.AccessExpiresAt.Time.After(now) || !parent.RefreshExpiresAt.Time.After(now) {
				return result, ErrVisitorPermission
			}
			until = minTime(until, minTime(parent.AccessExpiresAt.Time, parent.RefreshExpiresAt.Time))
		}
		decision, err := q.VisitorPermission(ctx, controlstatedb.VisitorPermissionParams{ResourceKind: "service", ResourceID: scope.ID, IdentityID: creator, ControlSessionID: session, Now: timestamptz(now)})
		if err != nil {
			return result, publisherLookupError(err, ErrVisitorPermission)
		}
		if decision.ExpiresAt.Valid && decision.ExpiresAt.InfinityModifier == 0 {
			until = minTime(until, decision.ExpiresAt.Time)
		}
		subject = visitortoken.Grant{GrantID: grantID}
		explicitLifetime = true
	default:
		return result, ErrVisitorPermission
	}
	if !until.After(now) {
		return result, ErrVisitorPermission
	}
	result = resource.permission(subject, until, now)
	if explicitLifetime {
		result.ExpiresAt = until.Truncate(time.Second)
	}
	return result, nil
}

// a refresh credential is authority-facing only. it has a separate format and
// digest purpose from every retired application-access credential.
func visitorRefreshDigest(credential string) (string, [32]byte, error) {
	var zero [32]byte
	parts := strings.Split(credential, ".")
	if len(parts) != 3 || parts[0] != "vrf1" || !opaqueid.Valid(parts[1], "shg_") || len(parts[2]) != 43 {
		return "", zero, ErrVisitorPermission
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != parts[2] {
		return "", zero, ErrVisitorPermission
	}
	return parts[1], sha256.Sum256([]byte("tnl visitor refresh v1\x00" + credential)), nil
}

type browserTokenFacts struct {
	Principal ControlPrincipal
	PreviewID string
	ExpiresAt time.Time
}

// browser sign-in records supply authentication and the captured hostname scope.
// the common permission model makes the resource decision after this boundary.
func (d *Database) browserTokenFacts(ctx context.Context, tx pgx.Tx, scope visitorscope.Scope, secret string, now time.Time) (result browserTokenFacts, err error) {
	digest, err := browserDigest(secret)
	if err != nil {
		return result, ErrVisitorPermission
	}
	q := controlstatedb.New(tx)
	if scope.Kind == visitorscope.Service {
		err := tx.QueryRow(ctx, `SELECT session.control_session_id,parent.identity_id,LEAST(session.expires_at,parent.refresh_expires_at)
		    FROM control.service_http_browser_sessions session JOIN control.control_sessions parent ON parent.id=session.control_session_id
		    WHERE session.service_id=$1 AND session.cookie_digest=$2
		    AND session.revoked_at IS NULL AND session.expires_at>$3 AND parent.revoked_at IS NULL
		    AND parent.refresh_expires_at>$3 FOR SHARE OF session,parent`, scope.ID, digest, now).Scan(&result.Principal.SessionID, &result.Principal.IdentityID, &result.ExpiresAt)
		return result, publisherLookupError(err, ErrVisitorPermission)
	}
	if scope.Kind != visitorscope.PublicURL {
		return result, ErrVisitorPermission
	}
	row, err := q.LockBrowserAccessSession(ctx, digest)
	if err != nil {
		return result, publisherLookupError(err, ErrVisitorPermission)
	}
	if row.RevokedAt.Valid || !row.ExpiresAt.Time.After(now) {
		return result, ErrVisitorPermission
	}
	var bound bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.browser_session_run_bindings WHERE session_digest=$1 AND public_url_id=$2)`, digest, scope.ID).Scan(&bound)
	if err != nil {
		return result, err
	}
	if !bound {
		return result, ErrVisitorPermission
	}
	if d.storageKey == nil {
		return result, ErrVisitorPermission
	}
	access, _, err := d.storageKey.Open(row.StorageKeyID, browserContext(digest), row.AccessCiphertext)
	if err != nil {
		return result, err
	}
	accessID, tokenDigest, err := credentials.ParseAccessToken(credentials.AccessToken(access))
	if err != nil {
		return result, ErrVisitorPermission
	}
	parent, err := q.LockVisitorControlSession(ctx, accessID.String())
	if err != nil {
		return result, publisherLookupError(err, ErrVisitorPermission)
	}
	if parent.IdentityID != row.IdentityID || parent.RevokedAt.Valid || !credentials.SecretHashMatches(parent.AccessTokenDigest, tokenDigest) || !parent.AccessExpiresAt.Time.After(now) {
		return result, ErrVisitorPermission
	}
	result.Principal = ControlPrincipal{SessionID: parent.ID, IdentityID: parent.IdentityID}
	result.PreviewID, result.ExpiresAt = row.PreviewID.String, row.ExpiresAt.Time
	if row.ParentControlSessionID.Valid {
		original, err := q.GetVisitorParentSession(ctx, row.ParentControlSessionID.String)
		if err != nil {
			return result, publisherLookupError(err, ErrVisitorPermission)
		}
		if original.IdentityID != row.IdentityID || original.RevokedAt.Valid || !original.RefreshExpiresAt.Time.After(now) {
			return result, ErrVisitorPermission
		}
		result.ExpiresAt = minTime(result.ExpiresAt, original.RefreshExpiresAt.Time)
	}
	return result, nil
}
