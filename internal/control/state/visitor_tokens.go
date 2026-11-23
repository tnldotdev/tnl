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
	"github.com/tnldotdev/tnl/internal/policy/serviceendpoint"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitorcert"
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

type RegisteredKeyTokenSource struct{ Credential string }

func (RegisteredKeyTokenSource) visitorTokenSource() {}
func (RegisteredKeyTokenSource) String() string      { return "registered key visitor token source" }
func (RegisteredKeyTokenSource) GoString() string    { return "registered key visitor token source" }

type ShareTokenSource struct{ ShareID, Secret string }

func (ShareTokenSource) visitorTokenSource() {}
func (ShareTokenSource) String() string      { return "share visitor token source" }
func (ShareTokenSource) GoString() string    { return "share visitor token source" }

type ShareSessionTokenSource struct{ ShareID, Secret, RunID string }

func (ShareSessionTokenSource) visitorTokenSource() {}
func (ShareSessionTokenSource) String() string      { return "share session token source" }
func (ShareSessionTokenSource) GoString() string    { return "share session token source" }

type GrantTokenSource struct{ Credential string }

func (GrantTokenSource) visitorTokenSource() {}
func (GrantTokenSource) String() string      { return "grant visitor token source" }
func (GrantTokenSource) GoString() string    { return "grant visitor token source" }

type IssuedVisitorToken struct {
	Token                visitortoken.Token
	Permission           visitortoken.Permission
	ServiceTrustRevision int64
}

type visitorResource struct {
	Scope            visitorscope.Scope
	TeamID, Hostname string
	Port             uint16
	Revision         int64
	Anonymous        bool
	ExpiresAt        time.Time
}

// resource admission holds the existing team/resource guards. ordinary permission
// is independent of a selected run; guest permission also spends its run's fixed
// serving deadline. neither needs a per-connection database row.
func lockVisitorResource(ctx context.Context, tx pgx.Tx, scope visitorscope.Scope, now time.Time) (visitorResource, error) {
	if !scope.Valid() {
		return visitorResource{}, ErrVisitorPermission
	}
	if scope.Kind == visitorscope.Service {
		if err := lockServiceAdmission(ctx, tx, scope.ID); err != nil {
			return visitorResource{}, err
		}
	}
	return readLockedVisitorResource(ctx, tx, scope, now)
}

// callers already hold the resource's admission or run guard.
func readLockedVisitorResource(ctx context.Context, tx pgx.Tx, scope visitorscope.Scope, now time.Time) (visitorResource, error) {
	resource := visitorResource{Scope: scope}
	q := controlstatedb.New(tx)
	switch scope.Kind {
	case visitorscope.Service:
		row, err := q.GetService(ctx, scope.ID)
		if err != nil {
			return resource, err
		}
		if !row.Enabled || row.DeletedAt.Valid || !row.ServicePort.Valid || !serviceendpoint.Valid(row.Protocol, row.CertificateHostname, int(row.ServicePort.Int32), row.Public) {
			return resource, ErrVisitorPermission
		}
		resource.TeamID, resource.Hostname, resource.Port = row.TeamID.String, row.CertificateHostname, serviceendpoint.PermissionPort(row.Protocol)
		if row.ExpiresAt.Valid {
			resource.ExpiresAt = row.ExpiresAt.Time
		}
		if row.GuestID.Valid {
			deadline, err := q.GuestServiceServingDeadline(ctx, controlstatedb.GuestServiceServingDeadlineParams{ServiceID: scope.ID, Now: timestamptz(now)})
			if err != nil || !deadline.Valid || !deadline.Time.After(now) {
				if err != nil {
					return resource, publisherLookupError(err, ErrVisitorPermission)
				}
				return resource, ErrVisitorPermission
			}
			resource.ExpiresAt = minTime(resource.ExpiresAt, deadline.Time)
		}
	}
	var err error
	resource.Revision, err = q.ReadVisitorPolicyRevision(ctx, scope.ID)
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
func (d *Database) IssueVisitorToken(ctx context.Context, issuer string, scope visitorscope.Scope, source VisitorTokenSource, now time.Time, hostnames ...string) (result IssuedVisitorToken, retErr error) {
	hostname, err := serviceHTTPHostnameSelection(hostnames)
	if err != nil {
		return result, ErrVisitorPermission
	}
	if hostname != "" {
		switch source.(type) {
		case BrowserTokenSource, BrowserSessionTokenSource, ShareTokenSource, ShareSessionTokenSource, GrantTokenSource:
		default:
			return result, ErrVisitorPermission
		}
	}
	return retryVisitorPreparation(ctx, now, func(at time.Time) (IssuedVisitorToken, error) {
		return d.issueVisitorTokenTransaction(ctx, issuer, scope, source, at, hostname)
	})
}

// retry the whole preparation decision, including current source authority and
// key retention. a repeatable-read serialization failure rolls back every write.
func retryVisitorPreparation[T any](ctx context.Context, now time.Time, work func(time.Time) (T, error)) (result T, err error) {
	return retryVisitorPreparationWithLockAttempts(ctx, now, 8, work)
}

func retryVisitorPreparationWithLockAttempts[T any](ctx context.Context, now time.Time, lockAttempts int, work func(time.Time) (T, error)) (result T, err error) {
	for attempt := 0; ; attempt++ {
		if attempt > 0 {
			now = time.Now()
		}
		result, err = work(now)
		var pgErr *pgconn.PgError
		// the first PostgreSQL match owns classification. a malformed nil match
		// never permits retry, even if a later joined cause is retryable.
		if !errors.As(err, &pgErr) || pgErr == nil || pgErr.Code != "40001" && pgErr.Code != "40P01" && pgErr.Code != "55P03" {
			return result, err
		}
		// retry only after the previous attempt rolled back cleanly.
		var cleanup *RollbackFailure
		if errors.As(err, &cleanup) {
			return result, err
		}
		limit := 8
		if pgErr.Code == "55P03" {
			limit = lockAttempts
		}
		if attempt+1 >= limit {
			return result, err
		}
		timer := time.NewTimer(min(time.Duration(attempt+1)*5*time.Millisecond, 50*time.Millisecond))
		select {
		case <-ctx.Done():
			timer.Stop()
			var zero T
			return zero, context.Cause(ctx)
		case <-timer.C:
		}
	}
}

func (d *Database) issueVisitorTokenTransaction(ctx context.Context, issuer string, scope visitorscope.Scope, source VisitorTokenSource, now time.Time, hostname string) (result IssuedVisitorToken, retErr error) {
	clock := newAuthorizationClock(now)
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "issue visitor token", &retErr)()
	result, err = d.issueVisitorToken(ctx, tx, issuer, scope, source, clock, hostname)
	if err != nil {
		return IssuedVisitorToken{}, err
	}
	if _, registered := source.(RegisteredKeyTokenSource); registered {
		commit, stop := context.WithDeadline(ctx, clock.started.Add(result.Permission.ExpiresAt.Sub(clock.entered)))
		defer stop()
		if err = tx.Commit(commit); err != nil {
			return IssuedVisitorToken{}, err
		}
		if !result.Permission.ExpiresAt.After(clock.current()) {
			return IssuedVisitorToken{}, ErrVisitorPermission
		}
		return result, nil
	}
	return result, tx.Commit(ctx)
}

func (d *Database) issueVisitorToken(ctx context.Context, tx pgx.Tx, issuer string, scope visitorscope.Scope, source VisitorTokenSource, clock authorizationClock, hostnames ...string) (result IssuedVisitorToken, retErr error) {
	authority, err := d.visitorAuthorityForSource(ctx, tx, scope, source, clock, hostnames...)
	if err != nil {
		return result, err
	}
	permission := authority.Permission
	if scope.Kind == visitorscope.Service {
		// service admission holds the same lock as metadata updates. read the
		// current revision without selecting another publisher run.
		if err := tx.QueryRow(ctx, `SELECT trust_revision FROM control.services WHERE id=$1`, scope.ID).Scan(&result.ServiceTrustRevision); err != nil {
			return result, err
		}
	}
	token, err := d.signVisitorPermission(ctx, tx, issuer, permission, clock.entered)
	if err != nil {
		return result, err
	}
	if err = d.lockRegisteredVisitorAuthority(ctx, tx, source, permission, clock); err != nil {
		return result, err
	}
	result.Token, result.Permission = token, permission
	return result, nil
}

// visitorAuthority keeps the permission and its proof key from one locked source
// decision. connector preparation consumes these facts without reauthenticating.
type visitorAuthority struct {
	Permission              visitortoken.Permission
	PublicKey               ed25519.PublicKey
	ConnectorUntil          time.Time
	WorkloadCredentialUntil time.Time
}

func (d *Database) visitorAuthorityForSource(ctx context.Context, tx pgx.Tx, scope visitorscope.Scope, source VisitorTokenSource, clock authorizationClock, hostnames ...string) (result visitorAuthority, retErr error) {
	now := clock.entered
	var err error
	// workload authentication owns the team guard and fixed session facts. it
	// deliberately cannot create a human control principal.
	var workloadSource workloadAuthority
	if workload, ok := source.(WorkloadTokenSource); ok {
		workloadSource, err = lockWorkloadCredential(ctx, tx, workload.Credential, clock)
		if err != nil {
			return result, err
		}
	}
	resource, err := lockVisitorResource(ctx, tx, scope, now)
	if err != nil {
		return result, err
	}
	q := controlstatedb.New(tx)
	hostname, err := serviceHTTPHostnameSelection(hostnames)
	if err != nil {
		return result, ErrVisitorPermission
	}
	if hostname != "" {
		switch source.(type) {
		case BrowserTokenSource, BrowserSessionTokenSource, ShareTokenSource, ShareSessionTokenSource, GrantTokenSource:
		default:
			return result, ErrVisitorPermission
		}
		if scope.Kind != visitorscope.Service {
			return result, ErrVisitorPermission
		}
		selected, err := selectServiceHTTPHostname(ctx, q, scope.ID, resource.Hostname, hostname, now)
		if err != nil {
			return result, publisherLookupError(err, ErrVisitorPermission)
		}
		resource.Hostname = selected
	}
	var subject visitortoken.Subject
	var browserGrantID string
	var until time.Time
	explicitLifetime := false
	switch supplied := source.(type) {
	case BrowserTokenSource, DeviceTokenSource, BrowserSessionTokenSource:
		principal, _ := ctx.Value(controlPrincipalKey{}).(ControlPrincipal)
		preview := ""
		var browserDeadline time.Time
		if browser, ok := supplied.(BrowserSessionTokenSource); ok {
			facts, err := d.browserTokenFacts(ctx, tx, scope, browser.Secret, resource.Hostname, now)
			if err != nil {
				return result, err
			}
			principal, browserDeadline = facts.Principal, facts.ExpiresAt
		}
		parentUntil, err := currentVisitorParentSession(ctx, tx, principal, now)
		if err != nil {
			return result, err
		}
		if browser, ok := supplied.(BrowserTokenSource); ok {
			preview = browser.PreviewID
		}
		decision, err := q.VisitorPermission(ctx, controlstatedb.VisitorPermissionParams{ResourceKind: string(scope.Kind), ResourceID: scope.ID, IdentityID: principal.IdentityID, ControlSessionID: principal.SessionID, PreviewID: preview, Now: timestamptz(now)})
		_, deviceSource := supplied.(DeviceTokenSource)
		if errors.Is(err, pgx.ErrNoRows) && scope.Kind == visitorscope.Service && !deviceSource {
			http, httpErr := d.serviceHTTPIdentityPermission(WithControlPrincipal(ctx, principal), tx, scope.ID, principal.IdentityID, now)
			if httpErr != nil {
				return result, httpErr
			}
			_, browserSession := supplied.(BrowserSessionTokenSource)
			if http.VisitAllowed && (http.Reason != "anonymous" || browserSession) {
				err = nil
				if http.ExpiresAt != nil {
					decision.ExpiresAt = timestamptz(*http.ExpiresAt)
				}
			}
		}
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
		until = parentUntil
		if !browserDeadline.IsZero() {
			until = minTime(until, browserDeadline)
		}
		if decision.ExpiresAt.Valid && decision.ExpiresAt.InfinityModifier == 0 {
			until = minTime(until, decision.ExpiresAt.Time)
		}
		subject = visitortoken.Browser{IdentityID: principal.IdentityID, SessionID: principal.SessionID}
		if !deviceSource {
			browserGrantID = decision.GrantID
		}
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
			result.PublicKey = ed25519.PublicKey(public)
			result.ConnectorUntil = minTime(until, now.Add(2*time.Minute))
		}
	case WorkloadTokenSource:
		if scope.Kind != visitorscope.Service || workloadSource.ID == "" {
			return result, ErrVisitorPermission
		}
		// selected-service membership is an authority-confirmed workload fact,
		// independent of human grants and of which publisher run is ready.
		var selected bool
		err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.workload_sessions w
		    JOIN control.workload_session_services selected ON selected.workload_session_id=w.id AND selected.service_id=$2
		    JOIN control.teams team ON team.id=w.team_id AND team.deleted_at IS NULL
		    JOIN control.applied_projects project ON project.team_id=w.team_id AND project.project_key=w.project_key
		    WHERE w.id=$1 AND w.team_id=$3)`, workloadSource.ID, scope.ID, resource.TeamID).Scan(&selected)
		if err != nil {
			return result, publisherLookupError(err, ErrVisitorPermission)
		}
		if !selected || len(workloadSource.PublicKey) != ed25519.PublicKeySize {
			return result, ErrVisitorPermission
		}
		digest, err := visitortoken.KeyDigest(ed25519.PublicKey(workloadSource.PublicKey))
		if err != nil {
			return result, err
		}
		until = minTime(workloadSource.LeaseExpiresAt, workloadSource.IdentityExpiresAt)
		if workloadSource.ExpiresAt != nil {
			until = minTime(until, *workloadSource.ExpiresAt)
		}
		subject = visitortoken.Workload{SessionID: workloadSource.ID, KeySHA256: digest}
		result.PublicKey = ed25519.PublicKey(workloadSource.PublicKey)
		result.ConnectorUntil = minTime(until, now.Add(WorkloadLease))
		result.WorkloadCredentialUntil = visitorcert.WorkloadDeadline(now, workloadSource.ExpiresAt)
	case RegisteredKeyTokenSource:
		if scope.Kind != visitorscope.Service {
			return result, ErrVisitorPermission
		}
		identity, err := d.authenticatePublisherAccess(ctx, q, supplied.Credential, "", clock.current(), false)
		if err != nil {
			return result, err
		}
		if identity.Scope.TeamID != resource.TeamID || identity.Scope.Kind != DeploymentCredentialGrant {
			return result, ErrVisitorPermission
		}
		facts, err := deploymentConnectAuthority(ctx, tx, identity.GrantID, identity.KeyID, scope.ID, clock.current())
		if err != nil {
			return result, publisherLookupError(err, ErrVisitorPermission)
		}
		digest, err := visitortoken.KeyDigest(ed25519.PublicKey(facts.PublicKey))
		if err != nil {
			return result, err
		}
		accessDigest := sha256.Sum256([]byte(supplied.Credential))
		access, err := q.GetPublisherAccess(ctx, accessDigest[:])
		if err != nil {
			return result, err
		}
		until = minTime(facts.ExpiresAt, access.ExpiresAt.Time)
		subject = visitortoken.RegisteredKey{GrantID: identity.GrantID, KeyID: identity.KeyID, KeySHA256: digest}
		result.PublicKey = ed25519.PublicKey(facts.PublicKey)
		result.ConnectorUntil = minTime(until, now.Add(90*time.Second))
	case ShareTokenSource, ShareSessionTokenSource:
		var shareID, sourceSecret string
		var session bool
		runID := ""
		switch value := supplied.(type) {
		case ShareTokenSource:
			shareID, sourceSecret = value.ShareID, value.Secret
		case ShareSessionTokenSource:
			shareID, sourceSecret, session = value.ShareID, value.Secret, true
			runID = value.RunID
		}
		if scope.Kind != visitorscope.Service {
			return result, ErrVisitorPermission
		}
		until, err = d.shareVisitorPermission(ctx, tx, scope.ID, runID, shareID, sourceSecret, session, now, resource.Hostname)
		if err != nil {
			return result, err
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
		grant, err := currentServiceHTTPGrantAuthority(ctx, tx, scope.ID, grantID, now)
		if err != nil {
			return result, err
		}
		if subtle.ConstantTimeCompare(grant.secretDigest, digest[:]) != 1 {
			return result, ErrVisitorPermission
		}
		subject, until = grant.subject, grant.expiresAt
		explicitLifetime = true
	default:
		return result, ErrVisitorPermission
	}
	if !until.After(clock.current()) {
		if _, workload := source.(WorkloadTokenSource); workload {
			// the source can expire after its locked read while the selected
			// service is checked. retain the source denial at this later fence.
			return result, ErrWorkloadDenied
		}
		return result, ErrVisitorPermission
	}
	result.Permission = resource.permission(subject, until, now)
	result.Permission.BrowserGrantID = browserGrantID
	if explicitLifetime {
		result.Permission.ExpiresAt = until.Truncate(time.Second)
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
	ExpiresAt time.Time
}

// browser sign-in records supply authentication and the captured hostname scope.
// the common permission model makes the resource decision after this boundary.
func (d *Database) browserTokenFacts(ctx context.Context, tx pgx.Tx, scope visitorscope.Scope, secret, hostname string, now time.Time) (result browserTokenFacts, err error) {
	digest, err := browserDigest(secret)
	if err != nil {
		return result, ErrVisitorPermission
	}
	if scope.Kind != visitorscope.Service {
		return result, ErrVisitorPermission
	}
	err = tx.QueryRow(ctx, `SELECT browser.control_session_id,parent.identity_id,
	    LEAST(browser.expires_at,parent.access_expires_at,parent.refresh_expires_at,original.refresh_expires_at)
	    FROM control.service_http_browser_sessions browser
	    JOIN control.control_sessions parent ON parent.id=browser.control_session_id
	    JOIN control.identities person ON person.id=parent.identity_id AND person.disabled_at IS NULL
	    LEFT JOIN control.control_sessions original ON original.id=browser.parent_control_session_id AND original.identity_id=parent.identity_id
	    WHERE browser.token_digest=$2 AND browser.revoked_at IS NULL AND browser.expires_at>$3
	    AND parent.revoked_at IS NULL AND parent.access_expires_at>$3 AND parent.refresh_expires_at>$3
	    AND (browser.parent_control_session_id IS NULL OR original.revoked_at IS NULL AND original.refresh_expires_at>$3)
	    AND EXISTS(SELECT 1 FROM control.service_http_browser_handoffs bound
	        JOIN control.service_runs run ON run.service_id=bound.service_id
	        WHERE bound.session_digest=browser.token_digest AND bound.service_id=$1 AND bound.consumed_at IS NOT NULL
	        AND bound.hostname=$4 AND ($4=(SELECT certificate_hostname FROM control.services WHERE id=$1)
	            OR control.service_run_alias_current(run.id,$4))
	        AND bound.revoked_at IS NULL AND run.state='ready' AND run.healthy AND run.closed_at IS NULL
	        AND run.publisher_expires_at>$3 AND run.certificate_expires_at>$3
	        AND EXISTS(SELECT 1 FROM control.publisher_service_permission(run.publisher_identity_id,
	            run.publisher_grant_id,run.service_id,$3) permission
	            JOIN control.publisher_grants grant_record ON grant_record.id=run.publisher_grant_id
	            JOIN control.publisher_identity_keys signing ON signing.id=run.publisher_key_id
	                AND signing.publisher_identity_id=run.publisher_identity_id
	                AND (grant_record.kind='service' OR signing.retired_at IS NULL)))
	    FOR SHARE OF browser,parent`, scope.ID, digest, now, hostname).Scan(&result.Principal.SessionID, &result.Principal.IdentityID, &result.ExpiresAt)
	return result, publisherLookupError(err, ErrVisitorPermission)
}
