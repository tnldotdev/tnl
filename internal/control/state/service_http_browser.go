package state

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/policy/serviceendpoint"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

const browserSessionLifetime = 24 * time.Hour

type BrowserLoginAttempt struct {
	Subject       visitorscope.Scope
	ServiceRunIDs []string
	PreviewID     string
	CompanyIntent *CompanyIntentBinding
	ReturnPath    string
	Nonce         string
	Verifier      string
}

type BrowserAccessSession struct {
	ParentControlSessionID string
	IdentityID             string
	DisplayName            string
	AccessToken            string
	RefreshToken           string
	AccessExpiresAt        time.Time
	ExpiresAt              time.Time
}

type BrowserTokenRotation struct {
	IdentityID      string
	AccessToken     string
	RefreshToken    string
	AccessExpiresAt time.Time
}

type BrowserHandoff struct {
	Origin     string
	Token      string
	ReturnPath string
}

func randomBrowserSecret() (string, []byte, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, err
	}
	return base64.RawURLEncoding.EncodeToString(raw), raw, nil
}

func browserDigest(token string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != token {
		return nil, ErrPreviewAccess
	}
	digest := sha256.Sum256(raw)
	return digest[:], nil
}

func browserContext(digest []byte) string { return "browser-access:" + hex.EncodeToString(digest) }

// ServiceHTTPRun carries an exact service/run credential. browser/share scopes
// cannot be interpreted as publisher permission.
type ServiceHTTPRun struct {
	Subject visitorscope.Scope
	RunID   string
	Number  int64
	Token   credentials.ServiceRunToken
}

func (a ServiceHTTPRun) valid() bool {
	_, err := credentials.ParseServiceRunToken(a.Token)
	return a.Subject.Kind == visitorscope.Service && a.Subject.Valid() && opaqueid.Valid(a.RunID, opaqueid.ServiceRunPrefix) && a.Number > 0 && err == nil
}

func (d *Database) lockServiceHTTPRun(ctx context.Context, tx pgx.Tx, auth ServiceHTTPRun, now time.Time) error {
	if !auth.valid() {
		return ErrServiceAccess
	}
	if err := lockServiceAdmission(ctx, tx, auth.Subject.ID); err != nil {
		return err
	}
	q := controlstatedb.New(tx)
	run, err := d.serviceRunAuthorization(ctx, tx, q, auth.Subject.ID, auth.RunID, auth.Token.String(), now)
	if err != nil {
		return err
	}
	return validateServiceHTTPRun(ctx, q, auth, run, now)
}

func validateServiceHTTPRun(ctx context.Context, q *controlstatedb.Queries, auth ServiceHTTPRun, run controlstatedb.ControlServiceRun, now time.Time) error {
	if run.RunNumber != auth.Number || run.State != "ready" || !run.Healthy || !run.CertificateExpiresAt.Time.After(now) {
		return ErrServiceAccess
	}
	endpoint, err := q.ServiceHTTPBrowserEndpoint(ctx, controlstatedb.ServiceHTTPBrowserEndpointParams{ServiceID: auth.Subject.ID, Now: timestamptz(now)})
	if err != nil {
		return publisherLookupError(err, ErrServiceAccess)
	}
	if !slices.Contains(endpoint.RunIds, auth.RunID) {
		return ErrServiceAccess
	}
	observability.AuthenticatedServerScope(ctx, observability.Identity{TeamID: run.TeamID.String, PublisherIdentityID: run.PublisherIdentityID, ServiceID: run.ServiceID}, observability.Fields{Component: "control", ServiceProtocol: observability.ProtocolHTTP})
	return nil
}

func serviceHTTPOrigin(endpoint controlstatedb.ServiceHTTPBrowserEndpointRow) (string, error) {
	if !endpoint.ServicePort.Valid || !serviceendpoint.Valid("http", endpoint.CertificateHostname, int(endpoint.ServicePort.Int32), false) {
		return "", ErrServiceAccess
	}
	return "https://" + endpoint.CertificateHostname, nil
}

func (d *Database) ServiceHTTPBrowserTeam(ctx context.Context, subject visitorscope.Scope, now time.Time) (string, error) {
	if subject.Kind != visitorscope.Service || !subject.Valid() {
		return "", ErrServiceAccess
	}
	endpoint, err := controlstatedb.New(d.pool).ServiceHTTPBrowserEndpoint(ctx, controlstatedb.ServiceHTTPBrowserEndpointParams{ServiceID: subject.ID, Now: timestamptz(now)})
	if err != nil {
		return "", publisherLookupError(err, ErrServiceAccess)
	}
	if len(endpoint.RunIds) == 0 {
		return "", ErrServiceAccess
	}
	return endpoint.TeamID.String, nil
}

func (d *Database) BeginServiceBrowserLogin(ctx context.Context, subject visitorscope.Scope, preview, path, nonce, verifier string, binding []byte, intent *CompanyLoginIntent, now time.Time) (string, error) {
	if subject.Kind != visitorscope.Service || !subject.Valid() || !naming.ValidRequestPath(path) || len(path) > 2048 || len(nonce) < 16 || len(nonce) > 256 || len(verifier) < 43 || len(verifier) > 128 || len(binding) != 32 || d.storageKey == nil {
		return "", ErrPreviewAccess
	}
	q := controlstatedb.New(d.pool)
	endpoint, err := q.ServiceHTTPBrowserEndpoint(ctx, controlstatedb.ServiceHTTPBrowserEndpointParams{ServiceID: subject.ID, Now: timestamptz(now)})
	if err != nil {
		return "", publisherLookupError(err, ErrServiceAccess)
	}
	if len(endpoint.RunIds) == 0 {
		return "", ErrServiceAccess
	}
	state, _, err := randomBrowserSecret()
	if err != nil {
		return "", err
	}
	digest, _ := browserDigest(state)
	if preview != "" {
		included, err := q.ListPreviewServices(ctx, preview)
		if err != nil || !slices.Contains(included, subject.ID) {
			return "", ErrPreviewAccess
		}
	}
	private := BrowserLoginAttempt{Verifier: verifier, Subject: subject, PreviewID: preview}
	if intent != nil {
		private.CompanyIntent = &CompanyIntentBinding{ID: intent.ID, BindingToken: intent.BindingToken, RedirectURI: intent.RedirectURI}
	}
	plain, err := json.Marshal(private)
	if err != nil {
		return "", err
	}
	sealed, err := d.storageKey.Seal(browserContext(digest), plain)
	if err != nil {
		return "", err
	}
	bindingDigest := sha256.Sum256(binding)
	err = q.InsertServiceHTTPBrowserLogin(ctx, controlstatedb.InsertServiceHTTPBrowserLoginParams{StateDigest: digest, BindingDigest: bindingDigest[:], ServiceID: subject.ID, RunIds: endpoint.RunIds, ReturnPath: path, Nonce: nonce, VerifierCiphertext: sealed, StorageKeyID: d.storageKey.CurrentID(), ExpiresAt: timestamptz(now.Add(5 * time.Minute))})
	return state, err
}

func (d *Database) ConsumeBrowserLogin(ctx context.Context, state string, binding []byte, now time.Time) (BrowserLoginAttempt, error) {
	digest, err := browserDigest(state)
	if err != nil || len(binding) != 32 || d.storageKey == nil {
		return BrowserLoginAttempt{}, ErrPreviewAccess
	}
	bindingDigest := sha256.Sum256(binding)
	row, err := controlstatedb.New(d.pool).ConsumeServiceHTTPBrowserLogin(ctx, controlstatedb.ConsumeServiceHTTPBrowserLoginParams{StateDigest: digest, BindingDigest: bindingDigest[:], Now: timestamptz(now)})
	if err != nil {
		return BrowserLoginAttempt{}, publisherLookupError(err, ErrPreviewAccess)
	}
	plain, _, err := d.storageKey.Open(row.StorageKeyID, browserContext(digest), row.VerifierCiphertext)
	if err != nil {
		return BrowserLoginAttempt{}, err
	}
	var result BrowserLoginAttempt
	if err := json.Unmarshal(plain, &result); err != nil {
		return result, err
	}
	if result.Subject != (visitorscope.Scope{Kind: visitorscope.Service, ID: row.ServiceID}) {
		return BrowserLoginAttempt{}, ErrPreviewAccess
	}
	result.ServiceRunIDs, result.ReturnPath, result.Nonce = row.RunIds, row.ReturnPath, row.Nonce
	return result, nil
}

func (d *Database) IssueBrowserHandoff(ctx context.Context, attempt BrowserLoginAttempt, session BrowserAccessSession, now time.Time) (result BrowserHandoff, retErr error) {
	if attempt.Subject.Kind != visitorscope.Service || !attempt.Subject.Valid() || len(attempt.ServiceRunIDs) == 0 || !session.ExpiresAt.After(now) || session.RefreshToken == "" || d.storageKey == nil {
		return result, ErrPreviewAccess
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "issue managed browser handoff", &retErr)()
	if err = lockServiceAdmission(ctx, tx, attempt.Subject.ID); err != nil {
		return result, err
	}
	q := controlstatedb.New(tx)
	if _, err = currentVisitorSession(ctx, q, session.AccessToken, session.IdentityID, session.ParentControlSessionID, now); err != nil {
		return result, err
	}
	sessionID, _, err := credentials.ParseAccessToken(credentials.AccessToken(session.AccessToken))
	if err != nil {
		return result, ErrVisitorSignIn
	}
	controlSession, err := q.LockVisitorControlSession(ctx, sessionID.String())
	if err != nil {
		return result, err
	}
	ctx = WithControlPrincipal(ctx, ControlPrincipal{SessionID: controlSession.ID, IdentityID: session.IdentityID})
	if _, err = d.serviceHTTPIdentityPermission(ctx, tx, attempt.Subject.ID, session.IdentityID, now); err != nil {
		return result, err
	}
	endpoint, err := q.ServiceHTTPBrowserEndpoint(ctx, controlstatedb.ServiceHTTPBrowserEndpointParams{ServiceID: attempt.Subject.ID, Now: timestamptz(now)})
	if err != nil {
		return result, err
	}
	runs := slices.DeleteFunc(slices.Clone(attempt.ServiceRunIDs), func(id string) bool { return !slices.Contains(endpoint.RunIds, id) })
	if len(runs) == 0 {
		return result, ErrPreviewAccess
	}
	result.Origin, err = serviceHTTPOrigin(endpoint)
	if err != nil {
		return result, err
	}
	cookie, _, err := randomBrowserSecret()
	if err != nil {
		return result, err
	}
	digest, _ := browserDigest(cookie)
	refresh, err := d.storageKey.Seal(browserContext(digest), []byte(session.RefreshToken))
	if err != nil {
		return result, err
	}
	until := minTime(session.ExpiresAt, controlSession.RefreshExpiresAt.Time)
	until = minTime(until, now.Add(browserSessionLifetime))
	err = q.InsertServiceHTTPBrowserSession(ctx, controlstatedb.InsertServiceHTTPBrowserSessionParams{TokenDigest: digest, ControlSessionID: controlSession.ID, ParentControlSessionID: nullableText(session.ParentControlSessionID), ExpiresAt: timestamptz(until), RefreshCiphertext: refresh, StorageKeyID: d.storageKey.CurrentID()})
	if err != nil {
		return result, err
	}
	hosts, err := q.ReadyServiceBrowserHosts(ctx, controlstatedb.ReadyServiceBrowserHostsParams{ServiceID: attempt.Subject.ID, PreviewID: attempt.PreviewID, Now: timestamptz(now)})
	if err != nil {
		return result, err
	}
	next := result.Origin + attempt.ReturnPath
	issue := func(service string, captured []string, redirect string, bridge bool) (string, error) {
		ticket, _, err := randomBrowserSecret()
		if err != nil {
			return "", err
		}
		ticketDigest, _ := browserDigest(ticket)
		sealed, err := d.storageKey.Seal(browserContext(ticketDigest), []byte(cookie))
		if err != nil {
			return "", err
		}
		err = q.InsertServiceHTTPBrowserHandoff(ctx, controlstatedb.InsertServiceHTTPBrowserHandoffParams{
			TokenDigest: ticketDigest, SessionDigest: digest, ServiceID: service, RunIds: captured,
			CookieCiphertext: sealed, StorageKeyID: d.storageKey.CurrentID(), ReturnPath: attempt.ReturnPath,
			RedirectUrl: redirect, Bridge: bridge, ExpiresAt: timestamptz(minTime(until, now.Add(time.Minute))),
		})
		return ticket, err
	}
	for index, host := range hosts {
		if host.ServiceID == attempt.Subject.ID {
			continue
		}
		ticket, err := issue(host.ServiceID, host.RunIds, next, index%8 == 7)
		if err != nil {
			return result, err
		}
		next = "https://" + host.CertificateHostname + "/__tnl/team/handoff/" + ticket
	}
	result.Token, err = issue(attempt.Subject.ID, runs, next, false)
	if err != nil {
		return result, err
	}
	result.ReturnPath = attempt.ReturnPath
	return result, tx.Commit(ctx)
}

// callers validate their exact current service run before consulting the
// service-bound browser identity. only one-use handoffs retain run captures.
func (d *Database) serviceBrowserPermission(ctx context.Context, tx pgx.Tx, service string, digest []byte, now time.Time) (VisitorPermission, error) {
	row, err := controlstatedb.New(tx).ServiceHTTPBrowserPermission(ctx, controlstatedb.ServiceHTTPBrowserPermissionParams{ServiceID: service, CookieDigest: digest, Now: timestamptz(now)})
	if err != nil {
		return VisitorPermission{}, publisherLookupError(err, ErrVisitorSignIn)
	}
	ctx = WithControlPrincipal(ctx, ControlPrincipal{SessionID: row.ControlSessionID, IdentityID: row.IdentityID})
	result, err := d.serviceHTTPIdentityPermission(ctx, tx, service, row.IdentityID, now)
	if err != nil {
		return VisitorPermission{}, err
	}
	result.ExpiresAt = earlierVisitorExpiry(result.ExpiresAt, row.ExpiresAt.Time)
	return result, nil
}

// authentication survives a denied visitor decision. preview team access is
// evaluated only here, never by connector, device, or workload authorization.
func (d *Database) serviceHTTPIdentityPermission(ctx context.Context, tx pgx.Tx, service, identity string, now time.Time) (VisitorPermission, error) {
	q := controlstatedb.New(tx)
	result := VisitorPermission{}
	person, err := q.LockVisitorIdentity(ctx, identity)
	if err != nil {
		return result, publisherLookupError(err, ErrVisitorSignIn)
	}
	s, err := q.GetService(ctx, service)
	if err != nil {
		return result, publisherLookupError(err, ErrServiceAccess)
	}
	if s.Protocol != "http" || !s.Enabled || s.DeletedAt.Valid {
		return result, ErrServiceAccess
	}
	session := companySessionID(ctx, identity)
	allowed, err := q.CompanySubjectSessionAuthorized(ctx, controlstatedb.CompanySubjectSessionAuthorizedParams{TeamID: s.TeamID.String, IdentityID: identity, SessionID: session, Now: timestamptz(now)})
	if err != nil {
		return result, err
	}
	if !allowed {
		return result, ErrVisitorSignIn
	}
	result.Authenticated, result.IdentityID, result.DisplayName = true, identity, person.DisplayName
	membership, err := q.VisitorCurrentMembership(ctx, controlstatedb.VisitorCurrentMembershipParams{TeamID: s.TeamID.String, IdentityID: identity})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return result, err
	}
	result.TeamMember = err == nil
	permission, err := q.VisitorPermission(ctx, controlstatedb.VisitorPermissionParams{ResourceKind: "service", ResourceID: service, IdentityID: identity, ControlSessionID: session, Now: timestamptz(now)})
	if err == nil {
		result.VisitAllowed, result.Reason = true, permission.Reason
		if permission.ExpiresAt.InfinityModifier == 0 {
			result.ExpiresAt = optionalTime(permission.ExpiresAt)
		}
		return result, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return result, err
	}
	// current stored namespace ownership restores HTTP browser access only.
	// connector/device and portable HTTP-grant permission still use the generic
	// visitor rule above, not this path-specific decision.
	if result.TeamMember {
		owner, ownerErr := storedServiceSourceOwner(ctx, tx, s, false)
		if ownerErr != nil && !errors.Is(ownerErr, ErrServiceAccess) {
			return result, ownerErr
		}
		if ownerErr == nil && (owner.scope == NamespaceScopeShared || owner.membership == membership) {
			facts, factsErr := serviceHostnameAuthority(ctx, tx, s.TeamID.String, identity, s.DomainID.String, now)
			if factsErr != nil && !errors.Is(factsErr, ErrServiceAccess) {
				return result, factsErr
			}
			if factsErr == nil {
				ownershipErr := d.authorizeOwnedServiceHostname(ctx, tx, facts, owner, s.TeamID.String, s.DomainID.String, s.CertificateHostname, now)
				if ownershipErr != nil && !errors.Is(ownershipErr, ErrServiceAccess) {
					return result, ownershipErr
				}
				if ownershipErr == nil {
					var deadline pgtype.Timestamptz
					if err := tx.QueryRow(ctx, `SELECT control.company_subject_deadline($1,$2,$3,$4)`,
						s.TeamID.String, identity, session, now).Scan(&deadline); err != nil {
						return result, err
					}
					result.VisitAllowed, result.Reason = true, "owner"
					if deadline.InfinityModifier == 0 {
						result.ExpiresAt = optionalTime(deadline)
					}
					return result, nil
				}
			}
		}
	}
	deadline, err := q.ServiceHTTPPreviewTeamPermission(ctx, controlstatedb.ServiceHTTPPreviewTeamPermissionParams{ServiceID: service, IdentityID: identity, ControlSessionID: session, Now: timestamptz(now)})
	if err == nil {
		result.VisitAllowed, result.Reason = true, "preview_team"
		if deadline.InfinityModifier == 0 {
			result.ExpiresAt = optionalTime(deadline)
		}
		return result, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return result, err
	}
	settings, err := d.serviceHTTPSettings(ctx, q, service)
	if err != nil {
		return result, err
	}
	if settings != nil && settings.Access != nil && settings.Access.VisitorMode() == "anonymous" {
		result.VisitAllowed, result.Reason = true, "anonymous"
	}
	return result, nil
}

func (d *Database) RedeemServiceBrowserHandoff(ctx context.Context, auth ServiceHTTPRun, ticket string, now time.Time) (result controlv1.BrowserHandoffResponse, retErr error) {
	digest, err := browserDigest(ticket)
	if err != nil {
		return result, ErrVisitorSignIn
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "redeem managed browser handoff", &retErr)()
	if err = d.lockServiceHTTPRun(ctx, tx, auth, now); err != nil {
		return result, err
	}
	row, err := controlstatedb.New(tx).RedeemServiceHTTPBrowserHandoff(ctx, controlstatedb.RedeemServiceHTTPBrowserHandoffParams{TokenDigest: digest, ServiceID: auth.Subject.ID, ServiceRunID: auth.RunID, Now: timestamptz(now)})
	if err != nil {
		return result, publisherLookupError(err, ErrVisitorSignIn)
	}
	cookie, _, err := d.storageKey.Open(row.StorageKeyID, browserContext(digest), row.CookieCiphertext)
	if err != nil {
		return result, err
	}
	if _, err = d.serviceBrowserPermission(ctx, tx, auth.Subject.ID, row.SessionDigest, now); err != nil {
		return result, err
	}
	result = controlv1.BrowserHandoffResponse{CookieSecret: string(cookie), ReturnPath: row.ReturnPath, NextUrl: &row.RedirectUrl, Bridge: &row.Bridge, ExpiresAt: row.ExpiresAt.Time}
	return result, tx.Commit(ctx)
}

func (d *Database) ServiceBrowserSession(ctx context.Context, auth ServiceHTTPRun, secret string, revoke bool, now time.Time) (result VisitorPermission, retErr error) {
	digest, err := browserDigest(secret)
	if err != nil {
		return result, ErrVisitorSignIn
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "check managed browser session", &retErr)()
	if err = d.lockServiceHTTPRun(ctx, tx, auth, now); err != nil {
		return result, err
	}
	if revoke {
		err = controlstatedb.New(tx).RevokeServiceHTTPBrowserSession(ctx, controlstatedb.RevokeServiceHTTPBrowserSessionParams{ServiceID: auth.Subject.ID, CookieDigest: digest, Now: timestamptz(now)})
	} else {
		result, err = d.serviceBrowserPermission(ctx, tx, auth.Subject.ID, digest, now)
	}
	if errors.Is(err, ErrServiceAccess) {
		err = ErrVisitorSignIn
	}
	if err != nil {
		return result, err
	}
	return result, tx.Commit(ctx)
}

// the browser row serializes refresh without locking the parent session that
// the authority must rotate. contenders release their connection before retrying
// so they cannot exhaust the authority's pool. the row can stay locked during
// an authority network request, so busy-row retries have a longer, capped budget
// than local visitor preparation. service and expiry remain fixed.
func (d *Database) RefreshServiceBrowserSession(ctx context.Context, service, secret string, now time.Time,
	refresh func(context.Context, string) (BrowserTokenRotation, error)) (BrowserAccessSession, error) {
	result, err := retryVisitorPreparationWithLockAttempts(ctx, now, 64, func(at time.Time) (BrowserAccessSession, error) {
		return d.refreshServiceBrowserSession(ctx, service, secret, at, refresh)
	})
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr != nil && pgErr.Code == "55P03" {
		err = errors.Join(ErrVisitorPolicy, err)
	}
	return result, err
}

func (d *Database) refreshServiceBrowserSession(ctx context.Context, service, secret string, now time.Time,
	refresh func(context.Context, string) (BrowserTokenRotation, error)) (result BrowserAccessSession, retErr error) {
	digest, err := browserDigest(secret)
	if err != nil || d.storageKey == nil {
		return result, ErrPreviewAccess
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "refresh service browser session", &retErr)()
	q := controlstatedb.New(tx)
	if _, err := q.LockServiceHTTPBrowserSession(ctx, digest); err != nil {
		return result, publisherLookupError(err, ErrPreviewAccess)
	}
	// read the parent under a fresh statement snapshot after taking the browser
	// lock. a locking join can pair updated ciphertext with an old parent expiry.
	// locking the parent instead would block the authority's own rotation.
	row, err := q.ReadServiceHTTPBrowserSession(ctx, controlstatedb.ReadServiceHTTPBrowserSessionParams{ServiceID: service, CookieDigest: digest, ExpiresAt: timestamptz(now)})
	if err != nil {
		return result, publisherLookupError(err, ErrPreviewAccess)
	}
	if row.ParentRevokedAt.Valid || !row.RefreshExpiresAt.Time.After(now) {
		return result, ErrPreviewAccess
	}
	result = BrowserAccessSession{IdentityID: row.IdentityID, DisplayName: row.DisplayName, AccessExpiresAt: row.AccessExpiresAt.Time,
		ExpiresAt: minTime(row.ExpiresAt.Time, row.RefreshExpiresAt.Time)}
	if !result.AccessExpiresAt.After(now.Add(30 * time.Second)) {
		secret, _, err := d.storageKey.Open(row.StorageKeyID, browserContext(row.TokenDigest), row.RefreshCiphertext)
		if err != nil {
			return result, err
		}
		rotated, err := refresh(ctx, string(secret))
		if err != nil {
			return result, err
		}
		principal, err := d.authenticateAccessToken(ctx, q, credentials.AccessToken(rotated.AccessToken), now)
		if err != nil || principal.SessionID != row.ControlSessionID || principal.IdentityID != row.IdentityID || rotated.IdentityID != row.IdentityID || rotated.RefreshToken == "" || !rotated.AccessExpiresAt.After(now) {
			return result, ErrPreviewAccess
		}
		sealed, err := d.storageKey.Seal(browserContext(row.TokenDigest), []byte(rotated.RefreshToken))
		if err != nil {
			return result, err
		}
		if err := q.RotateServiceHTTPBrowserSession(ctx, controlstatedb.RotateServiceHTTPBrowserSessionParams{TokenDigest: row.TokenDigest, RefreshCiphertext: sealed, StorageKeyID: d.storageKey.CurrentID()}); err != nil {
			return result, err
		}
		result.AccessExpiresAt = rotated.AccessExpiresAt
	}
	return result, tx.Commit(ctx)
}
