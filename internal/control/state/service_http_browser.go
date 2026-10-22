package state

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net"
	"slices"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/policy/httpsubject"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// ServiceHTTPRun carries an exact service/run credential. public URL run tokens
// and browser/share scopes cannot be interpreted as service permission.
type ServiceHTTPRun struct {
	Subject httpsubject.Subject
	RunID   string
	Number  int64
	Token   credentials.ServiceRunToken
}

func (a ServiceHTTPRun) valid() bool {
	_, err := credentials.ParseServiceRunToken(a.Token)
	return a.Subject.Kind == httpsubject.Service && a.Subject.Valid() && opaqueid.Valid(a.RunID, opaqueid.ServiceRunPrefix) && a.Number > 0 && err == nil
}

func (d *Database) lockServiceHTTPRun(ctx context.Context, tx pgx.Tx, auth ServiceHTTPRun, now time.Time) error {
	if !auth.valid() {
		return ErrServiceAccess
	}
	if err := lockServiceAdmission(ctx, tx, auth.Subject.ID); err != nil {
		return err
	}
	q := controlstatedb.New(tx)
	run, err := serviceRunAuthorization(ctx, tx, q, auth.Subject.ID, auth.RunID, auth.Token.String(), now)
	if err != nil {
		return err
	}
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
	observability.AuthenticatedServerScope(ctx, observability.Identity{TeamID: run.TeamID, PublisherIdentityID: run.PublisherIdentityID, ServiceID: run.ServiceID}, observability.Fields{Component: "control", ServiceProtocol: observability.ProtocolHTTP})
	return nil
}

func serviceHTTPOrigin(endpoint controlstatedb.ServiceHTTPBrowserEndpointRow) (string, error) {
	if endpoint.CertificateHostname == "" || !endpoint.ServicePort.Valid || endpoint.ServicePort.Int32 < 1024 || endpoint.ServicePort.Int32 > 65535 {
		return "", ErrServiceAccess
	}
	return "https://" + net.JoinHostPort(endpoint.CertificateHostname, strconv.Itoa(int(endpoint.ServicePort.Int32))), nil
}

func (d *Database) ServiceHTTPBrowserTeam(ctx context.Context, subject httpsubject.Subject, now time.Time) (string, error) {
	if subject.Kind != httpsubject.Service || !subject.Valid() {
		return "", ErrServiceAccess
	}
	endpoint, err := controlstatedb.New(d.pool).ServiceHTTPBrowserEndpoint(ctx, controlstatedb.ServiceHTTPBrowserEndpointParams{ServiceID: subject.ID, Now: timestamptz(now)})
	if err != nil {
		return "", publisherLookupError(err, ErrServiceAccess)
	}
	if len(endpoint.RunIds) == 0 {
		return "", ErrServiceAccess
	}
	return endpoint.TeamID, nil
}

func (d *Database) BeginServiceBrowserLogin(ctx context.Context, subject httpsubject.Subject, path, nonce, verifier string, binding []byte, intent *CompanyLoginIntent, now time.Time) (string, error) {
	if subject.Kind != httpsubject.Service || !subject.Valid() || !validFeedbackPath(path) || len(path) > 2048 || len(nonce) < 16 || len(nonce) > 256 || len(verifier) < 43 || len(verifier) > 128 || len(binding) != 32 || d.storageKey == nil {
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
	private := BrowserLoginAttempt{Verifier: verifier, Subject: subject}
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

func (d *Database) consumeServiceBrowserLogin(ctx context.Context, digest, binding []byte, now time.Time) (BrowserLoginAttempt, error) {
	row, err := controlstatedb.New(d.pool).ConsumeServiceHTTPBrowserLogin(ctx, controlstatedb.ConsumeServiceHTTPBrowserLoginParams{StateDigest: digest, BindingDigest: binding, Now: timestamptz(now)})
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
	if result.Subject != (httpsubject.Subject{Kind: httpsubject.Service, ID: row.ServiceID}) {
		return BrowserLoginAttempt{}, ErrPreviewAccess
	}
	result.ServiceRunIDs, result.ReturnPath, result.Nonce = row.RunIds, row.ReturnPath, row.Nonce
	return result, nil
}

func (d *Database) issueServiceBrowserHandoff(ctx context.Context, attempt BrowserLoginAttempt, session BrowserAccessSession, now time.Time) (result BrowserHandoff, retErr error) {
	if !attempt.Subject.Valid() || len(attempt.ServiceRunIDs) == 0 || !session.ExpiresAt.After(now) {
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
	if _, err = currentVisitorSession(ctx, q, session.AccessToken, session.IdentityID, "", now); err != nil {
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
	if _, _, err = privateVisitorAccess(ctx, tx, attempt.Subject.ID, session.IdentityID, now); err != nil {
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
	result.Token, _, err = randomBrowserSecret()
	if err != nil {
		return result, err
	}
	digest, _ := browserDigest(result.Token)
	err = q.InsertServiceHTTPBrowserSession(ctx, controlstatedb.InsertServiceHTTPBrowserSessionParams{HandoffDigest: digest, ServiceID: attempt.Subject.ID, RunIds: runs, ControlSessionID: controlSession.ID, ReturnPath: attempt.ReturnPath, HandoffExpiresAt: timestamptz(now.Add(time.Minute)), ExpiresAt: timestamptz(minTime(session.ExpiresAt, now.Add(browserSessionLifetime)))})
	if err != nil {
		return result, err
	}
	result.ReturnPath = attempt.ReturnPath
	return result, tx.Commit(ctx)
}

func serviceBrowserPermission(ctx context.Context, tx pgx.Tx, service, run string, digest []byte, now time.Time) (VisitorPermission, error) {
	row, err := controlstatedb.New(tx).ServiceHTTPBrowserPermission(ctx, controlstatedb.ServiceHTTPBrowserPermissionParams{ServiceID: service, ServiceRunID: run, CookieDigest: digest, Now: timestamptz(now)})
	if err != nil {
		return VisitorPermission{}, publisherLookupError(err, ErrVisitorSignIn)
	}
	ctx = WithControlPrincipal(ctx, ControlPrincipal{SessionID: row.ControlSessionID, IdentityID: row.IdentityID})
	until, _, err := privateVisitorAccess(ctx, tx, service, row.IdentityID, now)
	if err != nil {
		return VisitorPermission{}, err
	}
	until = minTime(until, row.ExpiresAt.Time)
	q := controlstatedb.New(tx)
	s, err := q.GetService(ctx, service)
	if err != nil {
		return VisitorPermission{}, err
	}
	_, err = q.VisitorCurrentMembership(ctx, controlstatedb.VisitorCurrentMembershipParams{TeamID: s.TeamID, IdentityID: row.IdentityID})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return VisitorPermission{}, err
	}
	return VisitorPermission{Authenticated: true, TeamMember: err == nil, IdentityID: row.IdentityID, DisplayName: row.DisplayName, VisitAllowed: true, Reason: "service_browser", ExpiresAt: &until}, nil
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
	cookie, _, err := randomBrowserSecret()
	if err != nil {
		return result, err
	}
	cookieDigest, _ := browserDigest(cookie)
	row, err := controlstatedb.New(tx).RedeemServiceHTTPBrowserSession(ctx, controlstatedb.RedeemServiceHTTPBrowserSessionParams{HandoffDigest: digest, CookieDigest: cookieDigest, ServiceID: auth.Subject.ID, ServiceRunID: auth.RunID, Now: timestamptz(now)})
	if err != nil {
		return result, publisherLookupError(err, ErrVisitorSignIn)
	}
	if _, err = serviceBrowserPermission(ctx, tx, auth.Subject.ID, auth.RunID, cookieDigest, now); err != nil {
		return result, err
	}
	result = controlv1.BrowserHandoffResponse{CookieSecret: cookie, ReturnPath: row.ReturnPath, ExpiresAt: row.ExpiresAt.Time}
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
		err = controlstatedb.New(tx).RevokeServiceHTTPBrowserSession(ctx, controlstatedb.RevokeServiceHTTPBrowserSessionParams{ServiceID: auth.Subject.ID, ServiceRunID: auth.RunID, CookieDigest: digest, Now: timestamptz(now)})
	} else {
		result, err = serviceBrowserPermission(ctx, tx, auth.Subject.ID, auth.RunID, digest, now)
	}
	if errors.Is(err, ErrServiceAccess) {
		err = ErrVisitorSignIn
	}
	if err != nil {
		return result, err
	}
	return result, tx.Commit(ctx)
}
