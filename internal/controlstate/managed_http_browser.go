package controlstate

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
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/httpsubject"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

// ManagedHTTPRun carries an exact service/run credential. public URL run tokens
// and browser/share scopes cannot be interpreted as managed service permission.
type ManagedHTTPRun struct {
	Subject httpsubject.Subject
	RunID   string
	Number  int64
	Token   credentials.PublishRunToken
}

func (a ManagedHTTPRun) valid() bool {
	return a.Subject.Kind == httpsubject.ManagedService && a.Subject.Valid() && opaqueid.Valid(a.RunID, opaqueid.PrivateRunPrefix) && a.Number > 0 && a.Token != ""
}

func (d *Database) lockManagedHTTPRun(ctx context.Context, tx pgx.Tx, auth ManagedHTTPRun, now time.Time) error {
	if !auth.valid() {
		return ErrPrivateServiceAccess
	}
	if err := lockPrivateAdmission(ctx, tx, auth.Subject.ID); err != nil {
		return err
	}
	q := controlstatedb.New(tx)
	run, err := privateRunAuthorization(ctx, tx, q, auth.Subject.ID, auth.RunID, auth.Token.String(), now)
	if err != nil {
		return err
	}
	if run.RunNumber != auth.Number || run.State != "ready" || !run.Healthy || !run.CertificateExpiresAt.Time.After(now) {
		return ErrPrivateServiceAccess
	}
	endpoint, err := q.ManagedHTTPBrowserEndpoint(ctx, controlstatedb.ManagedHTTPBrowserEndpointParams{PrivateServiceID: auth.Subject.ID, Now: timestamptz(now)})
	if err != nil {
		return publisherLookupError(err, ErrPrivateServiceAccess)
	}
	if !slices.Contains(endpoint.RunIds, auth.RunID) {
		return ErrPrivateServiceAccess
	}
	return nil
}

func managedHTTPOrigin(endpoint controlstatedb.ManagedHTTPBrowserEndpointRow) (string, error) {
	if endpoint.CertificateHostname == "" || !endpoint.ServicePort.Valid || endpoint.ServicePort.Int32 < 1024 || endpoint.ServicePort.Int32 > 65535 {
		return "", ErrPrivateServiceAccess
	}
	return "https://" + net.JoinHostPort(endpoint.CertificateHostname, strconv.Itoa(int(endpoint.ServicePort.Int32))), nil
}

func (d *Database) ManagedHTTPBrowserTeam(ctx context.Context, subject httpsubject.Subject, now time.Time) (string, error) {
	if subject.Kind != httpsubject.ManagedService || !subject.Valid() {
		return "", ErrPrivateServiceAccess
	}
	endpoint, err := controlstatedb.New(d.pool).ManagedHTTPBrowserEndpoint(ctx, controlstatedb.ManagedHTTPBrowserEndpointParams{PrivateServiceID: subject.ID, Now: timestamptz(now)})
	if err != nil {
		return "", publisherLookupError(err, ErrPrivateServiceAccess)
	}
	if len(endpoint.RunIds) == 0 {
		return "", ErrPrivateServiceAccess
	}
	return endpoint.TeamID, nil
}

func (d *Database) BeginManagedBrowserLogin(ctx context.Context, subject httpsubject.Subject, path, nonce, verifier string, binding []byte, intent *CompanyLoginIntent, now time.Time) (string, error) {
	if subject.Kind != httpsubject.ManagedService || !subject.Valid() || !validFeedbackPath(path) || len(path) > 2048 || len(nonce) < 16 || len(nonce) > 256 || len(verifier) < 43 || len(verifier) > 128 || len(binding) != 32 || d.storageKey == nil {
		return "", ErrPreviewAccess
	}
	q := controlstatedb.New(d.pool)
	endpoint, err := q.ManagedHTTPBrowserEndpoint(ctx, controlstatedb.ManagedHTTPBrowserEndpointParams{PrivateServiceID: subject.ID, Now: timestamptz(now)})
	if err != nil {
		return "", publisherLookupError(err, ErrPrivateServiceAccess)
	}
	if len(endpoint.RunIds) == 0 {
		return "", ErrPrivateServiceAccess
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
	err = q.InsertManagedHTTPBrowserLogin(ctx, controlstatedb.InsertManagedHTTPBrowserLoginParams{StateDigest: digest, BindingDigest: bindingDigest[:], PrivateServiceID: subject.ID, RunIds: endpoint.RunIds, ReturnPath: path, Nonce: nonce, VerifierCiphertext: sealed, StorageKeyID: d.storageKey.CurrentID(), ExpiresAt: timestamptz(now.Add(5 * time.Minute))})
	return state, err
}

func (d *Database) consumeManagedBrowserLogin(ctx context.Context, digest, binding []byte, now time.Time) (BrowserLoginAttempt, error) {
	row, err := controlstatedb.New(d.pool).ConsumeManagedHTTPBrowserLogin(ctx, controlstatedb.ConsumeManagedHTTPBrowserLoginParams{StateDigest: digest, BindingDigest: binding, Now: timestamptz(now)})
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
	if result.Subject != (httpsubject.Subject{Kind: httpsubject.ManagedService, ID: row.PrivateServiceID}) {
		return BrowserLoginAttempt{}, ErrPreviewAccess
	}
	result.ManagedRunIDs, result.ReturnPath, result.Nonce = row.RunIds, row.ReturnPath, row.Nonce
	return result, nil
}

func (d *Database) issueManagedBrowserHandoff(ctx context.Context, attempt BrowserLoginAttempt, session BrowserAccessSession, now time.Time) (result BrowserHandoff, retErr error) {
	if !attempt.Subject.Valid() || len(attempt.ManagedRunIDs) == 0 || !session.ExpiresAt.After(now) {
		return result, ErrPreviewAccess
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "issue managed browser handoff", &retErr)()
	if err = lockPrivateAdmission(ctx, tx, attempt.Subject.ID); err != nil {
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
	endpoint, err := q.ManagedHTTPBrowserEndpoint(ctx, controlstatedb.ManagedHTTPBrowserEndpointParams{PrivateServiceID: attempt.Subject.ID, Now: timestamptz(now)})
	if err != nil {
		return result, err
	}
	runs := slices.DeleteFunc(slices.Clone(attempt.ManagedRunIDs), func(id string) bool { return !slices.Contains(endpoint.RunIds, id) })
	if len(runs) == 0 {
		return result, ErrPreviewAccess
	}
	result.Origin, err = managedHTTPOrigin(endpoint)
	if err != nil {
		return result, err
	}
	result.Token, _, err = randomBrowserSecret()
	if err != nil {
		return result, err
	}
	digest, _ := browserDigest(result.Token)
	err = q.InsertManagedHTTPBrowserSession(ctx, controlstatedb.InsertManagedHTTPBrowserSessionParams{HandoffDigest: digest, PrivateServiceID: attempt.Subject.ID, RunIds: runs, ControlSessionID: controlSession.ID, ReturnPath: attempt.ReturnPath, HandoffExpiresAt: timestamptz(now.Add(time.Minute)), ExpiresAt: timestamptz(minTime(session.ExpiresAt, now.Add(browserSessionLifetime)))})
	if err != nil {
		return result, err
	}
	result.ReturnPath = attempt.ReturnPath
	return result, tx.Commit(ctx)
}

func managedBrowserPermission(ctx context.Context, tx pgx.Tx, service, run string, digest []byte, now time.Time) (VisitorPermission, error) {
	row, err := controlstatedb.New(tx).ManagedHTTPBrowserPermission(ctx, controlstatedb.ManagedHTTPBrowserPermissionParams{PrivateServiceID: service, PrivateRunID: run, CookieDigest: digest, Now: timestamptz(now)})
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
	s, err := q.GetPrivateService(ctx, service)
	if err != nil {
		return VisitorPermission{}, err
	}
	_, err = q.VisitorCurrentMembership(ctx, controlstatedb.VisitorCurrentMembershipParams{TeamID: s.TeamID, IdentityID: row.IdentityID})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return VisitorPermission{}, err
	}
	return VisitorPermission{Authenticated: true, TeamMember: err == nil, IdentityID: row.IdentityID, DisplayName: row.DisplayName, VisitAllowed: true, Reason: "managed_browser", ExpiresAt: &until}, nil
}

func (d *Database) RedeemManagedBrowserHandoff(ctx context.Context, auth ManagedHTTPRun, ticket string, now time.Time) (result controlv1.BrowserHandoffResponse, retErr error) {
	digest, err := browserDigest(ticket)
	if err != nil {
		return result, ErrVisitorSignIn
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "redeem managed browser handoff", &retErr)()
	if err = d.lockManagedHTTPRun(ctx, tx, auth, now); err != nil {
		return result, err
	}
	cookie, _, err := randomBrowserSecret()
	if err != nil {
		return result, err
	}
	cookieDigest, _ := browserDigest(cookie)
	row, err := controlstatedb.New(tx).RedeemManagedHTTPBrowserSession(ctx, controlstatedb.RedeemManagedHTTPBrowserSessionParams{HandoffDigest: digest, CookieDigest: cookieDigest, PrivateServiceID: auth.Subject.ID, PrivateRunID: auth.RunID, Now: timestamptz(now)})
	if err != nil {
		return result, publisherLookupError(err, ErrVisitorSignIn)
	}
	if _, err = managedBrowserPermission(ctx, tx, auth.Subject.ID, auth.RunID, cookieDigest, now); err != nil {
		return result, err
	}
	result = controlv1.BrowserHandoffResponse{CookieSecret: cookie, ReturnPath: row.ReturnPath, ExpiresAt: row.ExpiresAt.Time}
	return result, tx.Commit(ctx)
}

func (d *Database) ManagedBrowserSession(ctx context.Context, auth ManagedHTTPRun, secret string, revoke bool, now time.Time) (result VisitorPermission, retErr error) {
	digest, err := browserDigest(secret)
	if err != nil {
		return result, ErrVisitorSignIn
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "check managed browser session", &retErr)()
	if err = d.lockManagedHTTPRun(ctx, tx, auth, now); err != nil {
		return result, err
	}
	if revoke {
		err = controlstatedb.New(tx).RevokeManagedHTTPBrowserSession(ctx, controlstatedb.RevokeManagedHTTPBrowserSessionParams{PrivateServiceID: auth.Subject.ID, PrivateRunID: auth.RunID, CookieDigest: digest, Now: timestamptz(now)})
	} else {
		result, err = managedBrowserPermission(ctx, tx, auth.Subject.ID, auth.RunID, digest, now)
	}
	if errors.Is(err, ErrPrivateServiceAccess) {
		err = ErrVisitorSignIn
	}
	if err != nil {
		return result, err
	}
	return result, tx.Commit(ctx)
}
