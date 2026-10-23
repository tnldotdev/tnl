package state

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
)

type VisitorGrantCredentials struct {
	GrantID           string
	RefreshCredential string
	IssuedVisitorToken
}

func (VisitorGrantCredentials) String() string   { return "visitor grant credentials" }
func (VisitorGrantCredentials) GoString() string { return "visitor grant credentials" }

// CreateVisitorGrantCredentials preserves an explicitly selected credential
// deadline. verification-key retention follows the access token's whole lifetime;
// the refresh credential is accepted only by authority-facing preparation.
func (d *Database) CreateVisitorGrantCredentials(ctx context.Context, issuer string, scope visitorscope.Scope, kind string, expires, now time.Time) (result VisitorGrantCredentials, retErr error) {
	if scope.Kind != visitorscope.Service || (kind != "token" && kind != "share") || !expires.After(now) || expires.After(now.Add(7*24*time.Hour)) {
		return result, ErrVisitorPermission
	}
	principal, _ := ctx.Value(controlPrincipalKey{}).(ControlPrincipal)
	if !opaqueid.Valid(principal.IdentityID, opaqueid.IdentityPrefix) || !opaqueid.Valid(principal.SessionID, opaqueid.ControlSessionPrefix) {
		return result, ErrVisitorPermission
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "create visitor grant credentials", &retErr)()
	resource, err := lockVisitorResource(ctx, tx, scope, now)
	if err != nil {
		return result, err
	}
	if err := serviceManager(ctx, tx, resource.TeamID, principal.IdentityID); err != nil {
		return result, err
	}
	// require the same current visitor authority as ordinary token issuance before
	// creating a credential another visitor could hold.
	if _, err := d.visitorPermissionForSource(ctx, tx, scope, BrowserTokenSource{}, now); err != nil {
		return result, err
	}
	id, err := opaqueid.New("shg_")
	if err != nil {
		return result, err
	}
	secret, _, err := randomBrowserSecret()
	if err != nil {
		return result, err
	}
	result.GrantID, result.RefreshCredential = id, "vrf1."+id+"."+secret
	_, digest, err := visitorRefreshDigest(result.RefreshCredential)
	if err != nil {
		return result, err
	}
	q := controlstatedb.New(tx)
	independent, err := q.CompanySubjectSessionAuthorized(ctx, controlstatedb.CompanySubjectSessionAuthorizedParams{TeamID: resource.TeamID, IdentityID: principal.IdentityID, SessionID: "", Now: timestamptz(now)})
	if err != nil {
		return result, err
	}
	parentSession := nullableText("")
	if !independent {
		parentSession = text(principal.SessionID)
	}
	err = q.InsertServiceHTTPGrant(ctx, controlstatedb.InsertServiceHTTPGrantParams{ID: id, ServiceID: scope.ID, Kind: kind, SecretDigest: digest[:], CreatedByIdentityID: principal.IdentityID, ControlSessionID: parentSession, ExpiresAt: timestamptz(expires)})
	if err != nil {
		return result, err
	}
	result.IssuedVisitorToken, err = d.issueVisitorToken(ctx, tx, issuer, scope, GrantTokenSource{Credential: result.RefreshCredential}, now)
	if err != nil {
		return VisitorGrantCredentials{}, err
	}
	return result, tx.Commit(ctx)
}
