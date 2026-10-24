package state

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// a verified website actor has no CLI control session. this independent
// authority boundary issues the same service-scoped signed credential as the
// CLI, never a second kind of app access secret or publisher token.
func (d *Database) CreateServiceActorVisitorCredential(ctx context.Context, issuer, service, actor string, input controlv1.CreateVisitorCredentialRequest, now time.Time) (result VisitorGrantCredentials, retErr error) {
	if input.Resource.Kind != "service" || input.Resource.Id != service || (input.Kind != "token" && input.Kind != "share") || !input.ExpiresAt.After(now) || input.ExpiresAt.After(now.Add(7*24*time.Hour)) {
		return result, ErrServiceAccess
	}
	tx, err := d.beginServiceAccess(ctx, pgx.TxOptions{})
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "create service HTTP grant", &retErr)()
	if err = lockServiceAdmission(ctx, tx, service); err != nil {
		return result, err
	}
	q := controlstatedb.New(tx)
	endpoint, err := q.ServiceHTTPBrowserEndpoint(ctx, controlstatedb.ServiceHTTPBrowserEndpointParams{ServiceID: service, Now: timestamptz(now)})
	if err != nil {
		return result, publisherLookupError(err, ErrServiceAccess)
	}
	if err = serviceManager(ctx, tx, endpoint.TeamID, actor); err != nil {
		return result, err
	}
	if _, _, err = privateVisitorAccess(ctx, tx, service, actor, now); err != nil {
		if _, signed := serviceActor(ctx); signed && errors.Is(err, ErrServiceAccess) {
			allowed, sourceErr := q.CompanySubjectSessionAuthorized(ctx, controlstatedb.CompanySubjectSessionAuthorizedParams{TeamID: endpoint.TeamID, IdentityID: actor, SessionID: "", Now: timestamptz(now)})
			if sourceErr != nil {
				return result, sourceErr
			}
			if !allowed {
				return result, ErrServiceSourceSignInRequired
			}
		}
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
	refresh := "vrf1." + id + "." + secret
	_, digest, err := visitorRefreshDigest(refresh)
	if err != nil {
		return result, err
	}
	err = q.InsertServiceHTTPGrant(ctx, controlstatedb.InsertServiceHTTPGrantParams{ID: id, ServiceID: service, Kind: string(input.Kind), SecretDigest: digest[:], CreatedByIdentityID: actor, ControlSessionID: nullableText(companySessionID(ctx, actor)), ExpiresAt: timestamptz(input.ExpiresAt)})
	if err != nil {
		return result, err
	}
	issued, err := d.issueVisitorToken(ctx, tx, issuer, visitorscope.Scope{Kind: visitorscope.Service, ID: service}, GrantTokenSource{Credential: refresh}, now)
	if err != nil {
		return result, err
	}
	result.GrantID, result.RefreshCredential, result.IssuedVisitorToken = id, refresh, issued
	return result, tx.Commit(ctx)
}

func (d *Database) ListServiceHTTPGrants(ctx context.Context, service, actor string, now time.Time) (result []controlv1.ServiceHTTPGrantSummary, retErr error) {
	tx, err := d.beginServiceAccess(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, err
	}
	defer rollback(ctx, tx, "list service HTTP grants", &retErr)()
	_, err = lockService(ctx, tx, service, actor)
	if err != nil {
		return nil, err
	}
	rows, err := controlstatedb.New(tx).ListServiceHTTPGrants(ctx, service)
	if err != nil {
		return nil, err
	}
	result = make([]controlv1.ServiceHTTPGrantSummary, 0, len(rows))
	for _, row := range rows {
		result = append(result, controlv1.ServiceHTTPGrantSummary{Subject: controlv1.VisitorResourceScope{Kind: "service", Id: service}, Id: row.ID, Kind: controlv1.ServiceHTTPGrantSummaryKind(row.Kind), ExpiresAt: row.ExpiresAt.Time, RevokedAt: optionalTime(row.RevokedAt)})
	}
	return result, tx.Commit(ctx)
}

func (d *Database) RevokeServiceHTTPGrant(ctx context.Context, service, actor, id string, now time.Time) (retErr error) {
	tx, err := d.beginServiceAccess(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "revoke service HTTP grant", &retErr)()
	if err = lockServiceAdmission(ctx, tx, service); err != nil {
		return err
	}
	q := controlstatedb.New(tx)
	s, err := q.GetService(ctx, service)
	if err != nil {
		return publisherLookupError(err, ErrServiceAccess)
	}
	if err = serviceManager(ctx, tx, s.TeamID, actor); err != nil {
		return err
	}
	n, err := q.RevokeServiceHTTPGrant(ctx, controlstatedb.RevokeServiceHTTPGrantParams{ID: id, ServiceID: service, Now: timestamptz(now)})
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrServiceAccess
	}
	return tx.Commit(ctx)
}
