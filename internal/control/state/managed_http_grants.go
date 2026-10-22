package controlstate

import (
	"context"
	"crypto/sha256"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func hashManagedHTTPSecret(secret string) []byte {
	digest := sha256.Sum256([]byte("managed-http-grant/v1\x00" + secret))
	return digest[:]
}

func (d *Database) CreateManagedHTTPGrant(ctx context.Context, service, actor string, input controlv1.CreateManagedHTTPGrantRequest, now time.Time) (result controlv1.ManagedHTTPGrant, retErr error) {
	kind := managedHTTPCredentialKind(input.Kind)
	if !kind.grant() || !input.ExpiresAt.After(now) || input.ExpiresAt.After(now.Add(7*24*time.Hour)) {
		return result, ErrPrivateServiceAccess
	}
	tx, err := d.beginServiceAccess(ctx, pgx.TxOptions{})
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "create managed HTTP grant", &retErr)()
	if err = lockPrivateAdmission(ctx, tx, service); err != nil {
		return result, err
	}
	q := controlstatedb.New(tx)
	endpoint, err := q.ManagedHTTPBrowserEndpoint(ctx, controlstatedb.ManagedHTTPBrowserEndpointParams{PrivateServiceID: service, Now: timestamptz(now)})
	if err != nil {
		return result, publisherLookupError(err, ErrPrivateServiceAccess)
	}
	if err = privateServiceManager(ctx, tx, endpoint.TeamID, actor); err != nil {
		return result, err
	}
	if _, _, err = privateVisitorAccess(ctx, tx, service, actor, now); err != nil {
		if _, signed := serviceActor(ctx); signed && errors.Is(err, ErrPrivateServiceAccess) {
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
	id, err := opaqueid.New("mhg_")
	if err != nil {
		return result, err
	}
	secret, _, err := randomBrowserSecret()
	if err != nil {
		return result, err
	}
	secret = id + "." + secret
	credential, err := parseManagedHTTPCredential(controlv1.ManagedHTTPCredential{Kind: controlv1.ManagedHTTPCredentialKind(kind), Secret: &secret})
	if err != nil {
		return result, err
	}
	err = q.InsertManagedHTTPGrant(ctx, controlstatedb.InsertManagedHTTPGrantParams{ID: id, PrivateServiceID: service, Kind: string(credential.kind), SecretDigest: credential.digest[:], CreatedByIdentityID: actor, ControlSessionID: nullableText(companySessionID(ctx, actor)), ExpiresAt: timestamptz(input.ExpiresAt)})
	if err != nil {
		return result, err
	}
	result = controlv1.ManagedHTTPGrant{Subject: controlv1.HTTPAuthorizationSubject{Kind: "managed_service", Id: service}, Id: id, Kind: controlv1.ManagedHTTPGrantKind(input.Kind), Secret: secret, ExpiresAt: input.ExpiresAt}
	if input.Kind == "share" {
		origin, err := managedHTTPOrigin(endpoint)
		if err != nil {
			return result, err
		}
		link := origin + "/__tnl/share/" + secret
		result.ShareUrl = &link
	}
	return result, tx.Commit(ctx)
}

func (d *Database) ListManagedHTTPGrants(ctx context.Context, service, actor string, now time.Time) (result []controlv1.ManagedHTTPGrantSummary, retErr error) {
	tx, err := d.beginServiceAccess(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, err
	}
	defer rollback(ctx, tx, "list managed HTTP grants", &retErr)()
	_, err = lockManagedPrivateService(ctx, tx, service, actor)
	if err != nil {
		return nil, err
	}
	rows, err := controlstatedb.New(tx).ListManagedHTTPGrants(ctx, service)
	if err != nil {
		return nil, err
	}
	result = make([]controlv1.ManagedHTTPGrantSummary, 0, len(rows))
	for _, row := range rows {
		result = append(result, controlv1.ManagedHTTPGrantSummary{Subject: controlv1.HTTPAuthorizationSubject{Kind: "managed_service", Id: service}, Id: row.ID, Kind: controlv1.ManagedHTTPGrantSummaryKind(row.Kind), ExpiresAt: row.ExpiresAt.Time, RevokedAt: optionalTime(row.RevokedAt)})
	}
	return result, tx.Commit(ctx)
}

func (d *Database) RevokeManagedHTTPGrant(ctx context.Context, service, actor, id string, now time.Time) (retErr error) {
	tx, err := d.beginServiceAccess(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "revoke managed HTTP grant", &retErr)()
	if err = lockPrivateAdmission(ctx, tx, service); err != nil {
		return err
	}
	q := controlstatedb.New(tx)
	s, err := q.GetPrivateService(ctx, service)
	if err != nil {
		return publisherLookupError(err, ErrPrivateServiceAccess)
	}
	if err = privateServiceManager(ctx, tx, s.TeamID, actor); err != nil {
		return err
	}
	n, err := q.RevokeManagedHTTPGrant(ctx, controlstatedb.RevokeManagedHTTPGrantParams{ID: id, PrivateServiceID: service, Now: timestamptz(now)})
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrPrivateServiceAccess
	}
	return tx.Commit(ctx)
}
