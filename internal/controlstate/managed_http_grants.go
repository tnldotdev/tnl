package controlstate

import (
	"context"
	"crypto/sha256"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func hashManagedHTTPSecret(secret string) []byte {
	digest := sha256.Sum256([]byte("managed-http-grant/v1\x00" + secret))
	return digest[:]
}

func (d *Database) CreateManagedHTTPGrant(ctx context.Context, service, actor string, input controlv1.CreateManagedHTTPGrantRequest, now time.Time) (result controlv1.ManagedHTTPGrant, retErr error) {
	if input.Kind != "token" && input.Kind != "share" || !input.ExpiresAt.After(now) || input.ExpiresAt.After(now.Add(7*24*time.Hour)) {
		return result, ErrPrivateServiceAccess
	}
	tx, err := d.pool.Begin(ctx)
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
	err = q.InsertManagedHTTPGrant(ctx, controlstatedb.InsertManagedHTTPGrantParams{ID: id, PrivateServiceID: service, Kind: string(input.Kind), SecretDigest: hashManagedHTTPSecret(secret), CreatedByIdentityID: actor, ControlSessionID: nullableText(companySessionID(ctx, actor)), ExpiresAt: timestamptz(input.ExpiresAt)})
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

func (d *Database) RevokeManagedHTTPGrant(ctx context.Context, service, actor, id string, now time.Time) (retErr error) {
	tx, err := d.pool.Begin(ctx)
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
