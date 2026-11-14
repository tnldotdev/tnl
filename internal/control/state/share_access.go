package state

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"slices"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

const shareHandoffLifetime = time.Minute

type ShareRedemption struct {
	ShareID, CookieSecret string
	ExpiresAt             time.Time
	NextURL               string
	Bridge                bool
}

func (d *Database) RedeemShare(ctx context.Context, auth ServiceHTTPRun, shareID string, secret, handoff []byte, now time.Time) (result ShareRedemption, retErr error) {
	if !auth.valid() || (len(secret) == 32) == (len(handoff) == 32) ||
		len(secret) == 32 && !opaqueid.Valid(shareID, opaqueid.SharePrefix) {
		return result, ErrShareNotFound
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "redeem share", &retErr)()
	if err = d.lockServiceHTTPRun(ctx, tx, auth, now); err != nil {
		return result, err
	}
	q := controlstatedb.New(tx)
	endpoint, err := q.ServiceHTTPBrowserEndpoint(ctx, controlstatedb.ServiceHTTPBrowserEndpointParams{ServiceID: auth.Subject.ID, Now: timestamptz(now)})
	if err != nil {
		return result, err
	}
	cookieRuns := endpoint.RunIds
	nextURL := ""
	bridge := false
	if len(handoff) == 32 {
		digest := sha256.Sum256(handoff)
		consumed, err := q.ConsumeShareHandoff(ctx, controlstatedb.ConsumeShareHandoffParams{
			Now: timestamptz(now), TokenDigest: digest[:], ServiceID: auth.Subject.ID, ServiceRunID: auth.RunID})
		if err != nil {
			return result, publisherLookupError(err, ErrShareNotFound)
		}
		shareID, nextURL, bridge = consumed.ShareID, consumed.RedirectUrl, consumed.Bridge
		// keep only the original captured replicas. a newly started run does not
		// inherit a ticket or the cookie installed by redeeming that ticket.
		cookieRuns = slices.DeleteFunc(slices.Clone(consumed.RunIds), func(id string) bool { return !slices.Contains(endpoint.RunIds, id) })
	}
	share, err := q.GetActiveShareForService(ctx, controlstatedb.GetActiveShareForServiceParams{ShareID: shareID, ServiceID: auth.Subject.ID, Now: timestamptz(now)})
	if err != nil {
		return result, publisherLookupError(err, ErrShareNotFound)
	}
	until, err := d.currentShareIssuer(ctx, tx, share, now)
	if err != nil {
		return result, err
	}
	count, err := q.CountActiveShareCookiesForService(ctx, controlstatedb.CountActiveShareCookiesForServiceParams{ServiceID: auth.Subject.ID, Now: timestamptz(now)})
	if err != nil {
		return result, err
	}
	if count >= 2048 {
		return result, ErrShareLimit
	}
	if len(secret) == 32 {
		digest := sha256.Sum256(secret)
		if subtle.ConstantTimeCompare(digest[:], share.SecretDigest) != 1 {
			return result, ErrShareNotFound
		}
		entry, err := q.ServiceHTTPBrowserEndpoint(ctx, controlstatedb.ServiceHTTPBrowserEndpointParams{ServiceID: share.EntryServiceID, Now: timestamptz(now)})
		if err != nil || len(entry.RunIds) == 0 {
			return result, ErrShareNotFound
		}
		nextURL, err = serviceHTTPOrigin(entry)
		if err != nil {
			return result, err
		}
		hosts, err := q.ListReadyShareServices(ctx, controlstatedb.ListReadyShareServicesParams{ShareID: shareID, Now: timestamptz(now)})
		if err != nil {
			return result, err
		}
		seen := map[string]bool{}
		other := hosts[:0]
		for _, host := range hosts {
			if seen[host.CertificateHostname] || len(host.RunIds) == 0 || len(host.RunIds) > 256 {
				return result, ErrShareStale
			}
			seen[host.CertificateHostname] = true
			if host.ServiceID != auth.Subject.ID {
				other = append(other, host)
			}
		}
		slices.Reverse(other)
		for index, host := range other {
			token, _, err := randomBrowserSecret()
			if err != nil {
				return result, err
			}
			digest, err := browserDigest(token)
			if err != nil {
				return result, err
			}
			if _, err = q.InsertShareHandoff(ctx, controlstatedb.InsertShareHandoffParams{
				TokenDigest: digest, ServiceID: host.ServiceID, RunIds: host.RunIds, NextUrl: nextURL,
				Bridge: (len(other)-index-1)%8 == 7, CreatedAt: timestamptz(now),
				ExpiresAt: timestamptz(minTime(until, now.Add(shareHandoffLifetime))), ShareID: shareID,
			}); err != nil {
				return result, err
			}
			origin, err := serviceHTTPOrigin(controlstatedb.ServiceHTTPBrowserEndpointRow{
				CertificateHostname: host.CertificateHostname, ServicePort: endpoint.ServicePort})
			if err != nil {
				return result, err
			}
			nextURL = origin + "/__tnl/share/handoff/" + token
		}
	}
	if !slices.Contains(cookieRuns, auth.RunID) {
		return result, ErrShareNotFound
	}
	cookie, digest, err := randomBrowserSecret()
	if err != nil {
		return result, err
	}
	if _, err = q.InsertShareCookie(ctx, controlstatedb.InsertShareCookieParams{TokenDigest: digest, ServiceID: auth.Subject.ID,
		RunIds: cookieRuns, CreatedAt: timestamptz(now), ExpiresAt: timestamptz(until), ShareID: shareID}); err != nil {
		return result, publisherLookupError(err, ErrShareNotFound)
	}
	if err = tx.Commit(ctx); err != nil {
		return result, err
	}
	return ShareRedemption{ShareID: shareID, CookieSecret: cookie,
		ExpiresAt: until, NextURL: nextURL, Bridge: bridge}, nil
}
