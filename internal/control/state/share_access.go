package state

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

// currentShareVisitorAuthority is shared by redemption, issuance, and signed
// bearer rechecks. it does not authenticate a share secret or browser cookie.
func (d *Database) currentShareVisitorAuthority(ctx context.Context, tx pgx.Tx, service, shareID string, now time.Time) (controlstatedb.ControlShare, time.Time, error) {
	if !opaqueid.Valid(service, opaqueid.ServicePrefix) || !opaqueid.Valid(shareID, opaqueid.SharePrefix) {
		return controlstatedb.ControlShare{}, time.Time{}, ErrVisitorPermission
	}
	q := controlstatedb.New(tx)
	share, err := q.GetActiveShareForService(ctx, controlstatedb.GetActiveShareForServiceParams{ShareID: shareID, ServiceID: service, Now: timestamptz(now)})
	if err != nil {
		return share, time.Time{}, err
	}
	until, err := d.currentShareIssuer(ctx, tx, share, now)
	if err != nil {
		return share, time.Time{}, err
	}
	return share, until, nil
}

// every share consumer rechecks the same captured service membership and current
// issuer management. a cookie keeps its service scope and original deadline;
// obtaining permission after an app restart still requires a current ready run.
func (d *Database) shareVisitorPermission(ctx context.Context, tx pgx.Tx, service, run, shareID, secret string, cookie bool, now time.Time, hostname string) (time.Time, error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(secret)
	if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != secret {
		return time.Time{}, ErrVisitorPermission
	}
	share, until, err := d.currentShareVisitorAuthority(ctx, tx, service, shareID, now)
	if err != nil {
		if errors.Is(err, ErrShareNotFound) || errors.Is(err, ErrShareStale) || errors.Is(err, ErrServiceAccess) ||
			errors.Is(err, ErrAuthorityAccess) || errors.Is(err, ErrServiceSourceSignInRequired) {
			err = errors.Join(ErrVisitorPermission, err)
		}
		err = publisherLookupError(err, ErrVisitorPermission)
		return time.Time{}, err
	}
	digest := sha256.Sum256(raw)
	if !cookie {
		if subtle.ConstantTimeCompare(share.SecretDigest, digest[:]) != 1 {
			return time.Time{}, ErrVisitorPermission
		}
		return until, nil
	}
	var deadline time.Time
	err = tx.QueryRow(ctx, `SELECT cookie.expires_at FROM control.share_cookies cookie
		WHERE cookie.share_id=$1 AND cookie.service_id=$2 AND cookie.token_digest=$3 AND cookie.expires_at>$4
		AND cookie.hostname=COALESCE(NULLIF($6::text,''),(SELECT certificate_hostname FROM control.services WHERE id=$2))
		AND EXISTS(SELECT 1 FROM control.service_runs current_run WHERE
		    ($5='' OR current_run.id=$5) AND current_run.service_id=cookie.service_id
		    AND current_run.state='ready' AND current_run.healthy AND current_run.closed_at IS NULL
		    AND current_run.publisher_expires_at>$4 AND current_run.certificate_expires_at>$4
		    AND EXISTS(SELECT 1 FROM control.publisher_service_permission(current_run.publisher_identity_id,
		        current_run.publisher_grant_id,current_run.service_id,$4) permission
		        JOIN control.publisher_grants grant_record ON grant_record.id=current_run.publisher_grant_id
		        JOIN control.publisher_identity_keys signing ON signing.id=current_run.publisher_key_id
		            AND signing.publisher_identity_id=current_run.publisher_identity_id
		            AND (grant_record.kind='service' OR signing.retired_at IS NULL))) FOR SHARE OF cookie`,
		shareID, service, digest[:], now, run, hostname).Scan(&deadline)
	if err != nil {
		return time.Time{}, publisherLookupError(err, ErrVisitorPermission)
	}
	return minTime(until, deadline), nil
}

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
	endpoint, err := q.ServiceHTTPBrowserEndpoint(ctx, controlstatedb.ServiceHTTPBrowserEndpointParams{ServiceID: auth.Subject.ID, Hostname: auth.Hostname, Now: timestamptz(now)})
	if err != nil {
		return result, err
	}
	if !slices.Contains(endpoint.RunIds, auth.RunID) {
		return result, ErrShareNotFound
	}
	nextURL := ""
	bridge := false
	if len(handoff) == 32 {
		// only a captured, currently ready run may redeem the one-use ticket.
		// the installed cookie then follows the service's current authorized runs.
		digest := sha256.Sum256(handoff)
		consumed, err := q.ConsumeShareHandoff(ctx, controlstatedb.ConsumeShareHandoffParams{
			Now: timestamptz(now), TokenDigest: digest[:], ServiceID: auth.Subject.ID, Hostname: endpoint.CertificateHostname, ServiceRunID: auth.RunID})
		if err != nil {
			return result, publisherLookupError(err, ErrShareNotFound)
		}
		shareID, nextURL, bridge = consumed.ShareID, consumed.RedirectUrl, consumed.Bridge
	}
	share, until, err := d.currentShareVisitorAuthority(ctx, tx, auth.Subject.ID, shareID, now)
	if err != nil {
		return result, publisherLookupError(err, ErrShareNotFound)
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
		if auth.Hostname != "" && auth.Hostname != entry.CertificateHostname && share.EntryServiceID == auth.Subject.ID {
			// opening a share on an exact-run address returns to that address,
			// rather than silently selecting a sibling through the pooled host.
			nextURL, err = serviceHTTPOrigin(endpoint)
			if err != nil {
				return result, err
			}
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
				TokenDigest: digest, ServiceID: host.ServiceID, Hostname: host.CertificateHostname, RunIds: host.RunIds, NextUrl: nextURL,
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
	cookie, _, err := randomBrowserSecret()
	if err != nil {
		return result, err
	}
	digest, err := browserDigest(cookie)
	if err != nil {
		return result, err
	}
	if _, err = q.InsertShareCookie(ctx, controlstatedb.InsertShareCookieParams{TokenDigest: digest, ServiceID: auth.Subject.ID,
		Hostname: endpoint.CertificateHostname, CreatedAt: timestamptz(now), ExpiresAt: timestamptz(until), ShareID: shareID}); err != nil {
		return result, publisherLookupError(err, ErrShareNotFound)
	}
	if err = tx.Commit(ctx); err != nil {
		return result, err
	}
	return ShareRedemption{ShareID: shareID, CookieSecret: cookie,
		ExpiresAt: until, NextURL: nextURL, Bridge: bridge}, nil
}
