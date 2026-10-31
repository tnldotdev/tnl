package state

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

const shareHandoffLifetime = time.Minute

type ShareRedemption struct {
	ShareID      string
	CookieSecret string
	ExpiresAt    time.Time
	NextURL      string
	Bridge       bool
}

func (d *Database) EnableShareAccess(ctx context.Context, authentication PublishRunAuthentication, previewID string) error {
	if err := validatePublishRunAuthentication(authentication); err != nil || previewID != "" && !opaqueid.Valid(previewID, opaqueid.PreviewPrefix) {
		return ErrPreviewAccess
	}
	if err := d.requireOpen(); err != nil {
		return err
	}
	_, err := controlstatedb.New(d.pool).EnablePublishRunShareAccess(ctx, controlstatedb.EnablePublishRunShareAccessParams{
		PublishRunID: authentication.PublishRunID, PublicURLID: authentication.PublicURLID,
		PublishRunNumber: int64(authentication.PublishRunNumber), PreviewID: previewID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrPreviewAccess
	}
	if err != nil {
		return fmt.Errorf("controlstate: enable share access: %w", err)
	}
	return nil
}

func (d *Database) RedeemShare(ctx context.Context, authentication PublishRunAuthentication, shareID string, secret, handoff []byte, now time.Time) (result ShareRedemption, retErr error) {
	if err := validatePublishRunAuthentication(authentication); err != nil {
		return ShareRedemption{}, err
	}
	if len(secret) == 32 && len(handoff) == 32 || len(secret) != 32 && len(handoff) != 32 ||
		len(secret) == 32 && !opaqueid.Valid(shareID, opaqueid.SharePrefix) {
		return ShareRedemption{}, ErrShareNotFound
	}
	if err := d.requireOpen(); err != nil {
		return ShareRedemption{}, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return ShareRedemption{}, fmt.Errorf("controlstate: redeem share: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "redeem share", &retErr)()
	queries := controlstatedb.New(tx)
	if err := requireShareCapableRun(ctx, queries, authentication, now); err != nil {
		return ShareRedemption{}, err
	}
	route, err := queries.LockPublicURLForRun(ctx, authentication.PublicURLID)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && route.LifecycleState != string(PublicURLLifecycleEnabled) {
		return ShareRedemption{}, ErrShareNotFound
	}
	if err != nil {
		return ShareRedemption{}, fmt.Errorf("controlstate: lock share public URL: %w", err)
	}
	cookieCount, err := queries.CountActiveShareCookiesForPublicURL(ctx, controlstatedb.CountActiveShareCookiesForPublicURLParams{
		PublicURLID: authentication.PublicURLID, Now: timestamptz(now),
	})
	if err != nil {
		return ShareRedemption{}, fmt.Errorf("controlstate: count share cookies: %w", err)
	}
	if cookieCount >= 2048 {
		return ShareRedemption{}, ErrShareLimit
	}
	nextURL := ""
	bridge := false
	if len(handoff) == 32 {
		digest := sha256.Sum256(handoff)
		consumed, err := queries.ConsumeShareHandoff(ctx, controlstatedb.ConsumeShareHandoffParams{
			Now: timestamptz(now), TokenDigest: digest[:], PublicURLID: authentication.PublicURLID,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return ShareRedemption{}, ErrShareNotFound
		}
		if err != nil {
			return ShareRedemption{}, fmt.Errorf("controlstate: consume share handoff: %w", err)
		}
		shareID, nextURL, bridge = consumed.ShareID, consumed.RedirectUrl, consumed.Bridge
	}
	share, err := queries.GetActiveShareForPublicURL(ctx, controlstatedb.GetActiveShareForPublicURLParams{
		ShareID: shareID, PublicURLID: authentication.PublicURLID, Now: timestamptz(now),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return ShareRedemption{}, ErrShareNotFound
	}
	if err != nil {
		return ShareRedemption{}, fmt.Errorf("controlstate: read share for redemption: %w", err)
	}
	if len(secret) == 32 {
		digest := sha256.Sum256(secret)
		if subtle.ConstantTimeCompare(digest[:], share.SecretDigest) != 1 {
			return ShareRedemption{}, ErrShareNotFound
		}
		nextURL = "https://" + route.CanonicalHostname + "/"
		hosts, err := queries.ListReadyShareHostnames(ctx, controlstatedb.ListReadyShareHostnamesParams{
			ShareID: shareID, Now: timestamptz(now),
		})
		if err != nil {
			return ShareRedemption{}, fmt.Errorf("controlstate: list share hostnames: %w", err)
		}
		otherHosts := make([]controlstatedb.ListReadyShareHostnamesRow, 0, len(hosts))
		for _, host := range hosts {
			if host.PublicURLID != authentication.PublicURLID {
				otherHosts = append(otherHosts, host)
			}
		}
		slices.Reverse(otherHosts)
		for index, host := range otherHosts {
			token := make([]byte, 32)
			if _, err := rand.Read(token); err != nil {
				return ShareRedemption{}, fmt.Errorf("controlstate: create share handoff: %w", err)
			}
			digest := sha256.Sum256(token)
			expires := now.Add(shareHandoffLifetime)
			if share.ExpiresAt.Time.Before(expires) {
				expires = share.ExpiresAt.Time
			}
			_, err := queries.InsertShareHandoff(ctx, controlstatedb.InsertShareHandoffParams{
				TokenDigest: digest[:], PublicURLID: host.PublicURLID, NextUrl: nextURL,
				Bridge:    (len(otherHosts)-index-1)%8 == 7,
				CreatedAt: timestamptz(now), ExpiresAt: timestamptz(expires), ShareID: shareID,
			})
			if err != nil {
				return ShareRedemption{}, fmt.Errorf("controlstate: save share handoff: %w", err)
			}
			nextURL = "https://" + host.CanonicalHostname + "/__tnl/share/handoff/" + base64.RawURLEncoding.EncodeToString(token)
		}
	}
	cookie := make([]byte, 32)
	if _, err := rand.Read(cookie); err != nil {
		return ShareRedemption{}, fmt.Errorf("controlstate: create share cookie: %w", err)
	}
	cookieDigest := sha256.Sum256(cookie)
	if _, err := queries.InsertShareCookie(ctx, controlstatedb.InsertShareCookieParams{
		TokenDigest: cookieDigest[:], PublicURLID: authentication.PublicURLID,
		CreatedAt: timestamptz(now), ShareID: shareID,
	}); errors.Is(err, pgx.ErrNoRows) {
		return ShareRedemption{}, ErrShareNotFound
	} else if err != nil {
		return ShareRedemption{}, fmt.Errorf("controlstate: save share cookie: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return ShareRedemption{}, fmt.Errorf("controlstate: redeem share: commit: %w", err)
	}
	return ShareRedemption{
		ShareID: shareID, CookieSecret: base64.RawURLEncoding.EncodeToString(cookie),
		ExpiresAt: share.ExpiresAt.Time, NextURL: nextURL, Bridge: bridge,
	}, nil
}

func requireShareCapableRun(ctx context.Context, queries *controlstatedb.Queries, authentication PublishRunAuthentication, now time.Time) error {
	_, err := queries.GetShareCapablePublishRun(ctx, controlstatedb.GetShareCapablePublishRunParams{
		PublishRunID: authentication.PublishRunID, PublicURLID: authentication.PublicURLID,
		PublishRunNumber: int64(authentication.PublishRunNumber), Now: timestamptz(now),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrPublishRunStale
	}
	if err != nil {
		return fmt.Errorf("controlstate: read share-capable publish run: %w", err)
	}
	return nil
}
