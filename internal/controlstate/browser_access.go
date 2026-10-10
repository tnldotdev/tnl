package controlstate

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

const browserSessionLifetime = 24 * time.Hour

type BrowserLoginAttempt struct {
	PreviewID   string
	PublicURLID string
	ReturnPath  string
	Nonce       string
	Verifier    string
}

type BrowserAccessSession struct {
	PreviewID       string
	PublicURLID     string
	IdentityID      string
	DisplayName     string
	AccessToken     string
	RefreshToken    string
	AccessExpiresAt time.Time
	ExpiresAt       time.Time
}

type BrowserTokenRotation struct {
	IdentityID      string
	AccessToken     string
	RefreshToken    string
	AccessExpiresAt time.Time
}

// browser identity proves who signed in; visit permission is a separate,
// current decision about one public URL.
type BrowserIdentity struct {
	IdentityID  string
	DisplayName string
	PreviewID   string
}

type BrowserAuthorization struct {
	Identity     BrowserIdentity
	VisitAllowed bool
}

type BrowserHandoff struct {
	Token       string
	PublicURLID string
	ReturnPath  string
}

// the encrypted handoff binds installation to the run that advertised support.
type browserHandoffCredential struct {
	CookieSecret     string `json:"cookie_secret"`
	PublishRunID     string `json:"publish_run_id"`
	PublishRunNumber int64  `json:"publish_run_number"`
}

func lockBrowserRun(ctx context.Context, queries *controlstatedb.Queries, auth PublishRunAuthentication, now time.Time) (controlstatedb.ControlPublishRun, error) {
	candidate, err := queries.GetFeedbackPublicURL(ctx, auth.PublicURLID)
	if errors.Is(err, pgx.ErrNoRows) {
		return controlstatedb.ControlPublishRun{}, ErrPreviewAccess
	}
	if err != nil {
		return controlstatedb.ControlPublishRun{}, fmt.Errorf("read browser public URL: %w", err)
	}
	if err := queries.LockReviewerTeam(ctx, candidate.TeamID); err != nil {
		return controlstatedb.ControlPublishRun{}, fmt.Errorf("lock browser team: %w", err)
	}
	publicURL, run, err := lockAuthenticatedPublishRun(ctx, queries, auth, now)
	if err != nil {
		return controlstatedb.ControlPublishRun{}, err
	}
	if publicURL.TeamID != candidate.TeamID || publicURL.Purpose != "app" {
		return controlstatedb.ControlPublishRun{}, ErrPreviewAccess
	}
	return run, nil
}

func (d *Database) EnableBrowserAccess(ctx context.Context, auth PublishRunAuthentication, now time.Time) (retErr error) {
	if err := validatePublishRunAuthentication(auth); err != nil {
		return err
	}
	if err := d.requireOpen(); err != nil {
		return err
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("enable browser access: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "enable browser access", &retErr)()
	queries := controlstatedb.New(tx)
	run, err := lockBrowserRun(ctx, queries, auth, now)
	if err != nil {
		return err
	}
	if run.State != "starting" {
		return ErrPublishRunStale
	}
	if err := queries.EnablePublishRunBrowserAccess(ctx, run.ID); err != nil {
		return fmt.Errorf("register browser capability: %w", err)
	}
	return tx.Commit(ctx)
}

// check capability before authority refresh, without holding a team guard during
// the network call. admission and handoff redemption recheck in their transactions.
func (d *Database) RequireBrowserAccess(ctx context.Context, auth PublishRunAuthentication, now time.Time) (retErr error) {
	if err := validatePublishRunAuthentication(auth); err != nil {
		return err
	}
	if err := d.requireOpen(); err != nil {
		return err
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("check browser capability: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "check browser capability", &retErr)()
	run, err := lockBrowserRun(ctx, controlstatedb.New(tx), auth, now)
	if err != nil {
		return err
	}
	if !run.BrowserCapable || run.State != "ready" {
		return ErrPreviewAccess
	}
	return tx.Commit(ctx)
}

func randomBrowserSecret() (string, []byte, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, err
	}
	return base64.RawURLEncoding.EncodeToString(raw), raw, nil
}

func browserDigest(token string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != token {
		return nil, ErrPreviewAccess
	}
	digest := sha256.Sum256(raw)
	return digest[:], nil
}

func browserContext(digest []byte) string { return "browser-access:" + hex.EncodeToString(digest) }

func (d *Database) BeginBrowserLogin(ctx context.Context, previewID, publicURLID, path, nonce, verifier string, browserBinding []byte, now time.Time) (string, error) {
	if previewID != "" && !opaqueid.Valid(previewID, opaqueid.PreviewPrefix) || !opaqueid.Valid(publicURLID, opaqueid.PublicURLPrefix) ||
		!validFeedbackPath(path) || len(path) > 2048 || len(nonce) < 16 || len(nonce) > 256 || len(verifier) < 43 || len(verifier) > 128 || len(browserBinding) != 32 {
		return "", ErrPreviewAccess
	}
	if d.storageKey == nil {
		return "", ErrPreviewAccess
	}
	state, _, err := randomBrowserSecret()
	if err != nil {
		return "", err
	}
	digest, _ := browserDigest(state)
	bindingDigest := sha256.Sum256(browserBinding)
	sealed, err := d.storageKey.Seal(browserContext(digest), []byte(verifier))
	if err != nil {
		return "", err
	}
	queries := controlstatedb.New(d.pool)
	if _, err := queries.BrowserLoginPublicURL(ctx, controlstatedb.BrowserLoginPublicURLParams{
		PreviewID: nullableText(previewID), PublicURLID: publicURLID, Now: timestamptz(now),
	}); errors.Is(err, pgx.ErrNoRows) {
		return "", ErrPreviewAccess
	} else if err != nil {
		return "", fmt.Errorf("read browser login scope: %w", err)
	}
	if err := queries.CleanupBrowserAccess(ctx, timestamptz(now)); err != nil {
		return "", fmt.Errorf("controlstate: expire browser logins: %w", err)
	}
	if err := queries.InsertBrowserLoginAttempt(ctx, controlstatedb.InsertBrowserLoginAttemptParams{
		StateDigest: digest, BindingDigest: bindingDigest[:], PreviewID: nullableText(previewID), PublicURLID: publicURLID,
		ReturnPath: path, Nonce: nonce, VerifierCiphertext: sealed,
		VerifierStorageKeyID: d.storageKey.CurrentID(), ExpiresAt: timestamptz(now.Add(5 * time.Minute)),
	}); err != nil {
		return "", fmt.Errorf("controlstate: start browser login: %w", err)
	}
	return state, nil
}

func (d *Database) ConsumeBrowserLogin(ctx context.Context, state string, browserBinding []byte, now time.Time) (BrowserLoginAttempt, error) {
	digest, err := browserDigest(state)
	if err != nil || len(browserBinding) != 32 {
		return BrowserLoginAttempt{}, ErrPreviewAccess
	}
	bindingDigest := sha256.Sum256(browserBinding)
	row, err := controlstatedb.New(d.pool).ConsumeBrowserLoginAttempt(ctx, controlstatedb.ConsumeBrowserLoginAttemptParams{
		StateDigest: digest, BindingDigest: bindingDigest[:], Now: timestamptz(now),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return BrowserLoginAttempt{}, ErrPreviewAccess
	}
	if err != nil {
		return BrowserLoginAttempt{}, fmt.Errorf("controlstate: consume browser login: %w", err)
	}
	verifier, _, err := d.storageKey.Open(row.VerifierStorageKeyID, browserContext(digest), row.VerifierCiphertext)
	if err != nil {
		return BrowserLoginAttempt{}, err
	}
	return BrowserLoginAttempt{PreviewID: row.PreviewID.String, PublicURLID: row.PublicURLID,
		ReturnPath: row.ReturnPath, Nonce: row.Nonce, Verifier: string(verifier)}, nil
}

func (d *Database) IssueBrowserHandoff(ctx context.Context, attempt BrowserLoginAttempt, session BrowserAccessSession, now time.Time) (BrowserHandoff, error) {
	if d.storageKey == nil || session.IdentityID == "" || session.DisplayName == "" || session.AccessToken == "" ||
		session.RefreshToken == "" || !session.AccessExpiresAt.After(now) || !session.ExpiresAt.After(now) ||
		attempt.PublicURLID == "" || !validBrowserLoginScope(attempt) {
		return BrowserHandoff{}, ErrPreviewAccess
	}
	cookie, _, err := randomBrowserSecret()
	if err != nil {
		return BrowserHandoff{}, err
	}
	cookieDigest, _ := browserDigest(cookie)
	context := browserContext(cookieDigest)
	access, err := d.storageKey.Seal(context, []byte(session.AccessToken))
	if err != nil {
		return BrowserHandoff{}, err
	}
	refresh, err := d.storageKey.Seal(context, []byte(session.RefreshToken))
	if err != nil {
		return BrowserHandoff{}, err
	}
	if session.ExpiresAt.After(now.Add(browserSessionLifetime)) {
		session.ExpiresAt = now.Add(browserSessionLifetime)
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return BrowserHandoff{}, err
	}
	defer tx.Rollback(ctx)
	queries := controlstatedb.New(tx)
	landing, err := queries.BrowserLoginPublicURL(ctx, controlstatedb.BrowserLoginPublicURLParams{
		PreviewID: nullableText(attempt.PreviewID), PublicURLID: attempt.PublicURLID, Now: timestamptz(now),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return BrowserHandoff{}, ErrPreviewAccess
	}
	if err != nil {
		return BrowserHandoff{}, fmt.Errorf("read browser landing scope: %w", err)
	}
	if err := queries.InsertBrowserAccessSession(ctx, controlstatedb.InsertBrowserAccessSessionParams{
		TokenDigest: cookieDigest, PreviewID: nullableText(attempt.PreviewID), PublicURLID: attempt.PublicURLID,
		IdentityID: session.IdentityID, DisplayName: session.DisplayName,
		AccessCiphertext: access, RefreshCiphertext: refresh, StorageKeyID: d.storageKey.CurrentID(),
		AccessExpiresAt: timestamptz(session.AccessExpiresAt), ExpiresAt: timestamptz(session.ExpiresAt),
	}); err != nil {
		return BrowserHandoff{}, fmt.Errorf("controlstate: save browser session: %w", err)
	}
	next := "https://" + landing.CanonicalHostname + attempt.ReturnPath
	hosts, err := queries.ListReadyPreviewBrowserHostnames(ctx, controlstatedb.ListReadyPreviewBrowserHostnamesParams{
		PreviewID: attempt.PreviewID, Now: timestamptz(now),
	})
	if err != nil {
		return BrowserHandoff{}, fmt.Errorf("controlstate: list ready preview hostnames: %w", err)
	}
	issue := func(publicURLID, runID string, runNumber int64, nextURL string, bridge bool) (string, error) {
		ticket, _, err := randomBrowserSecret()
		if err != nil {
			return "", err
		}
		digest, _ := browserDigest(ticket)
		credential, err := json.Marshal(browserHandoffCredential{CookieSecret: cookie, PublishRunID: runID, PublishRunNumber: runNumber})
		if err != nil {
			return "", err
		}
		ciphertext, err := d.storageKey.Seal(browserContext(digest), credential)
		if err != nil {
			return "", err
		}
		if err := queries.InsertBrowserAccessHandoff(ctx, controlstatedb.InsertBrowserAccessHandoffParams{
			TokenDigest: digest, SessionDigest: cookieDigest, PublicURLID: publicURLID,
			CookieCiphertext: ciphertext, StorageKeyID: d.storageKey.CurrentID(),
			ReturnPath: attempt.ReturnPath, NextUrl: nextURL, Bridge: bridge, ExpiresAt: timestamptz(now.Add(time.Minute)),
		}); err != nil {
			return "", err
		}
		return ticket, nil
	}
	for index, host := range hosts {
		if host.PublicURLID == attempt.PublicURLID {
			continue
		}
		ticket, err := issue(host.PublicURLID, host.PublishRunID, host.PublishRunNumber, next, index%8 == 7)
		if err != nil {
			return BrowserHandoff{}, fmt.Errorf("controlstate: save other-host browser handoff: %w", err)
		}
		next = "https://" + host.CanonicalHostname + "/__tnl/team/handoff/" + ticket
	}
	firstToken, err := issue(attempt.PublicURLID, landing.PublishRunID, landing.PublishRunNumber, next, false)
	if err != nil {
		return BrowserHandoff{}, fmt.Errorf("controlstate: save browser handoff: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return BrowserHandoff{}, err
	}
	return BrowserHandoff{Token: firstToken, PublicURLID: attempt.PublicURLID, ReturnPath: attempt.ReturnPath}, nil
}

func validBrowserLoginScope(attempt BrowserLoginAttempt) bool {
	return (attempt.PreviewID == "" || opaqueid.Valid(attempt.PreviewID, opaqueid.PreviewPrefix)) &&
		validFeedbackPath(attempt.ReturnPath) && len(attempt.ReturnPath) <= 2048
}

func (d *Database) RedeemBrowserHandoff(ctx context.Context, auth PublishRunAuthentication, token string, now time.Time) (string, string, string, bool, time.Time, error) {
	if err := validatePublishRunAuthentication(auth); err != nil {
		return "", "", "", false, time.Time{}, err
	}
	digest, err := browserDigest(token)
	if err != nil {
		return "", "", "", false, time.Time{}, err
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return "", "", "", false, time.Time{}, err
	}
	defer tx.Rollback(ctx)
	queries := controlstatedb.New(tx)
	run, err := lockBrowserRun(ctx, queries, auth, now)
	if err != nil {
		return "", "", "", false, time.Time{}, err
	}
	if !run.BrowserCapable || run.State != "ready" {
		return "", "", "", false, time.Time{}, ErrPreviewAccess
	}
	row, err := queries.ConsumeBrowserAccessHandoff(ctx, controlstatedb.ConsumeBrowserAccessHandoffParams{
		Now: timestamptz(now), TokenDigest: digest, PublicURLID: auth.PublicURLID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", "", false, time.Time{}, ErrPreviewAccess
	}
	if err != nil {
		return "", "", "", false, time.Time{}, fmt.Errorf("controlstate: redeem browser access: %w", err)
	}
	plaintext, _, err := d.storageKey.Open(row.StorageKeyID, browserContext(digest), row.CookieCiphertext)
	if err != nil {
		return "", "", "", false, time.Time{}, err
	}
	var credential browserHandoffCredential
	if err := json.Unmarshal(plaintext, &credential); err != nil || credential.PublishRunID != run.ID || credential.PublishRunNumber != run.PublishRunNumber {
		return "", "", "", false, time.Time{}, ErrPreviewAccess
	}
	cookieDigest, err := browserDigest(credential.CookieSecret)
	if err != nil || !bytes.Equal(cookieDigest, row.SessionDigest) {
		return "", "", "", false, time.Time{}, ErrPreviewAccess
	}
	if err := tx.Commit(ctx); err != nil {
		return "", "", "", false, time.Time{}, err
	}
	return credential.CookieSecret, row.ReturnPath, row.NextUrl, row.Bridge, row.ExpiresAt.Time, nil
}

func (d *Database) BrowserSession(ctx context.Context, publicURLID, token string, now time.Time) (BrowserAccessSession, error) {
	digest, err := browserDigest(token)
	if err != nil {
		return BrowserAccessSession{}, err
	}
	row, err := controlstatedb.New(d.pool).GetBrowserAccessSession(ctx, digest)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (row.RevokedAt.Valid || !row.ExpiresAt.Time.After(now)) {
		return BrowserAccessSession{}, ErrPreviewAccess
	}
	if err != nil {
		return BrowserAccessSession{}, fmt.Errorf("controlstate: read browser session: %w", err)
	}
	if _, err := controlstatedb.New(d.pool).BrowserSessionPublicURLIncluded(ctx, controlstatedb.BrowserSessionPublicURLIncludedParams{
		TokenDigest: digest, PublicURLID: publicURLID,
	}); errors.Is(err, pgx.ErrNoRows) {
		return BrowserAccessSession{}, ErrPreviewAccess
	} else if err != nil {
		return BrowserAccessSession{}, fmt.Errorf("controlstate: check browser preview URL: %w", err)
	}
	context := browserContext(digest)
	access, _, err := d.storageKey.Open(row.StorageKeyID, context, row.AccessCiphertext)
	if err != nil {
		return BrowserAccessSession{}, err
	}
	refresh, _, err := d.storageKey.Open(row.StorageKeyID, context, row.RefreshCiphertext)
	if err != nil {
		return BrowserAccessSession{}, err
	}
	return BrowserAccessSession{PreviewID: row.PreviewID.String, PublicURLID: row.PublicURLID,
		IdentityID: row.IdentityID, DisplayName: row.DisplayName, AccessToken: string(access), RefreshToken: string(refresh),
		AccessExpiresAt: row.AccessExpiresAt.Time, ExpiresAt: row.ExpiresAt.Time}, nil
}

func (d *Database) RotateBrowserSession(ctx context.Context, token, access, refresh string, expiresAt time.Time) error {
	digest, err := browserDigest(token)
	if err != nil {
		return err
	}
	context := browserContext(digest)
	sealedAccess, err := d.storageKey.Seal(context, []byte(access))
	if err != nil {
		return err
	}
	sealedRefresh, err := d.storageKey.Seal(context, []byte(refresh))
	if err != nil {
		return err
	}
	return controlstatedb.New(d.pool).RotateBrowserAccessSession(ctx, controlstatedb.RotateBrowserAccessSessionParams{
		TokenDigest: digest, AccessCiphertext: sealedAccess, RefreshCiphertext: sealedRefresh,
		AccessExpiresAt: timestamptz(expiresAt), StorageKeyID: d.storageKey.CurrentID(),
	})
}

// RefreshBrowserSession serializes authority refresh for every hostname using
// the same browser session. concurrent requests reuse the first rotation.
func (d *Database) RefreshBrowserSession(ctx context.Context, publicURLID, token string, now time.Time,
	refresh func(context.Context, string) (BrowserTokenRotation, error)) (result BrowserAccessSession, retErr error) {
	digest, err := browserDigest(token)
	if err != nil {
		return BrowserAccessSession{}, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return BrowserAccessSession{}, err
	}
	defer rollback(ctx, tx, "refresh browser session", &retErr)()
	queries := controlstatedb.New(tx)
	row, err := queries.LockBrowserAccessSession(ctx, digest)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (row.RevokedAt.Valid || !row.ExpiresAt.Time.After(now)) {
		return BrowserAccessSession{}, ErrPreviewAccess
	}
	if err != nil {
		return BrowserAccessSession{}, fmt.Errorf("controlstate: lock browser session: %w", err)
	}
	if _, err := queries.BrowserSessionPublicURLIncluded(ctx, controlstatedb.BrowserSessionPublicURLIncludedParams{
		TokenDigest: digest, PublicURLID: publicURLID,
	}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return BrowserAccessSession{}, ErrPreviewAccess
		}
		return BrowserAccessSession{}, fmt.Errorf("check browser refresh scope: %w", err)
	}
	context := browserContext(digest)
	access, _, err := d.storageKey.Open(row.StorageKeyID, context, row.AccessCiphertext)
	if err != nil {
		return BrowserAccessSession{}, err
	}
	refreshToken, _, err := d.storageKey.Open(row.StorageKeyID, context, row.RefreshCiphertext)
	if err != nil {
		return BrowserAccessSession{}, err
	}
	session := BrowserAccessSession{
		PreviewID: row.PreviewID.String, PublicURLID: row.PublicURLID, IdentityID: row.IdentityID, DisplayName: row.DisplayName,
		AccessToken: string(access), RefreshToken: string(refreshToken),
		AccessExpiresAt: row.AccessExpiresAt.Time, ExpiresAt: row.ExpiresAt.Time,
	}
	if !session.AccessExpiresAt.After(now.Add(30 * time.Second)) {
		rotated, err := refresh(ctx, session.RefreshToken)
		if err != nil {
			return BrowserAccessSession{}, err
		}
		if rotated.IdentityID != session.IdentityID || rotated.AccessToken == "" || rotated.RefreshToken == "" ||
			!rotated.AccessExpiresAt.After(now) {
			return BrowserAccessSession{}, ErrPreviewAccess
		}
		sealedAccess, err := d.storageKey.Seal(context, []byte(rotated.AccessToken))
		if err != nil {
			return BrowserAccessSession{}, err
		}
		sealedRefresh, err := d.storageKey.Seal(context, []byte(rotated.RefreshToken))
		if err != nil {
			return BrowserAccessSession{}, err
		}
		if err := queries.RotateBrowserAccessSession(ctx, controlstatedb.RotateBrowserAccessSessionParams{
			TokenDigest: digest, AccessCiphertext: sealedAccess, RefreshCiphertext: sealedRefresh,
			AccessExpiresAt: timestamptz(rotated.AccessExpiresAt), StorageKeyID: d.storageKey.CurrentID(),
		}); err != nil {
			return BrowserAccessSession{}, err
		}
		session.AccessToken, session.RefreshToken, session.AccessExpiresAt = rotated.AccessToken, rotated.RefreshToken, rotated.AccessExpiresAt
	}
	if err := tx.Commit(ctx); err != nil {
		return BrowserAccessSession{}, err
	}
	return session, nil
}

func (d *Database) RevokeBrowserSession(ctx context.Context, publicURLID, token string, now time.Time) error {
	digest, err := browserDigest(token)
	if err != nil {
		return err
	}
	return controlstatedb.New(d.pool).RevokeBrowserAccessSession(ctx, controlstatedb.RevokeBrowserAccessSessionParams{TokenDigest: digest, PublicURLID: publicURLID, Now: timestamptz(now)})
}

func (d *Database) PreviewTeamAccessForPublicURL(ctx context.Context, publicURLID string) (Preview, error) {
	row, err := controlstatedb.New(d.pool).TeamAccessForPublicURL(ctx, publicURLID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Preview{}, ErrPreviewAccess
	}
	if err != nil {
		return Preview{}, err
	}
	return Preview{ID: row.PreviewID, TeamID: row.TeamID, TeamAccessEnabled: row.TeamAccessEnabled}, nil
}

// browser authorization rechecks identity and visit permission in one transaction.
// refresh, when needed, happens before this operation and never under a team lock.
func (d *Database) BrowserAuthorization(ctx context.Context, publicURLID, token string, now time.Time) (BrowserAuthorization, error) {
	return d.browserAuthorization(ctx, publicURLID, nil, token, now)
}

// browser admission validates the exact receiving run in the same transaction
// as identity and visit permission. authority I/O has already completed.
func (d *Database) BrowserAuthorizationForRun(ctx context.Context, auth PublishRunAuthentication, token string, now time.Time) (BrowserAuthorization, error) {
	if err := validatePublishRunAuthentication(auth); err != nil {
		return BrowserAuthorization{}, err
	}
	return d.browserAuthorization(ctx, auth.PublicURLID, &auth, token, now)
}

func (d *Database) browserAuthorization(ctx context.Context, publicURLID string, auth *PublishRunAuthentication, token string, now time.Time) (result BrowserAuthorization, retErr error) {
	digest, err := browserDigest(token)
	if err != nil {
		return BrowserAuthorization{}, err
	}
	if err := d.requireOpen(); err != nil {
		return BrowserAuthorization{}, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return BrowserAuthorization{}, fmt.Errorf("check browser authorization: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "check browser authorization", &retErr)()
	queries := controlstatedb.New(tx)
	candidate, err := queries.GetFeedbackPublicURL(ctx, publicURLID)
	if errors.Is(err, pgx.ErrNoRows) {
		return BrowserAuthorization{}, ErrPreviewAccess
	}
	if err != nil {
		return BrowserAuthorization{}, fmt.Errorf("read browser public URL: %w", err)
	}
	if err := queries.LockReviewerTeam(ctx, candidate.TeamID); err != nil {
		return BrowserAuthorization{}, fmt.Errorf("lock browser team: %w", err)
	}
	var publicURL controlstatedb.ControlPublicUrl
	if auth == nil {
		publicURL, err = queries.ShareBrowserPublicURL(ctx, publicURLID)
	} else {
		var run controlstatedb.ControlPublishRun
		publicURL, run, err = lockAuthenticatedPublishRun(ctx, queries, *auth, now)
		if err != nil {
			return BrowserAuthorization{}, err
		}
		if !run.BrowserCapable || run.State != "ready" {
			return BrowserAuthorization{}, ErrPreviewAccess
		}
	}
	if errors.Is(err, pgx.ErrNoRows) || err == nil && publicURL.TeamID != candidate.TeamID {
		return BrowserAuthorization{}, ErrPreviewAccess
	}
	if err != nil {
		return BrowserAuthorization{}, fmt.Errorf("lock browser public URL: %w", err)
	}
	if publicURL.Purpose != "app" {
		return BrowserAuthorization{}, ErrPreviewAccess
	}
	identity, err := d.browserIdentity(ctx, queries, publicURL.ID, digest, now)
	if err != nil {
		return BrowserAuthorization{}, err
	}
	allowed, err := browserVisitAllowed(ctx, queries, publicURL, identity)
	if err != nil {
		return BrowserAuthorization{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return BrowserAuthorization{}, fmt.Errorf("commit browser authorization: %w", err)
	}
	return BrowserAuthorization{Identity: identity, VisitAllowed: allowed}, nil
}

// browserIdentity is called with transaction-owned queries. sharing the browser,
// control-session, and identity rows fences logout, token rotation, and disable.
func (d *Database) browserIdentity(ctx context.Context, queries *controlstatedb.Queries, publicURLID string, digest []byte, now time.Time) (BrowserIdentity, error) {
	row, err := queries.ShareBrowserAccessSession(ctx, controlstatedb.ShareBrowserAccessSessionParams{
		TokenDigest: digest, PublicURLID: publicURLID,
	})
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (row.RevokedAt.Valid || !row.ExpiresAt.Time.After(now) || !row.AccessExpiresAt.Time.After(now)) {
		return BrowserIdentity{}, ErrPreviewAccess
	}
	if err != nil {
		return BrowserIdentity{}, fmt.Errorf("lock browser identity session: %w", err)
	}
	if row.PreviewID.Valid {
		if _, err := queries.ShareBrowserPreviewPublicURL(ctx, controlstatedb.ShareBrowserPreviewPublicURLParams{
			PreviewID: row.PreviewID.String, PublicURLID: publicURLID,
		}); errors.Is(err, pgx.ErrNoRows) {
			return BrowserIdentity{}, ErrPreviewAccess
		} else if err != nil {
			return BrowserIdentity{}, fmt.Errorf("lock browser preview inclusion: %w", err)
		}
	}
	access, _, err := d.storageKey.Open(row.StorageKeyID, browserContext(digest), row.AccessCiphertext)
	if err != nil {
		return BrowserIdentity{}, fmt.Errorf("open browser identity credential: %w", err)
	}
	tokenID, tokenDigest, err := credentials.ParseAccessToken(credentials.AccessToken(access))
	if err != nil {
		return BrowserIdentity{}, ErrPreviewAccess
	}
	identity, err := queries.ShareBrowserControlIdentity(ctx, tokenID.String())
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (identity.IdentityID != row.IdentityID ||
		!credentials.SecretHashMatches(identity.AccessTokenDigest, tokenDigest) || !identity.AccessExpiresAt.Time.After(now) ||
		!identity.RefreshExpiresAt.Time.After(now) || !validFeedbackText(identity.DisplayName, 256)) {
		return BrowserIdentity{}, ErrPreviewAccess
	}
	if err != nil {
		return BrowserIdentity{}, fmt.Errorf("lock browser control identity: %w", err)
	}
	return BrowserIdentity{IdentityID: identity.IdentityID, DisplayName: identity.DisplayName, PreviewID: row.PreviewID.String}, nil
}

// browserVisitAllowed owns current ownership and team-grant decisions. callers
// have already locked the team before the public URL; identity alone is not permission.
func browserVisitAllowed(ctx context.Context, queries *controlstatedb.Queries, publicURL controlstatedb.ControlPublicUrl, identity BrowserIdentity) (bool, error) {
	if identity.IdentityID == "" || publicURL.LifecycleState != string(PublicURLLifecycleEnabled) || publicURL.Purpose != "app" {
		return false, nil
	}
	membership, err := queries.GetActivePublishRunMembership(ctx, controlstatedb.GetActivePublishRunMembershipParams{
		TeamID: publicURL.TeamID, IdentityID: identity.IdentityID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read browser membership: %w", err)
	}
	if publicURL.PublicURLScope == "member" && publicURL.MembershipID.Valid && publicURL.MembershipID.String == membership.ID ||
		publicURL.PublicURLScope == "shared" && (membership.Role == "admin" || membership.Role == "owner") {
		return true, nil
	}
	if identity.PreviewID == "" {
		return false, nil
	}
	preview, err := queries.GetPreview(ctx, identity.PreviewID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read browser preview grant: %w", err)
	}
	if preview.TeamID != publicURL.TeamID || !preview.TeamAccessEnabled {
		return false, nil
	}
	return true, nil
}
