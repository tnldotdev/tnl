package state

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/oidc"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

var (
	ErrShareNotFound    = errors.New("controlstate: share not found")
	ErrShareInvalid     = errors.New("controlstate: share is invalid")
	ErrShareIdempotency = errors.New("controlstate: share idempotency conflict")
	ErrShareStale       = errors.New("controlstate: share service state changed")
	ErrShareLimit       = errors.New("controlstate: service has too many active shares or share cookies")
)

const maximumShareLifetime = 30 * 24 * time.Hour

func signedShareCompanyContext(ctx context.Context, q *controlstatedb.Queries, team, identity string, now time.Time) ([]byte, error) {
	actor, signed := serviceActor(ctx)
	if !signed {
		return nil, nil
	}
	var selected *oidc.TeamContext
	for _, source := range actor.identity.TeamContexts {
		if source.TeamID != team {
			continue
		}
		valid, err := verifiedCompanyProof(ctx, q, identity, actor.identity.Issuer, source, now)
		if err != nil {
			return nil, err
		}
		if valid && (selected == nil || source.AuthenticatedAt < selected.AuthenticatedAt) {
			selected = new(source)
		}
	}
	if selected == nil {
		return nil, nil
	}
	return json.Marshal(selected)
}

func currentCompanyShareIssuer(ctx context.Context, tx pgx.Tx, share controlstatedb.ControlShare, source oidc.TeamContext, ids []string, now time.Time) (time.Time, error) {
	if source.TeamID != share.TeamID.String || share.ControlSessionID.Valid || share.GuestID.Valid {
		return time.Time{}, ErrShareNotFound
	}
	var issuer string
	var active bool
	member := serviceMembership{teamID: share.TeamID.String}
	err := tx.QueryRow(ctx, `SELECT person.issuer,member.id,member.role,control.active_membership(member.id,$3)
		FROM control.team_memberships member
		JOIN control.identities person ON person.id=member.identity_id AND person.disabled_at IS NULL
		WHERE member.team_id=$1 AND member.identity_id=$2 AND member.removed_at IS NULL`,
		share.TeamID.String, share.CreatedByIdentityID.String, now).Scan(&issuer, &member.id, &member.role, &active)
	if err != nil {
		return time.Time{}, publisherLookupError(err, ErrShareNotFound)
	}
	if !active {
		return time.Time{}, ErrShareNotFound
	}
	q := controlstatedb.New(tx)
	valid, err := verifiedCompanyProof(ctx, q, share.CreatedByIdentityID.String, issuer, source, now)
	if err != nil {
		return time.Time{}, err
	}
	if !valid {
		return time.Time{}, ErrShareNotFound
	}
	if err := shareServicesForManagement(ctx, tx, ids, member, shareServicesRead); err != nil {
		return time.Time{}, err
	}
	eligibility, err := q.GetCompanyEligibility(ctx, controlstatedb.GetCompanyEligibilityParams{
		IdentityConnectionID: source.IdentityConnectionID, IdentityID: share.CreatedByIdentityID.String,
	})
	if err != nil {
		return time.Time{}, publisherLookupError(err, ErrShareNotFound)
	}
	until := minTime(share.ExpiresAt.Time, time.Unix(source.AuthenticatedAt, 0).Add(CompanyAuthenticationLifetime))
	return minTime(until, eligibility.ValidUntil.Time), nil
}

type Share struct {
	SchemaVersion                                int
	ID, PreviewID, TeamID, GuestID, Scope, Label string
	ServiceIDs                                   []string
	EntryServiceID, CreatedByIdentityID          string
	EntryHostname                                string
	CreatedAt, ExpiresAt                         time.Time
	RevokedAt                                    *time.Time
}

type SharePage struct {
	Shares     []Share
	NextCursor string
}

type CreateShareRequest struct {
	PreviewID, TeamID, Label, ActingIdentityID, IdempotencyKey string
	SecretFingerprint                                          [32]byte
	ExpiresAt                                                  time.Time
	ServiceIDs                                                 []string
	EntryServiceID                                             string
}

func (d *Database) CreateShare(ctx context.Context, request CreateShareRequest, now time.Time) (result Share, retErr error) {
	now = now.UTC().Truncate(time.Microsecond)
	clock := newAuthorizationClock(now)
	request.ExpiresAt = request.ExpiresAt.UTC().Truncate(time.Microsecond)
	ids := slices.Clone(request.ServiceIDs)
	slices.Sort(ids)
	if request.PreviewID != "" && !opaqueid.Valid(request.PreviewID, opaqueid.PreviewPrefix) ||
		request.ActingIdentityID == "" || len(request.Label) > 128 ||
		request.IdempotencyKey == "" || len(request.IdempotencyKey) > 128 || len(ids) < 1 ||
		request.PreviewID == "" && len(ids) != 1 || !slices.Contains(ids, request.EntryServiceID) {
		return result, ErrShareInvalid
	}
	for index, id := range ids {
		if !opaqueid.Valid(id, opaqueid.ServicePrefix) || index > 0 && id == ids[index-1] {
			return result, ErrShareInvalid
		}
	}
	if request.TeamID == "" {
		if err := d.pool.QueryRow(ctx, `SELECT team_id FROM control.services WHERE id=$1 AND enabled AND deleted_at IS NULL`, ids[0]).Scan(&request.TeamID); err != nil {
			return result, publisherLookupError(err, ErrShareStale)
		}
	}
	encoded, err := json.Marshal(struct {
		PreviewID      string    `json:"preview_id"`
		TeamID         string    `json:"team_id"`
		Label          string    `json:"label"`
		ServiceIDs     []string  `json:"service_ids"`
		EntryServiceID string    `json:"entry_service_id"`
		ExpiresAt      time.Time `json:"expires_at"`
	}{request.PreviewID, request.TeamID, request.Label, ids, request.EntryServiceID, request.ExpiresAt})
	if err != nil {
		return result, err
	}
	digest := sha256.Sum256(encoded)
	tx, err := d.beginServiceAccess(ctx, pgx.TxOptions{})
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "create share", &retErr)()
	q := controlstatedb.New(tx)
	if _, err = q.LockLocalTeamForMutation(ctx, request.TeamID); err != nil {
		return result, publisherLookupError(err, ErrPreviewAccess)
	}
	member, err := serviceMembershipForActor(ctx, tx, request.TeamID, request.ActingIdentityID, clock.current())
	if err != nil {
		return result, err
	}
	if request.PreviewID != "" {
		preview, err := q.LockPreviewForTeamAccess(ctx, request.PreviewID)
		if err != nil {
			return result, publisherLookupError(err, ErrPreviewNotFound)
		}
		if preview.GuestID.Valid || preview.TeamID.String != request.TeamID || preview.CreatedByIdentityID.String != request.ActingIdentityID || preview.DemoServiceRunID.Valid {
			return result, ErrPreviewAccess
		}
		included, err := q.ListPreviewServices(ctx, preview.ID)
		if err != nil {
			return result, err
		}
		for _, id := range ids {
			if _, found := slices.BinarySearch(included, id); !found {
				return result, ErrShareStale
			}
		}
	}
	if err = shareServicesForManagement(ctx, tx, ids, member, shareServicesCreate); err != nil {
		return result, err
	}
	existing, err := q.FindShareRequest(ctx, controlstatedb.FindShareRequestParams{CreatedByIdentityID: text(request.ActingIdentityID), IdempotencyKey: request.IdempotencyKey})
	if err == nil {
		if subtle.ConstantTimeCompare(existing.RequestDigest, digest[:]) != 1 {
			return result, ErrShareIdempotency
		}
		if err = shareActorCurrent(ctx, clock.current()); err != nil {
			return result, err
		}
		if err = tx.Commit(ctx); err != nil {
			return result, err
		}
		return result, &CredentialDeliveryUnavailable{ResourceID: existing.ID}
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return result, err
	}
	if !request.ExpiresAt.After(now) || request.ExpiresAt.After(now.Add(maximumShareLifetime)) {
		return result, ErrShareInvalid
	}
	for _, id := range ids {
		count, err := q.CountActiveSharesForService(ctx, controlstatedb.CountActiveSharesForServiceParams{ServiceID: id, Now: timestamptz(now)})
		if err != nil {
			return result, err
		}
		if count >= 256 {
			return result, ErrShareLimit
		}
	}
	id, err := opaqueid.New(opaqueid.SharePrefix)
	if err != nil {
		return result, err
	}
	scope := "service"
	if request.PreviewID != "" {
		scope = "preview"
	}
	companyContext, err := signedShareCompanyContext(ctx, q, request.TeamID, request.ActingIdentityID, clock.current())
	if err != nil {
		return result, err
	}
	row, err := q.CreateShare(ctx, controlstatedb.CreateShareParams{ID: id, PreviewID: nullableText(request.PreviewID),
		TeamID: text(request.TeamID), Scope: scope, Label: request.Label, EntryServiceID: request.EntryServiceID,
		ControlSessionID: nullableText(companySessionID(ctx, request.ActingIdentityID)), CreatedByIdentityID: text(request.ActingIdentityID),
		IssuerCompanyContext: nullableText(string(companyContext)),
		IdempotencyKey:       request.IdempotencyKey, RequestDigest: digest[:], SecretDigest: request.SecretFingerprint[:],
		CreatedAt: timestamptz(now), ExpiresAt: timestamptz(request.ExpiresAt)})
	if err != nil {
		return result, err
	}
	for _, service := range ids {
		if _, err = q.AddShareService(ctx, controlstatedb.AddShareServiceParams{ServiceID: service, ShareID: row.ID, IdentityID: text(request.ActingIdentityID)}); err != nil {
			return result, publisherLookupError(err, ErrShareStale)
		}
		if err = auditPrivateMutation(ctx, tx, service, request.ActingIdentityID, "grant.create", row.ID, now); err != nil {
			return result, err
		}
	}
	result, err = shareWithServices(ctx, q, row)
	if err != nil {
		return result, err
	}
	entry, err := q.GetService(ctx, row.EntryServiceID)
	if err != nil {
		return result, err
	}
	result.EntryHostname = entry.CertificateHostname
	if _, err = tx.Exec(ctx, "SET CONSTRAINTS ALL IMMEDIATE"); err != nil {
		return Share{}, err
	}
	if err = shareActorCurrent(ctx, clock.current()); err != nil {
		return Share{}, err
	}
	if !request.ExpiresAt.After(clock.current()) {
		return Share{}, ErrShareInvalid
	}
	return result, tx.Commit(ctx)
}

type shareServiceOperation uint8

const (
	shareServicesRead shareServiceOperation = iota
	shareServicesCreate
	shareServicesRevoke
)

// the caller validates the current human membership once. revocation checks
// retained ownership, not availability; it cannot grant access to a tombstone.
func shareServicesForManagement(ctx context.Context, tx pgx.Tx, ids []string, member serviceMembership, operation shareServiceOperation) error {
	q := controlstatedb.New(tx)
	for _, id := range ids {
		var service controlstatedb.ControlService
		var err error
		if operation != shareServicesRead {
			service, err = q.LockService(ctx, id)
		} else {
			service, err = q.GetService(ctx, id)
		}
		if err != nil {
			return publisherLookupError(err, ErrShareStale)
		}
		if operation != shareServicesRevoke && (service.Protocol != "http" || !service.Enabled || service.DeletedAt.Valid) {
			return ErrShareStale
		}
		if err = requireStoredServiceManagement(ctx, tx, service, member, operation == shareServicesRevoke); err != nil {
			return err
		}
	}
	return nil
}

// renewal reuses the service-management predicate, not a visitor grant or the
// caller's publisher identity. the saved session retains revocation, refresh
// validity, and company authentication independently of access-token rotation.
func (d *Database) currentShareIssuer(ctx context.Context, tx pgx.Tx, share controlstatedb.ControlShare, now time.Time) (time.Time, error) {
	until := share.ExpiresAt.Time
	if share.RevokedAt.Valid || !until.After(now) {
		return time.Time{}, ErrShareNotFound
	}
	q := controlstatedb.New(tx)
	ids, err := q.ListShareServices(ctx, share.ID)
	if err != nil {
		return time.Time{}, err
	}
	if len(ids) == 0 || !slices.Contains(ids, share.EntryServiceID) {
		return time.Time{}, ErrShareNotFound
	}
	if share.GuestID.Valid {
		if share.TeamID.Valid || share.CreatedByIdentityID.Valid || share.Scope != "guest" || len(ids) != 1 || ids[0] != share.EntryServiceID {
			return time.Time{}, ErrShareNotFound
		}
		trial, err := q.GetGuestTrialByID(ctx, share.GuestID.String)
		if err != nil {
			return time.Time{}, publisherLookupError(err, ErrShareNotFound)
		}
		service, err := q.GetService(ctx, share.EntryServiceID)
		if err != nil {
			return time.Time{}, publisherLookupError(err, ErrShareNotFound)
		}
		if !guestPublicationEligible(trial, now) || service.GuestID != share.GuestID || service.TeamID.Valid ||
			!service.Enabled || service.DeletedAt.Valid {
			return time.Time{}, ErrShareNotFound
		}
		until = minTime(until, trial.ExpiresAt.Time)
		if trial.ActiveServiceRunID.Valid {
			deadline, err := q.GuestServiceServingDeadline(ctx, controlstatedb.GuestServiceServingDeadlineParams{ServiceID: service.ID, Now: timestamptz(now)})
			if err != nil || !deadline.Valid || !deadline.Time.After(now) {
				if err != nil {
					return time.Time{}, publisherLookupError(err, ErrShareNotFound)
				}
				return time.Time{}, ErrShareNotFound
			}
			until = minTime(until, deadline.Time)
		}
		return until, nil
	}
	if len(share.IssuerCompanyContext) != 0 {
		var source oidc.TeamContext
		if err := json.Unmarshal(share.IssuerCompanyContext, &source); err != nil {
			return time.Time{}, ErrShareNotFound
		}
		return currentCompanyShareIssuer(ctx, tx, share, source, ids, now)
	}
	principal := ControlPrincipal{IdentityID: share.CreatedByIdentityID.String, SessionID: share.ControlSessionID.String}
	if share.ControlSessionID.Valid {
		parent, err := q.GetVisitorParentSession(ctx, share.ControlSessionID.String)
		if err != nil {
			return time.Time{}, publisherLookupError(err, ErrShareNotFound)
		}
		if parent.IdentityID != share.CreatedByIdentityID.String || parent.RevokedAt.Valid ||
			!parent.RefreshExpiresAt.Time.After(now) {
			return time.Time{}, ErrShareNotFound
		}
		until = minTime(until, parent.RefreshExpiresAt.Time)
	}
	ctx = WithControlPrincipal(context.WithValue(ctx, serviceActorKey{}, nil), principal)
	member, err := serviceMembershipForActor(ctx, tx, share.TeamID.String, share.CreatedByIdentityID.String, now)
	if err != nil {
		return time.Time{}, err
	}
	if err = shareServicesForManagement(ctx, tx, ids, member, shareServicesRead); err != nil {
		return time.Time{}, err
	}
	deadline, err := q.CompanySubjectDeadline(ctx, controlstatedb.CompanySubjectDeadlineParams{
		TeamID: share.TeamID.String, IdentityID: principal.IdentityID, SessionID: principal.SessionID, Now: timestamptz(now),
	})
	if err != nil {
		return time.Time{}, err
	}
	if deadline.Valid && deadline.InfinityModifier == 0 {
		until = minTime(until, deadline.Time)
	}
	return until, nil
}

func (d *Database) CreateGuestShare(ctx context.Context, credential GuestCredential, serviceID, key, label string, fingerprint [32]byte, expiresAt, now time.Time) (result Share, retErr error) {
	clock := newAuthorizationClock(now)
	if !opaqueid.Valid(serviceID, opaqueid.ServicePrefix) || key == "" || len(key) > 128 || len(label) > 128 {
		return result, ErrShareInvalid
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "create guest share", &retErr)()
	q := controlstatedb.New(tx)
	trial, err := d.lockGuestCredential(ctx, q, credential, clock)
	if err != nil {
		return result, err
	}
	service, err := q.LockService(ctx, serviceID)
	if err != nil {
		return result, publisherLookupError(err, ErrShareStale)
	}
	if service.GuestID.String != trial.ID || service.TeamID.Valid || !service.Enabled || service.DeletedAt.Valid ||
		!guestPublicationEligible(trial, clock.current()) {
		return result, ErrShareStale
	}
	expiresAt = minTime(expiresAt, trial.ExpiresAt.Time).UTC().Truncate(time.Microsecond)
	encoded, err := json.Marshal(struct {
		ServiceID, Label string
		ExpiresAt        time.Time
	}{serviceID, label, expiresAt})
	if err != nil {
		return result, err
	}
	digest := sha256.Sum256(encoded)
	existing, err := q.FindGuestShareRequest(ctx, controlstatedb.FindGuestShareRequestParams{GuestID: text(trial.ID), IdempotencyKey: key})
	if err == nil {
		if subtle.ConstantTimeCompare(existing.RequestDigest, digest[:]) != 1 {
			return result, ErrShareIdempotency
		}
		return result, &CredentialDeliveryUnavailable{ResourceID: existing.ID}
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return result, err
	}
	count, err := q.CountActiveSharesForService(ctx, controlstatedb.CountActiveSharesForServiceParams{ServiceID: serviceID, Now: timestamptz(clock.current())})
	if err != nil {
		return result, err
	}
	if count >= 256 {
		return result, ErrShareLimit
	}
	id, err := opaqueid.New(opaqueid.SharePrefix)
	if err != nil {
		return result, err
	}
	row, err := q.CreateGuestShare(ctx, controlstatedb.CreateGuestShareParams{
		ID: id, GuestID: trial.ID, ServiceID: serviceID, Label: label, IdempotencyKey: key,
		RequestDigest: digest[:], SecretDigest: fingerprint[:], Now: timestamptz(clock.current()), ExpiresAt: timestamptz(expiresAt),
	})
	if err != nil {
		return result, publisherLookupError(err, ErrShareStale)
	}
	if count, err := q.AddGuestShareService(ctx, controlstatedb.AddGuestShareServiceParams{ShareID: row.ID, GuestID: text(trial.ID)}); err != nil {
		return result, err
	} else if count != 1 {
		return result, ErrShareStale
	}
	if err = auditPrivateMutation(ctx, tx, serviceID, "", "grant.create", row.ID, clock.current()); err != nil {
		return result, err
	}
	if _, err = tx.Exec(ctx, "SET CONSTRAINTS ALL IMMEDIATE"); err != nil {
		return result, err
	}
	if !guestPublicationEligible(trial, clock.current()) || !expiresAt.After(clock.current()) {
		return result, ErrShareStale
	}
	result = shareFromModel(row, []string{serviceID})
	result.EntryHostname = service.CertificateHostname
	return result, tx.Commit(ctx)
}

func (d *Database) GetShare(ctx context.Context, id string) (Share, error) {
	if !opaqueid.Valid(id, opaqueid.SharePrefix) {
		return Share{}, ErrShareNotFound
	}
	q := controlstatedb.New(d.pool)
	row, err := q.GetShare(ctx, id)
	if err != nil {
		return Share{}, publisherLookupError(err, ErrShareNotFound)
	}
	return shareWithServices(ctx, q, row)
}

func (d *Database) GetShareForManagement(ctx context.Context, id, identity string, now time.Time) (result Share, retErr error) {
	clock := newAuthorizationClock(now)
	if !opaqueid.Valid(id, opaqueid.SharePrefix) || identity == "" {
		return result, ErrShareNotFound
	}
	tx, err := d.beginServiceAccess(ctx, serviceReadOptions(ctx))
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "read managed share", &retErr)()
	q := controlstatedb.New(tx)
	row, err := q.GetShare(ctx, id)
	if err != nil {
		return result, publisherLookupError(err, ErrShareNotFound)
	}
	if row.GuestID.Valid || row.CreatedByIdentityID.String != identity {
		return result, ErrShareNotFound
	}
	member, err := serviceMembershipForActor(ctx, tx, row.TeamID.String, identity, clock.current())
	if err != nil {
		return result, err
	}
	ids, err := q.ListShareServices(ctx, id)
	if err != nil {
		return result, err
	}
	if err = shareServicesForManagement(ctx, tx, ids, member, shareServicesRead); err != nil {
		return result, err
	}
	if err = shareActorCurrent(ctx, clock.current()); err != nil {
		return result, err
	}
	return shareFromModel(row, ids), tx.Commit(ctx)
}

func (d *Database) ListShares(ctx context.Context, preview, cursor string) (SharePage, error) {
	if !opaqueid.Valid(preview, opaqueid.PreviewPrefix) || cursor != "" && !opaqueid.Valid(cursor, opaqueid.SharePrefix) {
		return SharePage{}, ErrShareInvalid
	}
	q := controlstatedb.New(d.pool)
	rows, err := q.ListShares(ctx, controlstatedb.ListSharesParams{PreviewID: text(preview), AfterID: cursor})
	if err != nil {
		return SharePage{}, err
	}
	return sharePageFromRows(ctx, q, rows)
}

func (d *Database) ListTeamShares(ctx context.Context, team, identity, cursor string) (result SharePage, retErr error) {
	if team == "" || identity == "" || cursor != "" && !opaqueid.Valid(cursor, opaqueid.SharePrefix) {
		return SharePage{}, ErrShareInvalid
	}
	tx, err := d.beginServiceAccess(ctx, serviceReadOptions(ctx))
	if err != nil {
		return SharePage{}, err
	}
	defer rollback(ctx, tx, "list managed shares", &retErr)()
	now := time.Now()
	member, err := serviceMembershipForActor(ctx, tx, team, identity, now)
	if err != nil {
		return SharePage{}, err
	}
	q := controlstatedb.New(tx)
	page := SharePage{Shares: []Share{}}
	for {
		rows, err := q.ListTeamShares(ctx, controlstatedb.ListTeamSharesParams{TeamID: text(team), IdentityID: text(identity), AfterID: cursor})
		if err != nil {
			return SharePage{}, err
		}
		for index, row := range rows {
			share, err := shareWithServices(ctx, q, row)
			if err != nil {
				return SharePage{}, err
			}
			err = shareServicesForManagement(ctx, tx, share.ServiceIDs, member, shareServicesRead)
			if err != nil && !errors.Is(err, ErrServiceAccess) && !errors.Is(err, ErrServiceManagerRequired) && !errors.Is(err, ErrShareStale) {
				return SharePage{}, err
			}
			if err == nil {
				page.Shares = append(page.Shares, share)
			}
			cursor = row.ID
			if len(page.Shares) == 100 {
				if index+1 < len(rows) || len(rows) == 101 {
					page.NextCursor = cursor
				}
				if err := shareActorCurrent(ctx, time.Now()); err != nil {
					return SharePage{}, err
				}
				return page, tx.Commit(ctx)
			}
		}
		if len(rows) < 101 {
			break
		}
	}
	if err := shareActorCurrent(ctx, time.Now()); err != nil {
		return SharePage{}, err
	}
	return page, tx.Commit(ctx)
}

func shareActorCurrent(ctx context.Context, now time.Time) error {
	if proof, signed := serviceActor(ctx); signed && !proof.identity.AssertionExpiry.After(now) {
		return ErrControlAuthentication
	}
	return nil
}

func sharePageFromRows(ctx context.Context, q *controlstatedb.Queries, rows []controlstatedb.ControlShare) (SharePage, error) {
	page := SharePage{Shares: make([]Share, 0, min(len(rows), 100))}
	for index, row := range rows {
		if index == 100 {
			page.NextCursor = rows[index-1].ID
			break
		}
		share, err := shareWithServices(ctx, q, row)
		if err != nil {
			return SharePage{}, err
		}
		page.Shares = append(page.Shares, share)
	}
	return page, nil
}

func (d *Database) RevokeShare(ctx context.Context, id, identity string, now time.Time) (result Share, retErr error) {
	clock := newAuthorizationClock(now)
	if !opaqueid.Valid(id, opaqueid.SharePrefix) || identity == "" {
		return result, ErrShareInvalid
	}
	tx, err := d.beginServiceAccess(ctx, pgx.TxOptions{})
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "revoke share", &retErr)()
	q := controlstatedb.New(tx)
	row, err := q.GetShare(ctx, id)
	if err != nil {
		return result, publisherLookupError(err, ErrShareNotFound)
	}
	if row.CreatedByIdentityID.String != identity || row.GuestID.Valid {
		return result, ErrShareNotFound
	}
	if _, err = q.LockLocalTeamForMutation(ctx, row.TeamID.String); err != nil {
		return result, err
	}
	member, err := serviceMembershipForActor(ctx, tx, row.TeamID.String, identity, clock.current())
	if err != nil {
		return result, err
	}
	ids, err := q.ListShareServices(ctx, id)
	if err != nil {
		return result, err
	}
	if err = shareServicesForManagement(ctx, tx, ids, member, shareServicesRevoke); err != nil {
		return result, err
	}
	row, err = q.RevokeShare(ctx, controlstatedb.RevokeShareParams{ShareID: id, IdentityID: identity, RevokedAt: timestamptz(now)})
	if err != nil {
		return result, publisherLookupError(err, ErrShareNotFound)
	}
	for _, service := range ids {
		if err = auditPrivateMutation(ctx, tx, service, identity, "grant.revoke", id, now); err != nil {
			return result, err
		}
	}
	if err = shareActorCurrent(ctx, clock.current()); err != nil {
		return result, err
	}
	return shareFromModel(row, ids), tx.Commit(ctx)
}

func (d *Database) RevokeGuestShare(ctx context.Context, credential GuestCredential, id string, now time.Time) (result Share, retErr error) {
	clock := newAuthorizationClock(now)
	if !opaqueid.Valid(id, opaqueid.SharePrefix) {
		return result, ErrShareInvalid
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "revoke guest share", &retErr)()
	q := controlstatedb.New(tx)
	trial, err := d.lockGuestCredential(ctx, q, credential, clock)
	if err != nil {
		return result, err
	}
	share, err := q.GetShare(ctx, id)
	if err != nil {
		return result, publisherLookupError(err, ErrShareNotFound)
	}
	if share.GuestID.String != trial.ID || share.TeamID.Valid || share.Scope != "guest" {
		return result, ErrShareNotFound
	}
	service, err := q.LockService(ctx, share.EntryServiceID)
	if err != nil {
		return result, publisherLookupError(err, ErrShareNotFound)
	}
	if service.GuestID != share.GuestID || service.TeamID.Valid {
		return result, ErrShareNotFound
	}
	row, err := q.RevokeGuestShare(ctx, controlstatedb.RevokeGuestShareParams{
		ShareID: id, GuestID: text(trial.ID), Now: timestamptz(clock.current()),
	})
	if err != nil {
		return result, err
	}
	if err = auditPrivateMutation(ctx, tx, service.ID, "", "grant.revoke", id, clock.current()); err != nil {
		return result, err
	}
	if _, err = tx.Exec(ctx, "SET CONSTRAINTS ALL IMMEDIATE"); err != nil {
		return result, err
	}
	if !trial.ExpiresAt.Time.After(clock.current()) {
		return result, ErrGuestTrialSpent
	}
	return shareFromModel(row, []string{service.ID}), tx.Commit(ctx)
}

func shareWithServices(ctx context.Context, q *controlstatedb.Queries, row controlstatedb.ControlShare) (Share, error) {
	ids, err := q.ListShareServices(ctx, row.ID)
	if err != nil {
		return Share{}, err
	}
	return shareFromModel(row, ids), nil
}

func shareFromModel(row controlstatedb.ControlShare, ids []string) Share {
	return Share{SchemaVersion: int(row.SchemaVersion), ID: row.ID, PreviewID: row.PreviewID.String,
		TeamID: row.TeamID.String, GuestID: row.GuestID.String, Scope: row.Scope, Label: row.Label, ServiceIDs: ids, EntryServiceID: row.EntryServiceID,
		CreatedByIdentityID: row.CreatedByIdentityID.String, CreatedAt: row.CreatedAt.Time, ExpiresAt: row.ExpiresAt.Time, RevokedAt: optionalTime(row.RevokedAt)}
}
