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

type Share struct {
	SchemaVersion                       int
	ID, PreviewID, TeamID, Scope, Label string
	ServiceIDs                          []string
	EntryServiceID, CreatedByIdentityID string
	EntryHostname                       string
	CreatedAt, ExpiresAt                time.Time
	RevokedAt                           *time.Time
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
	request.ExpiresAt = request.ExpiresAt.UTC().Truncate(time.Microsecond)
	ids := slices.Clone(request.ServiceIDs)
	slices.Sort(ids)
	if request.PreviewID != "" && !opaqueid.Valid(request.PreviewID, opaqueid.PreviewPrefix) ||
		request.ActingIdentityID == "" || len(request.Label) > 128 ||
		request.IdempotencyKey == "" || len(request.IdempotencyKey) > 128 || len(ids) < 1 || len(ids) > 32 ||
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
	member, err := serviceMembershipForActor(ctx, tx, request.TeamID, request.ActingIdentityID, now)
	if err != nil {
		return result, err
	}
	if request.PreviewID != "" {
		preview, err := q.LockPreviewForTeamAccess(ctx, request.PreviewID)
		if err != nil {
			return result, publisherLookupError(err, ErrPreviewNotFound)
		}
		if preview.TeamID != request.TeamID || preview.CreatedByIdentityID != request.ActingIdentityID || preview.DemoServiceRunID.Valid {
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
	if err = shareServicesForManagement(ctx, tx, ids, member, true); err != nil {
		return result, err
	}
	existing, err := q.FindShareRequest(ctx, controlstatedb.FindShareRequestParams{CreatedByIdentityID: request.ActingIdentityID, IdempotencyKey: request.IdempotencyKey})
	if err == nil {
		if subtle.ConstantTimeCompare(existing.RequestDigest, digest[:]) != 1 {
			return result, ErrShareIdempotency
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
	row, err := q.CreateShare(ctx, controlstatedb.CreateShareParams{ID: id, PreviewID: nullableText(request.PreviewID),
		TeamID: request.TeamID, Scope: scope, Label: request.Label, EntryServiceID: request.EntryServiceID,
		ControlSessionID: nullableText(companySessionID(ctx, request.ActingIdentityID)), CreatedByIdentityID: request.ActingIdentityID,
		IdempotencyKey: request.IdempotencyKey, RequestDigest: digest[:], SecretDigest: request.SecretFingerprint[:],
		CreatedAt: timestamptz(now), ExpiresAt: timestamptz(request.ExpiresAt)})
	if err != nil {
		return result, err
	}
	for _, service := range ids {
		if _, err = q.AddShareService(ctx, controlstatedb.AddShareServiceParams{ServiceID: service, ShareID: row.ID, IdentityID: request.ActingIdentityID}); err != nil {
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
	return result, tx.Commit(ctx)
}

// the caller validates the current human membership once. this helper reads
// service-owned provenance for every captured service; it never consumes proof.
func shareServicesForManagement(ctx context.Context, tx pgx.Tx, ids []string, member serviceMembership, lock bool) error {
	q := controlstatedb.New(tx)
	for _, id := range ids {
		var service controlstatedb.ControlService
		var err error
		if lock {
			service, err = q.LockService(ctx, id)
		} else {
			service, err = q.GetService(ctx, id)
		}
		if err != nil {
			return publisherLookupError(err, ErrShareStale)
		}
		if service.Protocol != "http" || !service.Enabled || service.DeletedAt.Valid {
			return ErrShareStale
		}
		if err = requireServiceManagement(ctx, tx, service, member); err != nil {
			return err
		}
	}
	return nil
}

// renewal reuses the service-management predicate, not a visitor grant or the
// caller's publisher identity. the saved session supplies company authentication.
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
	if len(ids) == 0 || len(ids) > 32 || !slices.Contains(ids, share.EntryServiceID) {
		return time.Time{}, ErrShareNotFound
	}
	if share.GuestID.Valid {
		var live bool
		var deadline time.Time
		err = tx.QueryRow(ctx, `SELECT control.guest_share_live(guest.id,$3) AND NOT EXISTS(
			SELECT 1 FROM control.share_services included WHERE included.share_id=$1 AND NOT EXISTS(
				SELECT 1 FROM control.services service WHERE service.guest_id=guest.id AND service.id=included.service_id
					AND service.enabled AND service.deleted_at IS NULL)),
			LEAST(guest.expires_at,control.guest_serving_deadline(guest.id,$3))
			FROM control.guest_trials guest WHERE guest.id=$2 AND guest.active_ready_at IS NOT NULL`, share.ID, share.GuestID.String, now).Scan(&live, &deadline)
		if err != nil {
			return time.Time{}, publisherLookupError(err, ErrShareNotFound)
		}
		if !live || !deadline.After(now) {
			return time.Time{}, ErrShareNotFound
		}
		return minTime(until, deadline), nil
	}
	principal := ControlPrincipal{IdentityID: share.CreatedByIdentityID, SessionID: share.ControlSessionID.String}
	if share.ControlSessionID.Valid {
		parent, err := q.GetVisitorParentSession(ctx, share.ControlSessionID.String)
		if err != nil {
			return time.Time{}, publisherLookupError(err, ErrShareNotFound)
		}
		if parent.IdentityID != share.CreatedByIdentityID || parent.RevokedAt.Valid ||
			!parent.AccessExpiresAt.Time.After(now) || !parent.RefreshExpiresAt.Time.After(now) {
			return time.Time{}, ErrShareNotFound
		}
		until = minTime(until, minTime(parent.AccessExpiresAt.Time, parent.RefreshExpiresAt.Time))
	}
	ctx = WithControlPrincipal(context.WithValue(ctx, serviceActorKey{}, nil), principal)
	member, err := serviceMembershipForActor(ctx, tx, share.TeamID, share.CreatedByIdentityID, now)
	if err != nil {
		return time.Time{}, err
	}
	if err = shareServicesForManagement(ctx, tx, ids, member, false); err != nil {
		return time.Time{}, err
	}
	return until, nil
}

func (d *Database) CreateGuestShare(ctx context.Context, guestID, serviceID, key, label string, fingerprint [32]byte, expiresAt, now time.Time) (result Share, retErr error) {
	now = now.UTC().Truncate(time.Microsecond)
	expiresAt = expiresAt.UTC().Truncate(time.Microsecond)
	if guestID == "" || !opaqueid.Valid(serviceID, opaqueid.ServicePrefix) || key == "" || len(key) > 128 || len(label) > 128 ||
		!expiresAt.After(now) || expiresAt.After(now.Add(maximumShareLifetime)) {
		return result, ErrShareInvalid
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "create guest share", &retErr)()
	if err = lockServiceAdmission(ctx, tx, serviceID); err != nil {
		return result, err
	}
	q := controlstatedb.New(tx)
	var live bool
	if err = tx.QueryRow(ctx, `SELECT control.guest_share_live($1,$3) AND EXISTS(
		SELECT 1 FROM control.services WHERE guest_id=$1 AND id=$2)`, guestID, serviceID, now).Scan(&live); err != nil {
		return result, err
	}
	if !live {
		return result, ErrShareStale
	}
	digest := sha256.Sum256([]byte(guestID + ":" + serviceID + ":" + expiresAt.Format(time.RFC3339Nano) + ":" + label))
	existing, err := q.FindShareRequest(ctx, controlstatedb.FindShareRequestParams{CreatedByIdentityID: guestID, IdempotencyKey: key})
	if err == nil {
		if subtle.ConstantTimeCompare(existing.RequestDigest, digest[:]) != 1 {
			return result, ErrShareIdempotency
		}
		if err = tx.Commit(ctx); err != nil {
			return result, err
		}
		return result, &CredentialDeliveryUnavailable{ResourceID: existing.ID}
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return result, err
	}
	count, err := q.CountActiveSharesForService(ctx, controlstatedb.CountActiveSharesForServiceParams{ServiceID: serviceID, Now: timestamptz(now)})
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
	row, err := q.CreateGuestShare(ctx, controlstatedb.CreateGuestShareParams{ID: id, GuestID: guestID, ServiceID: serviceID,
		IdempotencyKey: key, Label: label, RequestDigest: digest[:], SecretDigest: fingerprint[:], ExpiresAt: timestamptz(expiresAt), Now: timestamptz(now)})
	if err != nil {
		return result, publisherLookupError(err, ErrShareStale)
	}
	if _, err = q.AddGuestShareService(ctx, row.ID); err != nil {
		return result, publisherLookupError(err, ErrShareStale)
	}
	if err = auditPrivateMutation(ctx, tx, serviceID, "", "grant.create", row.ID, now); err != nil {
		return result, err
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

func (d *Database) ListTeamShares(ctx context.Context, team, identity, cursor string) (SharePage, error) {
	if team == "" || identity == "" || cursor != "" && !opaqueid.Valid(cursor, opaqueid.SharePrefix) {
		return SharePage{}, ErrShareInvalid
	}
	q := controlstatedb.New(d.pool)
	rows, err := q.ListTeamShares(ctx, controlstatedb.ListTeamSharesParams{TeamID: team, IdentityID: identity, AfterID: cursor})
	if err != nil {
		return SharePage{}, err
	}
	return sharePageFromRows(ctx, q, rows)
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
	if row.CreatedByIdentityID != identity || row.GuestID.Valid {
		return result, ErrShareNotFound
	}
	if _, err = q.LockLocalTeamForMutation(ctx, row.TeamID); err != nil {
		return result, err
	}
	member, err := serviceMembershipForActor(ctx, tx, row.TeamID, identity, now)
	if err != nil {
		return result, err
	}
	ids, err := q.ListShareServices(ctx, id)
	if err != nil {
		return result, err
	}
	if err = shareServicesForManagement(ctx, tx, ids, member, true); err != nil {
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
	return shareFromModel(row, ids), tx.Commit(ctx)
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
		TeamID: row.TeamID, Scope: row.Scope, Label: row.Label, ServiceIDs: ids, EntryServiceID: row.EntryServiceID,
		CreatedByIdentityID: row.CreatedByIdentityID, CreatedAt: row.CreatedAt.Time, ExpiresAt: row.ExpiresAt.Time, RevokedAt: optionalTime(row.RevokedAt)}
}
