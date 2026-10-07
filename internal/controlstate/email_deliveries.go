package controlstate

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
)

func emailPayloadContext(id string) string { return "control.email_deliveries.payload\x00" + id }

func (d *Database) queueInvitationEmail(ctx context.Context, queries *controlstatedb.Queries, id, teamName, to, secret string, expiresAt, now time.Time) error {
	encoded, err := json.Marshal(authorityv1.EmailDeliveryRequest{DeliveryId: id, Type: authorityv1.TeamInvitation, To: openapi_types.Email(to),
		Data: authorityv1.TeamInvitationEmail{TeamDisplayName: authorityv1.CanonicalLabel(teamName), Secret: secret, ExpiresAt: expiresAt}})
	if err != nil {
		return err
	}
	ciphertext, err := d.sealSecret(emailPayloadContext(id), encoded)
	if err != nil {
		return err
	}
	return queries.CreateInvitationEmail(ctx, controlstatedb.CreateInvitationEmailParams{DeliveryID: id, PayloadCiphertext: ciphertext, StorageKeyID: text(d.storageKey.CurrentID()), AvailableAt: timestamp(now)})
}

type EmailDelivery struct {
	ID       string
	Owner    string
	Attempts int64
	Payload  authorityv1.EmailDeliveryRequest
}

var ErrEmailDeliveryLeaseStale = errors.New("email delivery lease is stale")

func (d *Database) ClaimInvitationEmail(ctx context.Context, owner string, now time.Time) (EmailDelivery, error) {
	queries := controlstatedb.New(d.pool)
	if err := queries.DiscardInactiveInvitationEmails(ctx, timestamp(now)); err != nil {
		return EmailDelivery{}, err
	}
	row, err := queries.ClaimInvitationEmail(ctx, controlstatedb.ClaimInvitationEmailParams{LeaseOwner: text(owner), Now: timestamp(now), LeaseExpiresAt: timestamp(now.Add(time.Minute))})
	if errors.Is(err, pgx.ErrNoRows) {
		return EmailDelivery{}, nil
	}
	if err != nil {
		return EmailDelivery{}, err
	}
	payload, _, err := d.openSecret(row.StorageKeyID.String, emailPayloadContext(row.DeliveryID), row.PayloadCiphertext)
	if err != nil {
		return EmailDelivery{}, err
	}
	result := EmailDelivery{ID: row.DeliveryID, Owner: owner, Attempts: row.Attempts}
	if err := json.Unmarshal(payload, &result.Payload); err != nil {
		return EmailDelivery{}, err
	}
	return result, nil
}

func (d *Database) FinishInvitationEmail(ctx context.Context, delivery EmailDelivery, status int, now time.Time) error {
	complete := status == 204 || status == 400 || status == 422
	delay := time.Second * time.Duration(1<<min(delivery.Attempts, 8))
	rows, err := controlstatedb.New(d.pool).FinishInvitationEmail(ctx, controlstatedb.FinishInvitationEmailParams{
		DeliveryID: delivery.ID, LeaseOwner: text(delivery.Owner), Complete: complete,
		Now: timestamp(now), AvailableAt: timestamp(now.Add(delay)), LastStatus: int32(status),
	})
	if err != nil {
		return err
	}
	if rows != 1 {
		return failure.Wrap("finish invitation email", failure.ServerEmailLeaseStale, ErrEmailDeliveryLeaseStale)
	}
	return nil
}
