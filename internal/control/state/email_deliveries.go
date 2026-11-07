package state

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/failure"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

func emailPayloadContext(id string) string {
	return "control.team_invitation_email_deliveries.payload\x00" + id
}

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

// a claimed delivery either completes and has its payload scrubbed, or returns
// to the queue after a delay. the database checks the lease before either move.
type emailDeliveryNextPhase uint8

const (
	emailDeliveryRetryQueued emailDeliveryNextPhase = iota
	emailDeliveryCompleted
)

type EmailDeliveryOutcome struct {
	phase  emailDeliveryNextPhase
	status int
}

// InvitationEmailOutcome treats only the mailer's accepted or permanently
// rejected responses as complete. transport failures use status 0 and retry.
func InvitationEmailOutcome(status int) EmailDeliveryOutcome {
	switch status {
	case 204, 400, 422:
		return EmailDeliveryOutcome{phase: emailDeliveryCompleted, status: status}
	default:
		return EmailDeliveryOutcome{phase: emailDeliveryRetryQueued, status: status}
	}
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

func (d *Database) FinishInvitationEmail(ctx context.Context, delivery EmailDelivery, outcome EmailDeliveryOutcome, now time.Time) error {
	delay := time.Second * time.Duration(1<<min(delivery.Attempts, 8))
	rows, err := controlstatedb.New(d.pool).FinishInvitationEmail(ctx, controlstatedb.FinishInvitationEmailParams{
		DeliveryID: delivery.ID, LeaseOwner: text(delivery.Owner), Complete: outcome.phase == emailDeliveryCompleted,
		Now: timestamp(now), AvailableAt: timestamp(now.Add(delay)), LastHTTPStatus: int32(outcome.status),
	})
	if err != nil {
		return err
	}
	if rows != 1 {
		return failure.Wrap("finish invitation email", failure.ServerEmailLeaseStale, ErrEmailDeliveryLeaseStale)
	}
	return nil
}
