package controlstate

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
)

func TestIntegrationInvitationEmailIsEncryptedLeasedRetriedAndScrubbed(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "invitation_email")
	admin, err := database.CreateBuiltinControlSession(t.Context(), "routes.example.test", 1, time.Hour, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	team, err := database.CreateTeam(t.Context(), CreateTeamRequest{IdentityID: admin.Identity.Identity.ID, DisplayName: "studio", MemberSlug: "owner", IdempotencyKey: "studio"}, now)
	if err != nil {
		t.Fatal(err)
	}
	create := func(key string) InvitationSecret {
		t.Helper()
		invitation, err := database.CreateTeamInvitation(t.Context(), CreateInvitationRequest{IdentityID: admin.Identity.Identity.ID, TeamID: team.ID, IdempotencyKey: key, MemberSlug: key, InitialRole: TeamRoleMember, EmailRestriction: "sam@example.com", ExpiresAt: now.Add(time.Hour), RetrySecret: make([]byte, 32), SendEmail: true}, now)
		if err != nil {
			t.Fatal(err)
		}
		return invitation
	}
	invitation := create("sam")
	var ciphertext []byte
	if err := database.pool.QueryRow(t.Context(), `SELECT payload_ciphertext FROM control.email_deliveries WHERE delivery_id=$1`, invitation.Invitation.ID).Scan(&ciphertext); err != nil || bytes.Contains(ciphertext, []byte(invitation.Secret)) || bytes.Contains(ciphertext, []byte("sam@example.com")) {
		t.Fatalf("plaintext email persisted: %v", err)
	}
	job, err := database.ClaimInvitationEmail(t.Context(), "worker-a", now)
	if err != nil || job.Payload.Data.Secret != invitation.Secret || string(job.Payload.To) != "sam@example.com" {
		t.Fatalf("claim=%+v error=%v", job, err)
	}
	if other, err := database.ClaimInvitationEmail(t.Context(), "worker-b", now); err != nil || other.ID != "" {
		t.Fatalf("duplicate claim=%+v, %v", other, err)
	}
	stale := job
	stale.Owner = "not-the-current-worker"
	err = database.FinishInvitationEmail(t.Context(), stale, 204, now)
	if reason, ok := failure.ReasonOf(err); !ok || reason != failure.ServerEmailLeaseStale || !errors.Is(err, ErrEmailDeliveryLeaseStale) {
		t.Fatalf("stale claim error = %v", err)
	}
	if err := database.FinishInvitationEmail(t.Context(), job, 503, now); err != nil {
		t.Fatal(err)
	}
	if early, err := database.ClaimInvitationEmail(t.Context(), "worker-b", now); err != nil || early.ID != "" {
		t.Fatalf("early retry=%+v, %v", early, err)
	}
	job, err = database.ClaimInvitationEmail(t.Context(), "worker-b", now.Add(3*time.Second))
	if err != nil || job.ID != invitation.Invitation.ID || job.Attempts != 2 {
		t.Fatalf("retry=%+v, %v", job, err)
	}
	if err := database.FinishInvitationEmail(t.Context(), job, 204, now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	var scrubbed bool
	if err := database.pool.QueryRow(t.Context(), `SELECT payload_ciphertext IS NULL AND storage_key_id IS NULL FROM control.email_deliveries WHERE delivery_id=$1`, job.ID).Scan(&scrubbed); err != nil || !scrubbed {
		t.Fatalf("completed payload retained: %v", err)
	}
	revoked := create("revoked")
	if err := database.RevokeTeamInvitation(t.Context(), admin.Identity.Identity.ID, team.ID, revoked.Invitation.ID, now); err != nil {
		t.Fatal(err)
	}
	if job, err := database.ClaimInvitationEmail(t.Context(), "worker-a", now); err != nil || job.ID != "" {
		t.Fatalf("revoked delivery=%+v, %v", job, err)
	}
	if err := database.pool.QueryRow(t.Context(), `SELECT payload_ciphertext IS NULL FROM control.email_deliveries WHERE delivery_id=$1`, revoked.Invitation.ID).Scan(&scrubbed); err != nil || !scrubbed {
		t.Fatalf("revoked payload retained: %v", err)
	}
}
