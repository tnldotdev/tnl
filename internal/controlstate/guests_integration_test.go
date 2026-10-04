package controlstate

import (
	"crypto/sha256"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
)

func TestIntegrationGuestTrialCredentialAndOneCurrentPublicURL(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "guest_trial")
	guest, err := NewGuestTrialCredential(netip.MustParseAddr("192.0.2.7"))
	if err != nil {
		t.Fatal(err)
	}
	if err := database.CreateGuestTrial(t.Context(), guest, "dom_guest", "da_guest", now); err != nil {
		t.Fatal(err)
	}
	if number, err := database.AllocateGuestDemoNumber(t.Context(), guest.ID, now); err != nil || number != 1 {
		t.Fatalf("first demo number = %d, %v", number, err)
	}
	stored, err := database.GuestTrialByAccessToken(t.Context(), guest.Token)
	if err != nil || stored.ID != guest.ID || stored.NamespaceLabel != guest.NamespaceLabel || !stored.ExpiresAt.Equal(now.Add(GuestLifetime)) {
		t.Fatalf("guest = %+v, error = %v", stored, err)
	}
	if _, err := database.EnsureExternalAuthorityPrincipal(t.Context(), guest.ID, now); err != nil {
		t.Fatal(err)
	}
	request := CreatePublicURLRequest{
		GuestID: guest.ID, TeamID: guest.TeamID, DomainID: "dom_guest", MembershipID: guest.MembershipID,
		ActingIdentityID: guest.ID, IdempotencyKey: "first", RequestDigest: sha256.Sum256([]byte("first")),
		CanonicalHostname: "demo-1." + guest.NamespaceLabel + ".example.test",
		Target:            "http://127.0.0.1:3000", PublicURLScope: PublicURLScopeMember,
		AllowedIPPrefixes: []string{"192.0.2.7/32"}, DNSState: PublicURLDNSPending,
		DNSAuthorityReference: "da_guest", AuthorityIssuer: "guest", PolicyRevision: 1, Ephemeral: true,
	}
	first, err := database.CreatePublicURL(t.Context(), request, now)
	if err != nil {
		t.Fatal(err)
	}
	if owned, err := database.GuestOwnsPublicURL(t.Context(), guest.ID, first.ID); err != nil || !owned {
		t.Fatalf("guest route owned = %t, error = %v", owned, err)
	}
	second := request
	second.CanonicalHostname = first.CanonicalHostname
	second.IdempotencyKey = "second"
	second.RequestDigest = sha256.Sum256([]byte("second"))
	if _, err := database.CreatePublicURL(t.Context(), second, now.Add(time.Second)); !errors.Is(err, ErrPublishRunOpen) {
		t.Fatalf("second guest URL created while first was enabled: %v", err)
	}
	if _, err := database.AllocateGuestDemoNumber(t.Context(), guest.ID, now.Add(time.Second)); !errors.Is(err, ErrPublishRunOpen) {
		t.Fatalf("number allocated while first URL was enabled: %v", err)
	}
	if err := database.DeleteAuthorizedPublicURL(t.Context(), AuthorizedPublicURLDeleteRequest{
		PublicURLID: first.ID, TeamID: guest.TeamID, ActingIdentityID: guest.ID,
		AuthorityIssuer: "guest", PolicyRevision: 1, ExpectedMutationRevision: first.MutationRevision,
	}, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if number, err := database.AllocateGuestDemoNumber(t.Context(), guest.ID, now.Add(3*time.Second)); err != nil || number != 2 {
		t.Fatalf("second demo number = %d, %v", number, err)
	}
	second.CanonicalHostname = "demo-2." + guest.NamespaceLabel + ".example.test"
	replacement, err := database.CreatePublicURL(t.Context(), second, now.Add(3*time.Second))
	if err != nil {
		t.Fatalf("new numbered demo URL after stopping: %v", err)
	}
	if owned, err := database.GuestOwnsPublicURL(t.Context(), guest.ID, replacement.ID); err != nil || !owned {
		t.Fatalf("replacement route owned = %t, %v", owned, err)
	}
	if err := database.DeleteAuthorizedPublicURL(t.Context(), AuthorizedPublicURLDeleteRequest{
		PublicURLID: replacement.ID, TeamID: guest.TeamID, ActingIdentityID: guest.ID,
		AuthorityIssuer: "guest", PolicyRevision: 1, ExpectedMutationRevision: replacement.MutationRevision,
	}, now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.guest_trials SET used_ready_ns = $2 WHERE id = $1`, guest.ID, int64(GuestReadyAllowance)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.AllocateGuestDemoNumber(t.Context(), guest.ID, now.Add(4*time.Second)); !errors.Is(err, ErrGuestTrialSpent) {
		t.Fatalf("spent guest trial allocated another number: %v", err)
	}
}

func TestIntegrationGuestCredentialStopsAllocatingAtExpiry(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "guest_expiry")
	guest, err := NewGuestTrialCredential(netip.MustParseAddr("192.0.2.7"))
	if err != nil {
		t.Fatal(err)
	}
	if err := database.CreateGuestTrial(t.Context(), guest, "dom_guest", "da_guest", now); err != nil {
		t.Fatal(err)
	}
	if number, err := database.AllocateGuestDemoNumber(t.Context(), guest.ID, now.Add(GuestLifetime-time.Second)); err != nil || number != 1 {
		t.Fatalf("number before expiry = %d, %v", number, err)
	}
	if _, err := database.AllocateGuestDemoNumber(t.Context(), guest.ID, now.Add(GuestLifetime)); !errors.Is(err, ErrGuestTrialSpent) {
		t.Fatalf("expired guest allocated a number: %v", err)
	}
}

func TestIntegrationGuestTrialMetersReadyTimeAndBothByteDirections(t *testing.T) {
	database, now, request, _ := newPublishRunPrerequisites(t)
	guest, err := NewGuestTrialCredential(netip.MustParseAddr("192.0.2.7"))
	if err != nil {
		t.Fatal(err)
	}
	if err := database.CreateGuestTrial(t.Context(), guest, "dom_guest", "da_guest", now); err != nil {
		t.Fatal(err)
	}
	if _, err := database.pool.Exec(t.Context(), `INSERT INTO control.guest_public_urls (public_url_id, guest_id, created_at) VALUES ($1, $2, $3)`, request.PublicURLID, guest.ID, now); err != nil {
		t.Fatal(err)
	}
	setup, err := database.CreatePublishRun(t.Context(), request, now, 30*time.Second, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.guest_trials SET active_ready_at = $2 WHERE id = $1`, guest.ID, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.pool.Exec(t.Context(), `INSERT INTO control.public_url_usage_buckets
		(public_url_id, publish_run_number, team_id, acting_identity_id, bucket_start, bucket_end,
		 observed_through, ingress_bytes, egress_bytes, histogram_data, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $6, 2097152, 1048576, $7, $6)`,
		request.PublicURLID, setup.PublishRunNumber, request.TeamID, request.ActingIdentityID,
		now, now.Add(time.Minute), []byte{0}); err != nil {
		t.Fatal(err)
	}
	queries := controlstatedb.New(database.pool)
	update := controlstatedb.UpdateGuestTransferredBytesParams{
		GuestRouteID: request.PublicURLID, ObservedAt: timestamptz(now.Add(time.Minute)),
	}
	for range 2 {
		if _, err := queries.UpdateGuestTransferredBytes(t.Context(), update); err != nil {
			t.Fatal(err)
		}
	}
	if err := database.ClosePublishRun(t.Context(), setup.PublishRunID, setup.PublishRunToken, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	stored, err := database.GuestTrialByAccessToken(t.Context(), guest.Token)
	if err != nil || stored.UsedBytes != 3<<20 || stored.UsedReady != 59*time.Second {
		t.Fatalf("cumulative guest usage = %+v, error = %v", stored, err)
	}
	if count, err := database.FinalizePublicURLUsageBuckets(t.Context(), now.Add(time.Minute), now.Add(time.Minute)); err != nil || count != 0 {
		t.Fatalf("guest-only external usage deliveries = %d, %v", count, err)
	}
	var finalized bool
	if err := database.pool.QueryRow(t.Context(), `SELECT finalized FROM control.public_url_usage_buckets WHERE public_url_id = $1`, request.PublicURLID).Scan(&finalized); err != nil || !finalized {
		t.Fatalf("guest usage was not finalized: %t, %v", finalized, err)
	}
}

func TestIntegrationGuestHeartbeatClosesExhaustedTrial(t *testing.T) {
	database, now, request, _ := newPublishRunPrerequisites(t)
	guest, err := NewGuestTrialCredential(netip.MustParseAddr("192.0.2.7"))
	if err != nil {
		t.Fatal(err)
	}
	if err := database.CreateGuestTrial(t.Context(), guest, "dom_guest", "da_guest", now); err != nil {
		t.Fatal(err)
	}
	if _, err := database.pool.Exec(t.Context(), `INSERT INTO control.guest_public_urls (public_url_id, guest_id, created_at) VALUES ($1, $2, $3)`, request.PublicURLID, guest.ID, now); err != nil {
		t.Fatal(err)
	}
	setup, err := database.CreatePublishRun(t.Context(), request, now, 30*time.Second, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.pool.Exec(t.Context(), `INSERT INTO control.public_url_usage_buckets
		(public_url_id, publish_run_number, team_id, acting_identity_id, bucket_start, bucket_end,
		 observed_through, ingress_bytes, egress_bytes, histogram_data, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $6, 3145728, 3145728, $7, $6)`,
		request.PublicURLID, setup.PublishRunNumber, request.TeamID, request.ActingIdentityID,
		now, now.Add(time.Minute), []byte{0}); err != nil {
		t.Fatal(err)
	}
	if _, err := controlstatedb.New(database.pool).UpdateGuestTransferredBytes(t.Context(), controlstatedb.UpdateGuestTransferredBytesParams{
		GuestRouteID: request.PublicURLID, ObservedAt: timestamptz(now.Add(time.Minute)),
	}); err != nil {
		t.Fatal(err)
	}
	_, err = database.HeartbeatPublishRun(t.Context(), PublishRunAuthentication{
		PublishRunID: setup.PublishRunID, PublicURLID: setup.PublicURLID,
		PublishRunNumber: setup.PublishRunNumber, PublishRunToken: setup.PublishRunToken,
	}, now.Add(2*time.Second), 30*time.Second, time.Minute)
	if !errors.Is(err, ErrGuestTrialSpent) {
		t.Fatalf("exhausted guest heartbeat = %v", err)
	}
	var activeRunID *string
	if err := database.pool.QueryRow(t.Context(), `SELECT active_publish_run_id FROM control.guest_trials WHERE id = $1`, guest.ID).Scan(&activeRunID); err != nil || activeRunID != nil {
		t.Fatalf("guest retained active run = %v, %v", activeRunID, err)
	}
}
