package state

import (
	"crypto/sha256"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

func TestIntegrationGuestTrialCredentialAndOneCurrentPublicURL(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "guest_trial")
	guest, err := NewGuestTrialCredential(netip.MustParseAddr("192.0.2.7"))
	if err != nil {
		t.Fatal(err)
	}
	domainID, err := database.CreateGuestTrial(t.Context(), guest, "example.test", now)
	if err != nil {
		t.Fatal(err)
	}
	var storedTrial string
	if err := database.pool.QueryRow(t.Context(), `SELECT row_to_json(trial)::text FROM control.guest_trials AS trial WHERE id=$1`, guest.ID).Scan(&storedTrial); err != nil ||
		strings.Contains(storedTrial, guest.SourceIP.String()) {
		t.Fatalf("guest trial stored plaintext source IP: %v", err)
	}
	if number, err := database.AllocateGuestDemoNumber(t.Context(), guest.ID, now); err != nil || number != 1 {
		t.Fatalf("first demo number = %d, %v", number, err)
	}
	stored, err := database.GuestTrialByAccessToken(t.Context(), guest.Token)
	if err != nil || stored.ID != guest.ID || stored.NamespaceLabel != guest.NamespaceLabel {
		t.Fatalf("guest = %+v, error = %v", stored, err)
	}
	if _, err := database.EnsureGuestPrincipal(t.Context(), guest.ID, now); err != nil {
		t.Fatal(err)
	}
	request := CreatePublicURLRequest{
		GuestID: guest.ID, TeamID: guest.TeamID, DomainID: domainID, MembershipID: guest.MembershipID,
		ActingIdentityID: guest.ID, IdempotencyKey: "first", RequestDigest: sha256.Sum256([]byte("first")),
		CanonicalHostname: "demo-1." + guest.NamespaceLabel + ".example.test",
		Target:            "http://127.0.0.1:3000", PublicURLScope: PublicURLScopeMember, Purpose: PublicURLPurposeDemo,
		AllowedIPPrefixes: []string{"192.0.2.7/32"}, DNSState: PublicURLDNSPending,
		PolicyRevision: 1, Ephemeral: true,
	}
	first, err := database.CreatePublicURL(t.Context(), request, now)
	if err != nil {
		t.Fatal(err)
	}
	share, err := database.CreateGuestShare(t.Context(), guest.ID, first.ID, "first-share", "trial", sha256.Sum256([]byte("reviewer-secret")), stored.ExpiresAt, now)
	if err != nil || share.Scope != "guest" || share.Label != "trial" || share.PreviewID != "" || len(share.PublicURLIDs) != 1 || share.PublicURLIDs[0] != first.ID || !share.ExpiresAt.Equal(stored.ExpiresAt) {
		t.Fatalf("guest share = %+v, %v", share, err)
	}
	if _, err := database.CreateGuestShare(t.Context(), guest.ID, first.ID, "first-share", "trial", sha256.Sum256([]byte("other-secret")), stored.ExpiresAt, now); !errors.Is(err, ErrShareIdempotency) {
		t.Fatalf("reused guest share key with different secret: %v", err)
	}
	short, err := database.CreateGuestShare(t.Context(), guest.ID, first.ID, "short-share", "", sha256.Sum256([]byte("short-lived")), now.Add(time.Hour), now)
	if err != nil || !short.ExpiresAt.Equal(now.Add(time.Hour).UTC().Truncate(time.Microsecond)) {
		t.Fatalf("guest share with shorter expiry = %+v, %v", short, err)
	}
	if _, err := database.CreateGuestShare(t.Context(), guest.ID, first.ID, "short-share", "", sha256.Sum256([]byte("short-lived")), now.Add(2*time.Hour), now); !errors.Is(err, ErrShareIdempotency) {
		t.Fatalf("reused guest share key with different expiry: %v", err)
	}
	capped, err := database.CreateGuestShare(t.Context(), guest.ID, first.ID, "capped-share", "", sha256.Sum256([]byte("trial-bound")), now.Add(4*24*time.Hour), now)
	if err != nil || !capped.ExpiresAt.Equal(stored.ExpiresAt) {
		t.Fatalf("guest share beyond trial = %+v, %v", capped, err)
	}
	unrelated, err := opaqueid.New(opaqueid.PublicURLPrefix)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreateGuestShare(t.Context(), guest.ID, unrelated, "other-share", "", sha256.Sum256([]byte("reviewer-secret")), stored.ExpiresAt, now); !errors.Is(err, ErrShareStale) {
		t.Fatalf("guest share of unrelated public URL: %v", err)
	}
	if _, err := controlstatedb.New(database.pool).GetActiveShareForPublicURL(t.Context(), controlstatedb.GetActiveShareForPublicURLParams{ShareID: share.ID, PublicURLID: first.ID, Now: timestamptz(now)}); err != nil {
		t.Fatalf("guest share not active: %v", err)
	}
	var ingressPoolID string
	if err := database.pool.QueryRow(t.Context(), `SELECT ingress_pool_id FROM control.public_urls WHERE id = $1`, first.ID).Scan(&ingressPoolID); err != nil || ingressPoolID != PrimaryIngressPoolID {
		t.Fatalf("guest public URL ingress pool = %q, %v", ingressPoolID, err)
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
		GuestID: guest.ID, PolicyRevision: 1, ExpectedMutationRevision: first.MutationRevision,
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
		GuestID: guest.ID, PolicyRevision: 1, ExpectedMutationRevision: replacement.MutationRevision,
	}, now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.guest_trials SET used_ready_ns = $2 WHERE id = $1`, guest.ID, int64(GuestReadyAllowance)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.AllocateGuestDemoNumber(t.Context(), guest.ID, now.Add(4*time.Second)); !errors.Is(err, ErrGuestTrialSpent) {
		t.Fatalf("spent guest trial allocated another number: %v", err)
	}
	if _, err := controlstatedb.New(database.pool).GetActiveShareForPublicURL(t.Context(), controlstatedb.GetActiveShareForPublicURLParams{ShareID: share.ID, PublicURLID: first.ID, Now: timestamptz(now.Add(4 * time.Second))}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("ended guest trial retained share: %v", err)
	}
}

func TestIntegrationGuestIssuanceSerializesOneNetwork(t *testing.T) {
	database, databaseURL, now := newControlStateIntegrationDatabaseWithURL(t, "guest_issuance")
	other, err := Open(t.Context(), databaseURL, testStorageKey, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(other.Close)
	const callers = 40
	results := make(chan error, callers)
	var workers sync.WaitGroup
	for index := range callers {
		workers.Add(1)
		go func() {
			defer workers.Done()
			guest, err := NewGuestTrialCredential(netip.MustParseAddr("192.0.2.7"))
			if err == nil {
				owner := database
				if index%2 == 1 {
					owner = other
				}
				_, err = owner.CreateGuestTrial(t.Context(), guest, "routes.example.test", now)
			}
			results <- err
		}()
	}
	workers.Wait()
	close(results)
	allowed, limited := 0, 0
	for err := range results {
		switch {
		case err == nil:
			allowed++
		case errors.Is(err, ErrGuestIssuance):
			limited++
		default:
			t.Fatalf("guest issuance = %v", err)
		}
	}
	if allowed != 32 || limited != callers-32 {
		t.Fatalf("guest issuance allowed=%d limited=%d", allowed, limited)
	}
}

func TestIntegrationGuestTrialSettlesIdleReadyAuthorityOnce(t *testing.T) {
	database, now, request, _ := newPublishRunPrerequisites(t)
	guest, err := NewGuestTrialCredential(netip.MustParseAddr("192.0.2.7"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreateGuestTrial(t.Context(), guest, "routes.example.test", now); err != nil {
		t.Fatal(err)
	}
	if _, err := database.pool.Exec(t.Context(), `INSERT INTO control.guest_public_urls (public_url_id, guest_id, created_at) VALUES ($1, $2, $3)`, request.PublicURLID, guest.ID, now); err != nil {
		t.Fatal(err)
	}
	setup, err := database.CreatePublishRun(t.Context(), request, now, 30*time.Second, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	queries := controlstatedb.New(database.pool)
	if count, err := queries.MarkGuestRunReady(t.Context(), controlstatedb.MarkGuestRunReadyParams{PublishRunID: text(setup.PublishRunID), ReadyAt: timestamptz(now.Add(time.Second))}); err != nil || count != 1 {
		t.Fatal(err)
	}
	if _, err := queries.UpdateGuestServingAuthority(t.Context(), controlstatedb.UpdateGuestServingAuthorityParams{PublishRunID: setup.PublishRunID, Now: timestamptz(now.Add(time.Second))}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := database.ClosePublishRun(t.Context(), setup.PublishRunID, setup.PublishRunToken, now.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	stored, err := database.GuestTrialByAccessToken(t.Context(), guest.Token)
	if err != nil || stored.UsedReady != 29*time.Second || !stored.ServingUntil.Equal(now.Add(30*time.Second)) {
		t.Fatalf("idle ready authority settlement = %+v, error = %v", stored, err)
	}
}

func TestIntegrationGuestHeartbeatClosesExhaustedTrial(t *testing.T) {
	f, guest := guestAuthorityFixture(t)
	database, now := f.database, f.now
	if _, err := database.HeartbeatPublishRun(t.Context(), f.authentication(), now.Add(time.Second), time.Hour, time.Minute); err != nil {
		t.Fatal(err)
	}
	_, err := database.HeartbeatPublishRun(t.Context(), f.authentication(), now.Add(GuestReadyAllowance), 30*time.Second, time.Minute)
	if !errors.Is(err, ErrGuestTrialSpent) {
		t.Fatalf("exhausted guest heartbeat = %v", err)
	}
	var activeRunID *string
	if err := database.pool.QueryRow(t.Context(), `SELECT active_publish_run_id FROM control.guest_trials WHERE id = $1`, guest.ID).Scan(&activeRunID); err != nil || activeRunID != nil {
		t.Fatalf("guest retained active run = %v, %v", activeRunID, err)
	}
	var endReason string
	if err := database.pool.QueryRow(t.Context(), `SELECT end_reason FROM control.guest_trials WHERE id=$1`, guest.ID).Scan(&endReason); err != nil || endReason != "ready_limit" {
		t.Fatalf("guest ready cutoff reason = %q, %v", endReason, err)
	}
	stats, err := database.RecentGuestTrialStats(t.Context(), now.Add(GuestReadyAllowance))
	if err != nil || stats.Issued != 1 || stats.ReadyLimit != 1 || stats.Expired != 0 {
		t.Fatalf("committed guest totals = %+v, %v", stats, err)
	}
}

func TestIntegrationGuestExpiryRevokesCredentialAndForgetsIPDigests(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "guest_expiry")
	guest, err := NewGuestTrialCredential(netip.MustParseAddr("192.0.2.7"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreateGuestTrial(t.Context(), guest, "routes.example.test", now); err != nil {
		t.Fatal(err)
	}
	if number, err := database.AllocateGuestDemoNumber(t.Context(), guest.ID, now.Add(GuestLifetime-time.Second)); err != nil || number != 1 {
		t.Fatalf("demo before expiry = %d, %v", number, err)
	}
	if _, err := database.AllocateGuestDemoNumber(t.Context(), guest.ID, now.Add(GuestLifetime)); !errors.Is(err, ErrGuestTrialSpent) {
		t.Fatalf("expired trial issued another demo number: %v", err)
	}
	if removed, err := database.ForgetGuestPrivateState(t.Context(), now.Add(GuestLifetime+time.Second)); err != nil || removed != 2 {
		t.Fatalf("guest cleanup removed %d records: %v", removed, err)
	}
	if _, err := database.GuestTrialByAccessToken(t.Context(), guest.Token); !errors.Is(err, ErrGuestUnknown) {
		t.Fatalf("expired credential remains usable: %v", err)
	}
	var scrubbed bool
	if err := database.pool.QueryRow(t.Context(), `SELECT source_ip_digest IS NULL AND source_ip_key_id IS NULL
		AND issuance_ip_digest IS NULL AND credential_id IS NULL AND credential_hash IS NULL
		AND end_reason = 'expired' AND ended_at = expires_at
		FROM control.guest_trials WHERE id=$1`, guest.ID).Scan(&scrubbed); err != nil || !scrubbed {
		t.Fatalf("expired guest retained private data: %t, %v", scrubbed, err)
	}
	stats, err := database.RecentGuestTrialStats(t.Context(), now.Add(GuestLifetime+time.Second))
	if err != nil || stats.Issued != 0 || stats.Allocated != 1 || stats.Expired != 1 {
		t.Fatalf("expired guest totals = %+v, %v", stats, err)
	}
}

func TestIntegrationGuestExpiryClosesRunWithoutHeartbeat(t *testing.T) {
	for _, test := range []struct {
		name, reason string
		elapsed      time.Duration
		ready        bool
	}{
		{"trial_expired", "guest_expired", GuestLifetime + time.Second, false},
		{"ready_time_spent", "guest_ready_limit", GuestReadyAllowance + 12*time.Second, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			database, now, request, _ := newPublishRunPrerequisites(t)
			guest, err := NewGuestTrialCredential(netip.MustParseAddr("192.0.2.7"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := database.CreateGuestTrial(t.Context(), guest, "routes.example.test", now); err != nil {
				t.Fatal(err)
			}
			if _, err := database.pool.Exec(t.Context(), `INSERT INTO control.guest_public_urls
				(public_url_id, guest_id, created_at) VALUES ($1, $2, $3)`, request.PublicURLID, guest.ID, now); err != nil {
				t.Fatal(err)
			}
			setup, err := database.CreatePublishRun(t.Context(), request, now, 30*time.Second, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			if test.ready {
				if _, err := controlstatedb.New(database.pool).MarkGuestRunReady(t.Context(), controlstatedb.MarkGuestRunReadyParams{PublishRunID: text(setup.PublishRunID), ReadyAt: timestamptz(now)}); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := database.pool.Exec(t.Context(), `UPDATE control.publish_runs SET publisher_expires_at=$2 WHERE id=$1`,
				setup.PublishRunID, now.Add(GuestLifetime+time.Hour)); err != nil {
				t.Fatal(err)
			}
			if _, err := controlstatedb.New(database.pool).UpdateGuestServingAuthority(t.Context(), controlstatedb.UpdateGuestServingAuthorityParams{PublishRunID: setup.PublishRunID, Now: timestamptz(now)}); err != nil {
				t.Fatal(err)
			}
			closed, err := database.ExpireSavedPublishRuns(t.Context(), now.Add(test.elapsed))
			if err != nil || closed != 1 {
				t.Fatalf("expiry cleanup closed %d runs: %v", closed, err)
			}
			var reason string
			if err := database.pool.QueryRow(t.Context(), `SELECT close_reason FROM control.publish_runs WHERE id=$1`,
				setup.PublishRunID).Scan(&reason); err != nil || reason != test.reason {
				t.Fatalf("guest closure = %q, want %q: %v", reason, test.reason, err)
			}
			var endReason string
			if err := database.pool.QueryRow(t.Context(), `SELECT end_reason FROM control.guest_trials WHERE id=$1`, guest.ID).Scan(&endReason); err != nil ||
				endReason != map[string]string{"guest_expired": "expired", "guest_ready_limit": "ready_limit"}[test.reason] {
				t.Fatalf("guest outcome = %q, %v", endReason, err)
			}
		})
	}
}
