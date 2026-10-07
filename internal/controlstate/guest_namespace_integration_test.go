package controlstate

import (
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestIntegrationGuestReservesNamespaceAndBootstrapsDomain(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "guest_namespace")
	guest, err := NewGuestTrialCredential(netip.MustParseAddr("192.0.2.7"))
	if err != nil {
		t.Fatal(err)
	}
	domainID, err := database.CreateGuestTrial(t.Context(), guest, "routes.example.test", now)
	if err != nil || domainID == "" {
		t.Fatalf("create guest trial: %q, %v", domainID, err)
	}
	stored, err := database.GuestTrialByAccessToken(t.Context(), guest.Token)
	if err != nil || stored.DomainID != domainID || stored.DNSAuthorityReference != "" {
		t.Fatalf("stored managed guest: %+v, %v", stored, err)
	}
	admin, err := database.CreateBuiltinControlSession(t.Context(), "routes.example.test", 1, time.Hour, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreateTeam(t.Context(), CreateTeamRequest{IdentityID: admin.Identity.Identity.ID,
		DisplayName: guest.NamespaceLabel, IdempotencyKey: "reserved-guest", MemberSlug: "owner"}, now); !errors.Is(err, ErrTeamNameUnavailable) {
		t.Fatalf("team reused guest namespace: %v", err)
	}
	var reserved string
	if err := database.pool.QueryRow(t.Context(), `SELECT label FROM control.managed_label_reservations WHERE label=$1`, guest.NamespaceLabel).Scan(&reserved); err != nil {
		t.Fatal(err)
	}
}

func TestIntegrationGuestNamespaceAllocationIsAtomic(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "guest_namespace_collision")
	const callers = 8
	results := make(chan error, callers)
	var workers sync.WaitGroup
	for range callers {
		workers.Go(func() {
			guest, err := NewGuestTrialCredential(netip.MustParseAddr("192.0.2.7"))
			if err == nil {
				guest.NamespaceLabel = "guest-00000000"
				_, err = database.CreateGuestTrial(t.Context(), guest, "routes.example.test", now)
			}
			results <- err
		})
	}
	workers.Wait()
	close(results)
	created := 0
	for err := range results {
		if err == nil {
			created++
		} else if !errors.Is(err, ErrGuestNamespace) {
			t.Fatal(err)
		}
	}
	if created != 1 {
		t.Fatalf("created %d guests with the same label", created)
	}
}
