package publishingtest

import (
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/testutil"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestFixtureServiceExpirationIsCapturedWithoutAliasingOrReplacement(t *testing.T) {
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
	fixture := New(t, testutil.PublishingHooks{})
	service, err := fixture.SavedService(t.Context(), "temporary", controlv1.ProjectServiceConfiguration{Target: "app", Public: new(true), Ephemeral: new(true)})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Minute)
	fixed := deadline
	captured, err := fixture.backend.SetServiceExpiration(service.Id, &deadline)
	if err != nil || captured.Id != service.Id || captured.ExpiresAt == nil || !captured.ExpiresAt.Equal(fixed) {
		t.Fatal("allocation deadline was not captured in its saved service", err)
	}
	deadline = deadline.Add(time.Hour)
	*captured.ExpiresAt = fixed.Add(2 * time.Hour)
	assertFixed := func() {
		t.Helper()
		saved, _, found := fixture.backend.Service(service.Id)
		if !found || saved.ExpiresAt == nil || !saved.ExpiresAt.Equal(fixed) {
			t.Fatal("caller mutation or another capture changed the saved expiration")
		}
		*saved.ExpiresAt = fixed.Add(3 * time.Hour)
	}
	assertFixed()
	retry, err := fixture.backend.SetServiceExpiration(service.Id, new(fixed))
	if err != nil || retry.ExpiresAt == nil || !retry.ExpiresAt.Equal(fixed) {
		t.Fatal("equivalent expiration capture was not retryable", err)
	}
	for _, changed := range []*time.Time{nil, new(fixed.Add(time.Hour)), new(fixed.Add(-time.Second))} {
		if _, err := fixture.backend.SetServiceExpiration(service.Id, changed); err == nil {
			t.Fatal("another capture replaced the allocation's fixed expiration")
		}
		assertFixed()
	}
	owner, err := fixture.Owner()
	if err != nil {
		t.Fatal(err)
	}
	saved, err := owner.GetService(t.Context(), service.Id)
	if err != nil || saved.ExpiresAt == nil || !saved.ExpiresAt.Equal(fixed) {
		t.Fatal("service HTTP read lost the captured allocation deadline", err)
	}
	if _, err := fixture.backend.SetServiceExpiration("missing-service", new(fixed)); err == nil {
		t.Fatal("expiration capture manufactured an unknown saved service")
	}
}
