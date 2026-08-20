package controlstate

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestIntegrationAuthorizedRouteHostnameLookup(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "hostname_lookup")
	request := builtinRouteRequest(t, database, now)
	_, suffix, _ := strings.Cut(request.CanonicalHostname, ".")
	var target Route
	for index := range routePageSize + 5 {
		candidate := request
		candidate.CanonicalHostname = fmt.Sprintf("lookup-%03d.%s", index, suffix)
		candidate.IdempotencyKey = fmt.Sprintf("lookup-%03d", index)
		candidate.RequestDigest = sha256.Sum256([]byte(candidate.IdempotencyKey))
		target = createTestRoute(t, database, candidate, now)
	}
	page, err := database.ListAuthorizedRoutes(t.Context(), request.TeamID, "")
	if err != nil || len(page.Routes) != routePageSize || page.NextCursor == "" {
		t.Fatalf("list pagination changed: %+v, %v", page, err)
	}
	got, err := database.GetAuthorizedRouteByHostname(t.Context(), request.TeamID, target.CanonicalHostname)
	if err != nil || got.ID != target.ID || got.Target != target.Target || got.LifecycleState != RouteLifecycleEnabled {
		t.Fatalf("exact lookup = %+v, %v", got, err)
	}
	for _, lookup := range [][2]string{{"team_other", target.CanonicalHostname}, {request.TeamID, "missing." + suffix}} {
		if _, err := database.GetAuthorizedRouteByHostname(t.Context(), lookup[0], lookup[1]); !errors.Is(err, ErrRouteNotFound) {
			t.Fatalf("lookup %v: %v", lookup, err)
		}
	}
	if _, err := database.GetAuthorizedRouteByHostname(t.Context(), request.TeamID, strings.ToUpper(target.CanonicalHostname)); !errors.Is(err, ErrRouteInvalid) {
		t.Fatalf("noncanonical lookup: %v", err)
	}
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.routes SET lifecycle_state = 'suspended', suspended_at = $2 WHERE id = $1`, target.ID, now); err != nil {
		t.Fatal(err)
	}
	got, err = database.GetAuthorizedRouteByHostname(t.Context(), request.TeamID, target.CanonicalHostname)
	if err != nil || got.LifecycleState != RouteLifecycleSuspended {
		t.Fatalf("suspended route disappeared: %+v, %v", got, err)
	}
	if err := database.DeleteRoute(t.Context(), request.ActingIdentityID, target.ID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := database.GetAuthorizedRouteByHostname(t.Context(), request.TeamID, target.CanonicalHostname); !errors.Is(err, ErrRouteNotFound) {
		t.Fatalf("deleted lookup: %v", err)
	}
}
