package public

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/security/credentials"
)

func TestIntegrationServiceRestoredForeignTeamReadMutationAndListBoundaries(t *testing.T) {
	f := newRestoredServiceHTTP(t)
	before, err := f.database.GetService(t.Context(), f.service.ID, f.actor)
	if err != nil {
		t.Fatal(err)
	}
	configuration, digest, err := f.database.GetServiceConfiguration(t.Context(), f.service.ID, f.actor)
	if err != nil {
		t.Fatal(err)
	}
	update := fmt.Sprintf(`{"protocol":"http","publisher_pool":false,"expected_trust_revision":%q,"unconditional_configuration":true,"configuration":{"target":"foreign-mutation.internal:4000"}}`,
		fmt.Sprint(f.service.TrustRevision))
	for _, test := range []struct{ method, suffix, body string }{
		{http.MethodGet, "", ""},
		{http.MethodGet, "/configuration", ""},
		{http.MethodPut, "", update},
		{http.MethodDelete, "?expected_service_revision=" + fmt.Sprint(before.ServiceRevision), ""},
	} {
		t.Run(test.method+test.suffix, func(t *testing.T) {
			status, wire, _ := f.call(f.foreign, test.method, "/v1/services/"+f.service.ID+test.suffix, "", []byte(test.body))
			var problem struct {
				Code string `json:"code"`
			}
			if status != 404 || json.Unmarshal(wire, &problem) != nil || problem.Code != "not_found" {
				t.Fatalf("foreign-team operation disclosed service state: status=%d body=%s", status, wire)
			}
		})
	}
	status, wire, _ := f.call(f.foreign, http.MethodGet, "/v1/services?team_id="+f.team, "", nil)
	if status != 404 {
		t.Fatalf("foreign-team inventory status=%d, want 404: %s", status, wire)
	}
	after, err := f.database.GetService(t.Context(), f.service.ID, f.actor)
	if err != nil || !reflect.DeepEqual(after, before) {
		t.Fatal("denied mutations changed or deleted the service", err)
	}
	next, nextDigest, err := f.database.GetServiceConfiguration(t.Context(), f.service.ID, f.actor)
	if err != nil || nextDigest != digest || !reflect.DeepEqual(next, configuration) {
		t.Fatal("denied mutation changed the protected declaration", err)
	}
	// a real current visitor grant must not turn into management authority.
	identity, err := f.database.AuthenticateAccessToken(t.Context(), credentials.AccessToken(f.foreign), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.CreateServiceGrant(t.Context(), f.service.ID, f.actor, "restored-visitor-only", "identity", identity.IdentityID, nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	granted, err := f.database.GetService(t.Context(), f.service.ID, f.actor)
	if err != nil || granted.ServiceRevision <= before.ServiceRevision {
		t.Fatal("visitor grant did not advance saved-service revision", err)
	}
	before.ServiceRevision = granted.ServiceRevision
	if !reflect.DeepEqual(granted, before) {
		t.Fatal("visitor grant changed unrelated saved-service settings")
	}
	for _, test := range []struct{ method, body string }{{http.MethodPut, update}, {http.MethodDelete, ""}} {
		path := "/v1/services/" + f.service.ID
		if test.method == http.MethodDelete {
			path += "?unconditional_delete=true"
		}
		status, wire, _ := f.call(f.foreign, test.method, path, "", []byte(test.body))
		if status != 404 {
			t.Fatalf("visitor grant authorized management: status=%d body=%s", status, wire)
		}
	}
	after, err = f.database.GetService(t.Context(), f.service.ID, f.actor)
	if err != nil || !reflect.DeepEqual(after, before) {
		t.Fatal("visitor-only management denial changed the saved service", err)
	}
	next, nextDigest, err = f.database.GetServiceConfiguration(t.Context(), f.service.ID, f.actor)
	if err != nil || nextDigest != digest || !reflect.DeepEqual(next, configuration) {
		t.Fatal("visitor-only management denial changed the protected declaration", err)
	}
}
