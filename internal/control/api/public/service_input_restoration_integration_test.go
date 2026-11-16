package public

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type restoredServiceHTTP struct {
	t              *testing.T
	database       *controlstate.Database
	server         *httptest.Server
	owner, foreign string
	actor, team    string
	service        controlstate.ServiceRecord
}

func newRestoredServiceHTTP(t *testing.T) restoredServiceHTTP {
	t.Helper()
	f, owner, foreign, team, service := serviceFixture(t)
	h, err := NewHandler(Config{}, DatabaseStores(f.d), f.d, nil)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(h)
	t.Cleanup(server.Close)
	return restoredServiceHTTP{t: t, database: f.d, server: server, owner: owner.AccessToken,
		foreign: foreign.AccessToken, actor: owner.Identity.Identity.Id, team: team.ID, service: service}
}

func (f restoredServiceHTTP) call(token, method, path, key string, data []byte) (int, []byte, http.Header) {
	f.t.Helper()
	r, err := http.NewRequestWithContext(f.t.Context(), method, f.server.URL+path, bytes.NewReader(data))
	if err != nil {
		f.t.Fatal(err)
	}
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	if key != "" {
		r.Header.Set("Idempotency-Key", key)
	}
	response, err := f.server.Client().Do(r)
	if err != nil {
		f.t.Fatal(err)
	}
	defer response.Body.Close()
	wire, err := io.ReadAll(response.Body)
	if err != nil {
		f.t.Fatal(err)
	}
	return response.StatusCode, wire, response.Header
}

func TestIntegrationServiceRestoredCanonicalIPAndPostQuantumIdempotency(t *testing.T) {
	f := newRestoredServiceHTTP(t)
	create := func(configuration string, want int) controlv1.Service {
		t.Helper()
		body := fmt.Sprintf(`{"team_id":%q,"name":"canonical-policy","configuration":%s}`, f.team, configuration)
		status, wire, _ := f.call(f.owner, http.MethodPost, "/v1/services", "canonical-policy", []byte(body))
		if status != want {
			t.Fatalf("canonical create status=%d want=%d: %s", status, want, wire)
		}
		var service controlv1.Service
		if status == 200 || status == 201 {
			if err := json.Unmarshal(wire, &service); err != nil || !service.RequirePostQuantum {
				t.Fatal("authoritative service response lost its saved visitor TLS policy", err)
			}
		}
		return service
	}
	first := create(`{"target":"http://localhost:3000","require_post_quantum":true,"http":{"access":{"mode":"restricted","ip":["2001:db8::1/64","192.0.2.9/24"]}}}`, 201)
	retry := create(`{"target":"localhost:3000","require_post_quantum":true,"http":{"access":{"mode":"restricted","ip":["192.0.2.0/24","2001:db8::/64"]}}}`, 200)
	if first.Id == "" || retry.Id != first.Id || retry.EndpointRevision != first.EndpointRevision {
		t.Fatal("canonical dual-stack policy retry allocated a second identity or endpoint")
	}
	configuration, digest, err := f.database.GetServiceConfiguration(t.Context(), first.Id, f.actor)
	if err != nil || configuration == nil || configuration.HTTP == nil || configuration.HTTP.Access == nil ||
		!reflect.DeepEqual(configuration.HTTP.Access.IP, []string{"192.0.2.0/24", "2001:db8::/64"}) {
		t.Fatal("create did not persist the canonical masked and sorted dual-stack policy", err)
	}
	create(`{"target":"localhost:3000","require_post_quantum":false,"http":{"access":{"mode":"restricted","ip":["192.0.2.0/24","2001:db8::/64"]}}}`, 409)
	create(`{"target":"localhost:3000","require_post_quantum":true,"http":{"access":{"mode":"restricted","ip":["192.0.3.0/24","2001:db8::/64"]}}}`, 409)
	after, afterDigest, err := f.database.GetServiceConfiguration(t.Context(), first.Id, f.actor)
	if err != nil || afterDigest != digest || !reflect.DeepEqual(after, configuration) {
		t.Fatal("conflicting PQ or policy intent changed the saved declaration", err)
	}
}

func TestIntegrationServiceRestoredInvalidCreateAndConfigureMatrices(t *testing.T) {
	f := newRestoredServiceHTTP(t)
	for index, test := range []struct{ name, configuration string }{
		{"null target", `{"target":null}`},
		{"null IP policy", `{"target":"localhost:3000","http":{"access":{"mode":"restricted","ip":null}}}`},
		{"null PQ", `{"target":"localhost:3000","require_post_quantum":null}`},
		{"duplicate canonical prefix", `{"target":"localhost:3000","http":{"access":{"ip":["192.0.2.1/24","192.0.2.0/24"]}}}`},
		{"target path", `{"target":"https://localhost:3000/path"}`},
		{"unknown declaration field", `{"target":"localhost:3000","credential":"private-value"}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			before, _, err := f.database.ListServices(t.Context(), f.team, f.actor, "")
			if err != nil {
				t.Fatal("read durable inventory before invalid creation", err)
			}
			body := fmt.Sprintf(`{"team_id":%q,"name":"invalid-%d","configuration":%s}`, f.team, index, test.configuration)
			status, wire, _ := f.call(f.owner, http.MethodPost, "/v1/services", fmt.Sprintf("invalid-%d", index), []byte(body))
			if status != 400 {
				t.Errorf("invalid create accepted: status=%d body=%s", status, wire)
			}
			after, _, err := f.database.ListServices(t.Context(), f.team, f.actor, "")
			if err != nil {
				t.Fatal("read durable inventory after invalid creation", err)
			}
			if !reflect.DeepEqual(before, after) {
				t.Error("invalid creation changed durable service inventory")
			}
		})
	}
	for _, test := range []struct{ name, body string }{
		{"unknown protocol", fmt.Sprintf(`{"team_id":%q,"name":"unknown-protocol","protocol":"unknown"}`, f.team)},
		{"null root", `null`},
		{"unknown root", fmt.Sprintf(`{"team_id":%q,"name":"unknown-root","protocol":"http","unexpected":true}`, f.team)},
		{"trailing value", fmt.Sprintf(`{"team_id":%q,"name":"trailing","protocol":"http"} {}`, f.team)},
	} {
		t.Run(test.name, func(t *testing.T) {
			before, _, err := f.database.ListServices(t.Context(), f.team, f.actor, "")
			if err != nil {
				t.Fatal("read durable inventory before invalid create root", err)
			}
			status, wire, _ := f.call(f.owner, http.MethodPost, "/v1/services", "invalid-root", []byte(test.body))
			if status != 400 {
				t.Errorf("invalid create root status=%d, want 400: %s", status, wire)
			}
			after, _, err := f.database.ListServices(t.Context(), f.team, f.actor, "")
			if err != nil {
				t.Fatal("read durable inventory after invalid create root", err)
			}
			if !reflect.DeepEqual(before, after) {
				t.Error("invalid create root changed durable service inventory")
			}
		})
	}
	settings := fmt.Sprintf(`"protocol":"http","publisher_pool":false,"expected_trust_revision":%q,"unconditional_configuration":true`, fmt.Sprint(f.service.TrustRevision))
	for _, test := range []struct{ name, body string }{
		{"missing trust revision", `{"protocol":"http","publisher_pool":false,"configuration":{"target":"localhost:4000"}}`},
		{"unsafe numeric revision", `{"protocol":"http","publisher_pool":false,"expected_trust_revision":9007199254740992,"configuration":{"target":"localhost:4000"}}`},
		{"null declaration", `{` + settings + `,"configuration":null}`},
		{"null target", `{` + settings + `,"configuration":{"target":null}}`},
		{"null IP policy", `{` + settings + `,"configuration":{"target":"localhost:4000","http":{"access":{"ip":null}}}}`},
		{"null PQ", `{` + settings + `,"configuration":{"target":"localhost:4000","require_post_quantum":null}}`},
		{"duplicate canonical prefix", `{` + settings + `,"configuration":{"target":"localhost:4000","http":{"access":{"ip":["192.0.2.1/24","192.0.2.0/24"]}}}}`},
		{"target path", `{` + settings + `,"configuration":{"target":"https://localhost:4000/path"}}`},
		{"unknown field", `{` + settings + `,"unexpected":true}`},
	} {
		t.Run("configure/"+test.name, func(t *testing.T) {
			before, digest, err := f.database.GetServiceConfiguration(t.Context(), f.service.ID, f.actor)
			if err != nil {
				t.Fatal("read durable declaration before invalid configuration", err)
			}
			status, wire, _ := f.call(f.owner, http.MethodPut, "/v1/services/"+f.service.ID, "", []byte(test.body))
			if status != 400 {
				t.Errorf("invalid configure accepted: status=%d body=%s", status, wire)
			}
			after, nextDigest, err := f.database.GetServiceConfiguration(t.Context(), f.service.ID, f.actor)
			if err != nil {
				t.Fatal("read durable declaration after invalid configuration", err)
			}
			if nextDigest != digest {
				t.Errorf("invalid configuration changed the durable digest: got %q, want %q", nextDigest, digest)
			}
			if !reflect.DeepEqual(after, before) {
				t.Error("invalid configuration changed the durable declaration")
			}
		})
	}
}
