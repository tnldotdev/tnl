package public

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationCreateServiceDeclarationAPI(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	ctx := t.Context()
	databaseURL := testutil.NewDisposablePostgresDatabaseURL(t, "create_service_api")
	if err := controlstate.Migrate(ctx, databaseURL); err != nil {
		t.Fatal(err)
	}
	d, err := controlstate.Open(ctx, databaseURL, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "", naming.ManagedURLModeGenerated)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	now := time.Now().UTC().Truncate(time.Microsecond)
	session, err := controltest.Session(ctx, d, "example.test", time.Hour, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(Config{}, DatabaseStores(d), d, nil)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	create := func(body controlv1.CreateServiceRequest, key string, want int) (controlv1.Service, []byte) {
		t.Helper()
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/v1/services", bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+session.AccessToken.String())
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Idempotency-Key", key)
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, err = io.ReadAll(response.Body)
		if err != nil || response.StatusCode != want {
			t.Fatalf("create status=%d want=%d error=%v body=%s", response.StatusCode, want, err, data)
		}
		var service controlv1.Service
		if want == http.StatusCreated || want == http.StatusOK {
			if err := json.Unmarshal(data, &service); err != nil {
				t.Fatal(err)
			}
		}
		return service, data
	}
	configuration := &controlv1.ProjectServiceConfiguration{
		Target: "http://origin.internal:8080", Public: new(true), RequirePostQuantum: new(true),
		Http: &controlv1.ProjectServiceHTTP{Limits: &controlv1.ProjectHTTPApplicationLimits{Concurrency: new(7)}},
	}
	body := controlv1.CreateServiceRequest{TeamId: session.Identity.Memberships[0].TeamID, Name: "web", Configuration: configuration}
	first, wire := create(body, "one-service", http.StatusCreated)
	if first.Protocol != controlv1.ServiceProtocolHTTP || first.Endpoint == nil || !first.Endpoint.Public ||
		first.Endpoint.Port != 443 || !first.RequirePostQuantum || first.Ephemeral || first.Source != nil {
		t.Fatal("declaration did not select the service lifecycle and endpoint", first)
	}
	for _, forbidden := range []string{"origin.internal:8080", `"configuration"`, `"target"`, `"traffic"`, `"http_limits"`} {
		if bytes.Contains(wire, []byte(forbidden)) {
			t.Fatal("creation response exposed private declaration data", forbidden)
		}
	}
	equivalent := *configuration
	equivalent.Target = "origin.internal:8080"
	body.Configuration = &equivalent
	retry, _ := create(body, "one-service", http.StatusOK)
	if retry.Id != first.Id || retry.EndpointRevision != first.EndpointRevision || retry.RequirePostQuantum != first.RequirePostQuantum {
		t.Fatal("HTTP retry created another service or endpoint")
	}
	body.Protocol = new(controlv1.Tcp)
	create(body, "conflicting-protocol", http.StatusConflict)
	body.Protocol = nil
	changed := equivalent
	changed.Public = new(false)
	body.Configuration = &changed
	create(body, "one-service", http.StatusConflict)
	changed = equivalent
	changed.Target = "different.internal:8080"
	body.Configuration = &changed
	create(body, "one-service", http.StatusConflict)
	body.Configuration = nil
	body.Protocol = new(controlv1.ServiceProtocolHTTP)
	create(body, "one-service", http.StatusConflict)
	body.Name, body.Protocol = "plain", new(controlv1.Tcp)
	plain, _ := create(body, "plain", http.StatusCreated)
	if plain.Protocol != controlv1.Tcp || plain.Endpoint == nil || plain.Endpoint.Public || plain.Endpoint.Port != 0 {
		t.Fatal("plain metadata-only service creation changed", plain)
	}
	body.Name, body.Protocol, body.Configuration = "web", nil, &equivalent
	client, err := clientcontrol.New(server.URL, server.Client(), session.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.DeleteService(ctx, first.Id, controlv1.DeleteServiceParams{ExpectedServiceRevision: &first.ServiceRevision}); err != nil {
		t.Fatal(err)
	}
	create(body, "one-service", http.StatusConflict)
}
