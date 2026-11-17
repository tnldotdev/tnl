package public

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationServiceExplicitHandlerConversion(t *testing.T) {
	f, session, recipient, _, service := serviceFixture(t)
	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	handler, err := NewHandler(Config{ControlURL: server.URL}, DatabaseStores(f.d), f.d, nil)
	if err != nil {
		t.Fatal(err)
	}
	mux.Handle("/", handler)
	owner, err := clientcontrol.New(server.URL, server.Client(), credentials.AccessToken(session.AccessToken))
	if err != nil {
		t.Fatal(err)
	}
	visitor, err := clientcontrol.New(server.URL, server.Client(), credentials.AccessToken(recipient.AccessToken))
	if err != nil {
		t.Fatal(err)
	}
	_, digest, err := owner.GetServiceConfiguration(t.Context(), service.ID)
	if err != nil {
		t.Fatal(err)
	}
	configure := func(client *clientcontrol.Client, target, mode, digest string) (controlv1.Service, error) {
		return client.ConfigureService(t.Context(), service.ID, controlv1.UpdateServiceRequest{
			Protocol: controlv1.ServiceProtocolHTTP, ExpectedTrustRevision: service.TrustRevision,
			ExpectedConfigurationDigest: &digest,
			Configuration: &controlv1.ProjectServiceConfiguration{Target: target,
				Http: &controlv1.ProjectServiceHTTP{Access: &controlv1.ProjectHTTPAccess{Mode: new(controlv1.VisitorAccessMode(mode))}}},
		})
	}
	if _, err := configure(owner, "app", "restricted", digest); err != nil {
		t.Fatal(err)
	}
	ordinary, ordinaryDigest, err := owner.GetServiceConfiguration(t.Context(), service.ID)
	if err != nil || ordinary == nil || ordinary.Target != "app" {
		t.Fatal("ordinary saved app was not established", err)
	}
	if _, err := configure(owner, "integration:oauth", "restricted", ordinaryDigest); err == nil {
		t.Fatal("integration conversion inferred anonymous access")
	}
	unchanged, currentDigest, err := owner.GetServiceConfiguration(t.Context(), service.ID)
	if err != nil || currentDigest != ordinaryDigest || unchanged == nil || unchanged.Target != "app" {
		t.Fatal("refused conversion mutated the ordinary app", err)
	}
	if _, err := configure(visitor, "integration:oauth", "anonymous", ordinaryDigest); err == nil {
		t.Fatal("another identity converted the saved app")
	}
	for _, target := range []string{"integration:oauth", "integration:webhooks"} {
		converted, err := configure(owner, target, "anonymous", currentDigest)
		if err != nil || converted.Id != service.ID || converted.TrustRevision != service.TrustRevision {
			t.Fatal("explicit conversion did not preserve the one saved service and target trust", target, err)
		}
		current, nextDigest, err := owner.GetServiceConfiguration(t.Context(), service.ID)
		if err != nil || current == nil || current.Target != target || nextDigest == currentDigest ||
			current.Http == nil || current.Http.Access == nil || current.Http.Access.Mode == nil || *current.Http.Access.Mode != controlv1.Anonymous {
			t.Fatal("saved integration lost explicit handler or anonymous intent", target, err)
		}
		currentDigest = nextDigest
	}
	if _, err := configure(owner, "app", "restricted", ordinaryDigest); !errors.Is(err, clientcontrol.ErrStatusConflict) {
		t.Fatal("stale ordinary declaration overwrote explicit conversion", err)
	}
	var count int
	if err := f.sql.QueryRow(t.Context(), `SELECT count(*) FROM control.services`).Scan(&count); err != nil || count != 1 {
		t.Fatal("conversion introduced another service record", count, err)
	}
}
