package invocation

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/publisher"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestRegionalCapabilityReachesInvocationWrappers(t *testing.T) {
	if _, ok := any(publicationControl{}).(interface {
		CreatePublishRunInRegions(context.Context, string, string, []string) (controlv1.PublishRunSetup, error)
	}); !ok {
		t.Error("public invocation hid its regional start method")
	}
	if _, ok := any(&privateProjectControl{}).(interface {
		StartServiceRunInRegions(context.Context, string, string, string, int64, []string) (controlv1.ServiceRunSetup, error)
	}); !ok {
		t.Error("private invocation hid its regional start method")
	}
}

type regionalInvocationControl struct {
	preferred []string
}

type preparedInvocationControl struct {
	publisherservice.RunControl
	prepared int
}

func (c *preparedInvocationControl) PrepareServiceRun(_ context.Context, _, _, _ string, _ controlv1.ServiceRunDeclaration) (controlv1.ServiceRunPreparation, error) {
	c.prepared++
	return controlv1.ServiceRunPreparation{RunNumber: 3}, nil
}

func (c *regionalInvocationControl) CreatePublishRunInRegions(_ context.Context, id, key string, preferred []string) (controlv1.PublishRunSetup, error) {
	c.preferred = slices.Clone(preferred)
	return controlv1.PublishRunSetup{PublicUrl: controlv1.PublicURL{Id: id}}, nil
}

func (c *regionalInvocationControl) StartServiceRunInRegions(_ context.Context, service, run, access string, number int64, preferred []string) (controlv1.ServiceRunSetup, error) {
	c.preferred = slices.Clone(preferred)
	return controlv1.ServiceRunSetup{ServiceRunId: run, RunNumber: number}, nil
}

func TestInvocationWrappersPreserveRegionalStartCapabilities(t *testing.T) {
	backend := &regionalInvocationControl{}
	var public publisher.RegionalRunControl = publicationControl{RegionalRunControl: backend}
	setup, err := public.CreatePublishRunInRegions(t.Context(), "url", "retry", []string{"ord", "sjc"})
	if err != nil || setup.PublicUrl.Id != "url" || !slices.Equal(backend.preferred, []string{"ord", "sjc"}) {
		t.Fatal("public wrapper lost measured preference", setup, err)
	}
	var private publisherservice.RegionalRunControl = &privateProjectControl{RegionalRunControl: backend}
	service, err := private.StartServiceRunInRegions(t.Context(), "service", "run", "access", 3, []string{"sjc", "ord"})
	if err != nil || service.ServiceRunId != "run" || service.RunNumber != 3 || !slices.Equal(backend.preferred, []string{"sjc", "ord"}) {
		t.Fatal("service wrapper lost measured preference", service, err)
	}
}

func TestPrivateRegionalStartRetainsPreparedObservation(t *testing.T) {
	backend := &regionalInvocationControl{}
	preparation := &preparedInvocationControl{}
	var observed uint64
	control := &privateProjectControl{RunControl: preparation, RegionalRunControl: backend, prepared: func(number uint64) error {
		observed = number
		return nil
	}}
	if _, err := control.PrepareServiceRun(t.Context(), "service", "retry", "access", controlv1.ServiceRunDeclaration{}); err != nil {
		t.Fatal(err)
	}
	if _, err := control.StartServiceRunInRegions(t.Context(), "service", "run", "access", 3, []string{"sjc", "ord"}); err != nil {
		t.Fatal(err)
	}
	if observed != 3 || control.number.Load() != 3 || preparation.prepared != 1 || !slices.Equal(backend.preferred, []string{"sjc", "ord"}) {
		t.Fatal("regional start lost private project preparation and run observation")
	}
}

func TestPublicationControlPreparesVisitorsWithoutManagementAuthentication(t *testing.T) {
	policyCalls, tokenCalls := 0, 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/visitor-policy":
			policyCalls++
			if r.Header.Get("Authorization") != "Bearer exact-run-token" {
				t.Error("policy preparation lost its scoped run credential")
			}
			_ = json.NewEncoder(w).Encode(controlv1.VisitorPolicyUpdate{})
		case "/v1/visitor-tokens":
			tokenCalls++
			if r.Header.Get("Authorization") != "" {
				t.Error("explicit visitor source borrowed management authentication")
			}
			_ = json.NewEncoder(w).Encode(controlv1.VisitorTokenResponse{VisitorToken: "prepared"})
		default:
			t.Errorf("visitor preparation called %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	client, err := clientcontrol.New(server.URL, server.Client(), credentials.AccessToken("management-token"))
	if err != nil {
		t.Fatal(err)
	}
	control := nativePublicationControl(nil, client)
	if _, err := control.ReadPublisherVisitorPolicy(t.Context(), controlv1.PublisherVisitorPolicyRequest{}, "exact-run-token"); err != nil {
		t.Fatal(err)
	}
	if _, err := control.IssueVisitorToken(t.Context(), controlv1.VisitorTokenRequest{Source: json.RawMessage(`{"kind":"browser_session","secret":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`)}); err != nil {
		t.Fatal(err)
	}
	if policyCalls != 1 || tokenCalls != 1 {
		t.Fatal("publication wrapper hid visitor preparation capabilities")
	}
}
