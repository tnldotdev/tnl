package invocation

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	controlclient "github.com/tnldotdev/tnl/internal/client/control"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestReserveConfiguredURLCreatesBeforeEnrollingPublisher(t *testing.T) {
	prefixes := []string{"192.0.2.1/32"}
	route := controlv1.PublicURL{
		Id: "url_0123456789abcdefghijkl", TeamId: "team", DomainId: "domain",
		CanonicalHostname: "web.member.example", PublicUrlScope: controlv1.Shared,
		Purpose: controlv1.App, ServiceProtocol: controlv1.Http,
		LifecycleState: controlv1.Enabled, AccessMode: controlv1.Anonymous, AllowedIpPrefixes: &prefixes,
	}
	created := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") != "Bearer session" {
			t.Error("URL management did not use the human control session")
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/public-urls":
			page := controlv1.PublicURLPage{PublicUrls: []controlv1.PublicURL{}}
			if created {
				page.PublicUrls = append(page.PublicUrls, route)
			}
			_ = json.NewEncoder(w).Encode(page)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/public-urls":
			var body controlv1.CreatePublicURLRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.CanonicalHostname != route.CanonicalHostname || body.Purpose != controlv1.App || body.Target != "" || body.AccessMode == nil || *body.AccessMode != controlv1.Anonymous {
				t.Errorf("created URL with incorrect public policy: %+v, %v", body, err)
			}
			created = true
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(route)
		default:
			t.Errorf("unexpected control request: %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	database, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(t.TempDir(), "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	state, err := database.Server(t.Context(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	control, err := controlclient.New(server.URL, server.Client(), credentials.AccessToken("session"))
	if err != nil {
		t.Fatal(err)
	}
	services := publisherServices{state: state, routes: control, teamID: route.TeamId, domainID: route.DomainId, publicURLScope: controlv1.Shared}
	cfg := publisher.Config{Hostname: route.CanonicalHostname, Purpose: route.Purpose, ServiceProtocol: route.ServiceProtocol, AccessMode: controlv1.Anonymous, AllowedIPPrefixes: prefixes}
	for range 2 {
		selected, err := reserveConfiguredURL(t.Context(), services, cfg)
		if err != nil || selected.Id != route.Id || !created {
			t.Fatalf("selected URL = %+v; created = %t, err = %v", selected, created, err)
		}
	}
	lock, err := clientstate.LockHostnameContext(t.Context(), state, cfg.Hostname)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	lookup, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	selected, err := reserveConfiguredURL(lookup, services, cfg)
	if err != nil || selected.Id != route.Id {
		t.Fatalf("unchanged URL waited for its active publisher's hostname lock: %+v, %v", selected, err)
	}
}

func TestReserveConfiguredURLReplacesVisitorAccessBeforeNativePublisher(t *testing.T) {
	route := controlv1.PublicURL{
		Id: "url_0123456789abcdefghijkl", TeamId: "team", DomainId: "domain",
		CanonicalHostname: "web.member.example", PublicUrlScope: controlv1.Shared,
		Purpose: controlv1.App, ServiceProtocol: controlv1.Http,
		LifecycleState: controlv1.Enabled, AccessMode: controlv1.Restricted, MutationRevision: 7,
	}
	updates := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") != "Bearer session" {
			t.Error("URL management did not use the human control session")
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/public-urls":
			_ = json.NewEncoder(w).Encode(controlv1.PublicURLPage{PublicUrls: []controlv1.PublicURL{route}})
		case r.Method == http.MethodPut && r.URL.Path == "/v1/public-urls/"+route.Id+"/access":
			var body controlv1.ReplaceVisitorAccessRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Mode != controlv1.Anonymous || len(body.Ip) != 0 || body.ExpectedRevision != route.MutationRevision {
				t.Errorf("replaced access with wrong policy: %+v, %v", body, err)
			}
			updates++
			route.AccessMode = controlv1.Anonymous
			route.MutationRevision++
			_ = json.NewEncoder(w).Encode(route)
		default:
			t.Errorf("unexpected control request: %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	database, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(t.TempDir(), "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	state, err := database.Server(t.Context(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	control, err := controlclient.New(server.URL, server.Client(), credentials.AccessToken("session"))
	if err != nil {
		t.Fatal(err)
	}
	services := publisherServices{state: state, routes: control, teamID: route.TeamId, domainID: route.DomainId, publicURLScope: controlv1.Shared}
	cfg := publisher.Config{Hostname: route.CanonicalHostname, Purpose: route.Purpose, ServiceProtocol: route.ServiceProtocol, AccessMode: controlv1.Anonymous}
	for range 2 {
		selected, err := reserveConfiguredURL(t.Context(), services, cfg)
		if err != nil || selected.AccessMode != controlv1.Anonymous || updates != 1 {
			t.Fatalf("selected URL = %+v; updates = %d, err = %v", selected, updates, err)
		}
	}
}
