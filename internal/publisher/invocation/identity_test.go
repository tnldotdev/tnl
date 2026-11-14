package invocation

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestReserveConfiguredURLUsesRecordedIDWithoutNameFallback(t *testing.T) {
	const id = "url_0123456789abcdefghijkl"
	for _, mode := range []string{"current", "missing", "substituted ID", "substituted hostname", "changed policy"} {
		t.Run(mode, func(t *testing.T) {
			saved := controlv1.PublicURL{
				Id: id, TeamId: "team", DomainId: "domain", Port: 25443, CanonicalHostname: "web.member.example",
				PublicUrlScope: controlv1.Shared, Purpose: controlv1.App, ServiceProtocol: controlv1.Http,
				LifecycleState: controlv1.Enabled, AccessMode: controlv1.Restricted,
			}
			switch mode {
			case "substituted ID":
				saved.Id = "url_abcdefghijkl0123456789"
			case "substituted hostname":
				saved.CanonicalHostname = "another.member.example"
			case "changed policy":
				saved.AccessMode = controlv1.Anonymous
			}
			requests := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				if r.Method != http.MethodGet || r.URL.Path != "/v1/public-urls/"+id || r.Header.Get("Authorization") != "Bearer session" {
					t.Errorf("recorded binding fell back to a name or mutation: %s %s", r.Method, r.URL)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				if mode == "missing" {
					w.WriteHeader(http.StatusNotFound)
					_ = json.NewEncoder(w).Encode(controlv1.Problem{Code: controlv1.NotFound})
					return
				}
				_ = json.NewEncoder(w).Encode(saved)
			}))
			defer server.Close()
			control, err := clientcontrol.New(server.URL, server.Client(), credentials.AccessToken("session"))
			if err != nil {
				t.Fatal(err)
			}
			services := publisherServices{routes: control, teamID: "team", domainID: "domain", publicURLScope: controlv1.Shared}
			cfg := publisher.Config{AssignedPublicURL: &controlv1.PublicURL{Id: id}, Hostname: "web.member.example",
				Purpose: controlv1.App, ServiceProtocol: controlv1.Http, AccessMode: controlv1.Restricted}
			selected, err := reserveConfiguredURL(t.Context(), services, cfg)
			if requests != 1 {
				t.Fatal("bound selection searched for or created another resource", requests)
			}
			if mode == "current" {
				if err != nil || selected.Id != id || selected.Port != saved.Port {
					t.Fatal("bound selection changed saved endpoint facts", selected, err)
				}
			} else if mode == "missing" {
				if !errors.Is(err, clientcontrol.ErrNotFound) {
					t.Fatal("missing bound URL did not remain missing", err)
				}
			} else if _, ok := failure.ReasonOf(err); !ok {
				t.Fatal("changed bound URL was not rejected", err)
			}
		})
	}
}

func TestReserveConfiguredURLCreatesBeforeEnrollingPublisher(t *testing.T) {
	prefixes := []string{"192.0.2.1/32"}
	publicURL := controlv1.PublicURL{
		Id: "url_0123456789abcdefghijkl", TeamId: "team", DomainId: "domain",
		CanonicalHostname: "web.member.example", PublicUrlScope: controlv1.Shared,
		Purpose: controlv1.App, ServiceProtocol: controlv1.Http,
		LifecycleState: controlv1.Enabled, AccessMode: controlv1.Anonymous, AllowedIpPrefixes: &prefixes, RequirePostQuantum: true,
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
				page.PublicUrls = append(page.PublicUrls, publicURL)
			}
			_ = json.NewEncoder(w).Encode(page)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/public-urls":
			var body controlv1.CreatePublicURLRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.CanonicalHostname != publicURL.CanonicalHostname || body.Purpose != controlv1.App || body.Target != "" || body.AccessMode == nil || *body.AccessMode != controlv1.Anonymous {
				t.Errorf("created URL with incorrect public policy: %+v, %v", body, err)
			}
			if body.RequirePostQuantum == nil || !*body.RequirePostQuantum {
				t.Error("configured public HTTPS requirement not sent to control")
			}
			created = true
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(publicURL)
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
	control, err := clientcontrol.New(server.URL, server.Client(), credentials.AccessToken("session"))
	if err != nil {
		t.Fatal(err)
	}
	services := publisherServices{state: state, routes: control, teamID: publicURL.TeamId, domainID: publicURL.DomainId, publicURLScope: controlv1.Shared}
	cfg := publisher.Config{Hostname: publicURL.CanonicalHostname, Purpose: publicURL.Purpose, ServiceProtocol: publicURL.ServiceProtocol, AccessMode: controlv1.Anonymous, AllowedIPPrefixes: prefixes, RequirePostQuantum: new(true)}
	for range 2 {
		selected, err := reserveConfiguredURL(t.Context(), services, cfg)
		if err != nil || selected.Id != publicURL.Id || !created {
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
	if err != nil || selected.Id != publicURL.Id {
		t.Fatalf("unchanged URL waited for its active publisher's hostname lock: %+v, %v", selected, err)
	}
}

func TestReserveConfiguredURLReplacesVisitorAccessBeforeNativePublisher(t *testing.T) {
	publicURL := controlv1.PublicURL{
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
			_ = json.NewEncoder(w).Encode(controlv1.PublicURLPage{PublicUrls: []controlv1.PublicURL{publicURL}})
		case r.Method == http.MethodPut && r.URL.Path == "/v1/public-urls/"+publicURL.Id+"/access":
			var body controlv1.ReplaceVisitorAccessRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Mode != controlv1.Anonymous || len(body.Ip) != 0 || body.ExpectedRevision != publicURL.MutationRevision {
				t.Errorf("replaced access with wrong policy: %+v, %v", body, err)
			}
			updates++
			publicURL.AccessMode = controlv1.Anonymous
			publicURL.MutationRevision++
			_ = json.NewEncoder(w).Encode(publicURL)
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
	control, err := clientcontrol.New(server.URL, server.Client(), credentials.AccessToken("session"))
	if err != nil {
		t.Fatal(err)
	}
	services := publisherServices{state: state, routes: control, teamID: publicURL.TeamId, domainID: publicURL.DomainId, publicURLScope: controlv1.Shared}
	cfg := publisher.Config{Hostname: publicURL.CanonicalHostname, Purpose: publicURL.Purpose, ServiceProtocol: publicURL.ServiceProtocol, AccessMode: controlv1.Anonymous}
	for range 2 {
		selected, err := reserveConfiguredURL(t.Context(), services, cfg)
		if err != nil || selected.AccessMode != controlv1.Anonymous || updates != 1 {
			t.Fatalf("selected URL = %+v; updates = %d, err = %v", selected, updates, err)
		}
	}
}
