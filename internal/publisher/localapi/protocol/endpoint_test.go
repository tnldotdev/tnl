package protocol

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

func TestCapabilitySnapshotsOwnSelectorsAndContextViews(t *testing.T) {
	c, err := NewCapabilities("http://127.0.0.1:12345")
	if err != nil {
		t.Fatal(err)
	}
	for _, scope := range []string{"app", "invocation"} {
		t.Run(scope, func(t *testing.T) {
			selector := "web"
			request := CapabilityRequest{Scope: "app", Service: &selector}
			if scope == "invocation" {
				selector, err = opaqueid.New(opaqueid.InvocationPrefix)
				if err != nil {
					t.Fatal(err)
				}
				request = CapabilityRequest{Scope: "invocation", InvocationId: &selector}
			}
			original := selector
			issued, err := c.Issue(request)
			if err != nil {
				t.Fatal(err)
			}
			secret := issued.Capability
			selector = "changed-input"
			if scope == "app" {
				*issued.Service = "changed-result"
			} else {
				*issued.InvocationId = "changed-result"
			}
			selector = original
			again, err := c.Issue(request)
			if err != nil || again.Capability != secret || optional(again.Service) != optional(request.Service) || optional(again.InvocationId) != optional(request.InvocationId) {
				t.Fatal("input or result mutation changed the stored grant", err)
			}
			stored, found := c.grants[sha256.Sum256([]byte(secret))]
			if !found || stored.capability != secret {
				t.Fatal("grant was not indexed by its exact SHA-256 capability digest")
			}
			handler := c.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				view := Grant(r)
				if view.Scope != again.Scope || optional(view.Service) != optional(again.Service) || optional(view.InvocationId) != optional(again.InvocationId) {
					t.Fatal("authenticated grant changed")
				}
				if view.Service != nil {
					*view.Service = "changed-context"
				}
				if view.InvocationId != nil {
					*view.InvocationId = "changed-context"
				}
				fresh := Grant(r)
				if optional(fresh.Service) != optional(again.Service) || optional(fresh.InvocationId) != optional(again.InvocationId) {
					t.Fatal("Grant returned an alias into request context")
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			for range 2 {
				r := httptest.NewRequest(http.MethodGet, "/v1/health", nil)
				r.Host = "127.0.0.1:12345"
				r.RemoteAddr = "127.0.0.1:23456"
				r.Header.Set("Authorization", "Bearer "+secret)
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, r)
				if response.Code != http.StatusNoContent {
					t.Fatalf("authenticated request = %d", response.Code)
				}
			}
		})
	}
}

func TestCapabilitySweepRetainsActiveInvocationsThenExpiresThem(t *testing.T) {
	c, err := NewCapabilities("http://127.0.0.1:12345")
	if err != nil {
		t.Fatal(err)
	}
	first, err := opaqueid.New(opaqueid.InvocationPrefix)
	if err != nil {
		t.Fatal(err)
	}
	second, err := opaqueid.New(opaqueid.InvocationPrefix)
	if err != nil {
		t.Fatal(err)
	}
	active, err := c.Issue(CapabilityRequest{Scope: "invocation", InvocationId: &first})
	if err != nil {
		t.Fatal(err)
	}
	abandoned, err := c.Issue(CapabilityRequest{Scope: "invocation", InvocationId: &second})
	if err != nil {
		t.Fatal(err)
	}
	handler := c.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	status := func(e Endpoint) int {
		r := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
		r.Host, r.RemoteAddr = "127.0.0.1:12345", "127.0.0.1:23456"
		r.Header.Set("Authorization", "Bearer "+e.Capability)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w.Code
	}
	later := time.Now().Add(time.Hour)
	c.ExpireInvocations(later, map[string]bool{first: true})
	if status(active) != http.StatusNoContent || status(abandoned) != http.StatusUnauthorized {
		t.Fatal("sweep did not distinguish a registration from an abandoned grant")
	}
	c.ExpireInvocations(later.Add(time.Minute), nil)
	if status(active) != http.StatusNoContent {
		t.Fatal("sweep discarded the grant before cleanup retries could complete")
	}
	c.ExpireInvocations(later.Add(time.Hour), nil)
	if status(active) != http.StatusUnauthorized || status(c.Owner()) != http.StatusNoContent {
		t.Fatal("sweep retained an expired grant or removed the owner")
	}
}

func TestCapabilitiesReuseSelectorsWithMoreThan256Grants(t *testing.T) {
	c, err := NewCapabilities("http://127.0.0.1:12345")
	if err != nil {
		t.Fatal(err)
	}
	var first Endpoint
	for index := range 260 {
		name := fmt.Sprintf("service-%d", index)
		endpoint, err := c.Issue(CapabilityRequest{Scope: "app", Service: &name})
		if err != nil {
			t.Fatalf("grant %d: %v", index, err)
		}
		if index == 0 {
			first = endpoint
		}
	}
	again, err := c.Issue(CapabilityRequest{Scope: "app", Service: first.Service})
	if err != nil || again.Capability != first.Capability || again.Service == first.Service {
		t.Fatal("did not reuse an independent descriptor", err)
	}
}
