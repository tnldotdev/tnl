package identity_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/publisher/identity/publishingtest"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	"github.com/tnldotdev/tnl/internal/testutil"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestEnsureOwnerPublishesExactCompanionServicesAndReusesIdentity(t *testing.T) {
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
	f := publishingtest.New(t, testutil.PublishingHooks{})
	control, err := f.Owner()
	if err != nil {
		t.Fatal(err)
	}
	authority, err := clientauthority.New(f.URL, f.HTTP, "")
	if err != nil {
		t.Fatal(err)
	}
	d, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(t.TempDir(), "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	profile, err := d.Server(t.Context(), f.URL)
	if err != nil {
		t.Fatal(err)
	}
	var aliasRequests atomic.Int32
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		aliasRequests.Add(1)
		w.Header().Set("X-Companion-Service", "alias")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer local.Close()
	type companion struct {
		service  controlv1.Service
		native   *publisheridentity.Native
		identity authorityv1.PublisherEnrollmentResult
		handler  http.Handler
		target   string
		requests *atomic.Int32
	}
	var companions []companion
	identities, grants, keys := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, name := range []string{"oauth", "webhooks", "alias"} {
		target := local.Listener.Addr().String()
		var handler http.Handler
		requests := &aliasRequests
		if name != "alias" {
			target = "app"
			requests = new(atomic.Int32)
			handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				w.Header().Set("X-Companion-Service", name)
				w.WriteHeader(http.StatusNoContent)
			})
		}
		service, err := f.SavedService(t.Context(), name, controlv1.ProjectServiceConfiguration{Target: target, Public: new(true)})
		if err != nil {
			t.Fatal(err)
		}
		_, identity, err := publisheridentity.EnsureServiceOwner(t.Context(), profile, control, authority, service)
		if err != nil {
			t.Fatal(err)
		}
		original, found, err := profile.PublisherIdentity(t.Context(), identity.ClientId)
		if err != nil || !found {
			t.Fatal("owner signing identity was not saved", err)
		}
		reused, again, err := publisheridentity.EnsureServiceOwner(t.Context(), profile, control, authority, service)
		if err != nil || again.ClientId != identity.ClientId || again.GrantId != identity.GrantId || again.KeyId != identity.KeyId {
			t.Fatalf("%s owner identity was not reused: %v", name, err)
		}
		retained, found, err := profile.PublisherIdentity(t.Context(), identity.ClientId)
		if err != nil || !found || !bytes.Equal(retained.SigningKey, original.SigningKey) {
			t.Fatal("owner retry replaced the original signing key", err)
		}
		if identity.Kind != authorityv1.Service || identity.ServiceId == nil || *identity.ServiceId != service.Id ||
			identity.DomainId != nil || identity.Namespace != nil || identities[identity.ClientId] || grants[identity.GrantId] || keys[identity.KeyId] {
			t.Fatal("companion services did not receive independent exact-service grants")
		}
		identities[identity.ClientId], grants[identity.GrantId], keys[identity.KeyId] = true, true, true
		if handler != nil {
			target = ""
		}
		companions = append(companions, companion{service, reused, identity, handler, target, requests})
	}
	ctx, cancel := context.WithCancel(t.Context())
	type result struct {
		name string
		err  error
	}
	done := make(chan result, len(companions))
	ready := make(chan string, len(companions))
	prepared := make(chan controlv1.ServiceRunPreparation, len(companions))
	for _, current := range companions {
		go func() {
			err := publisherservice.Publish(ctx, publisherservice.RunConfig{Control: current.native, Access: current.native.Access, State: profile,
				PublisherIdentityID: current.identity.ClientId, PublisherGrantID: current.identity.GrantId, PublisherKeyID: current.identity.KeyId,
				ServiceID: current.service.Id, Metadata: publisheridentity.ServiceMetadata(current.service), Target: current.target, Handler: current.handler,
				HeartbeatInterval: 10 * time.Millisecond, Prepared: func(run controlv1.ServiceRunPreparation) error {
					if run.ServiceId != current.service.Id || run.Hostname != current.service.Endpoint.Hostname || run.RunNumber != 1 ||
						run.PublisherIdentityId != current.identity.ClientId || run.PublisherGrantId != current.identity.GrantId || run.PublisherKeyId != current.identity.KeyId {
						return publisheridentity.ErrScope
					}
					prepared <- run
					return nil
				}, Ready: func() error { ready <- current.service.Id; return nil }})
			done <- result{current.service.Name, err}
		}()
	}
	joined := 0
	defer func() {
		cancel()
		for joined < len(companions) {
			select {
			case result := <-done:
				joined++
				if result.err != nil {
					t.Errorf("%s cleanup: %v", result.name, result.err)
				}
			case <-time.After(10 * time.Second):
				t.Error("companion service did not join cleanup")
				return
			}
		}
	}()
	readyIDs := map[string]bool{}
	for range companions {
		select {
		case service := <-ready:
			if readyIDs[service] {
				t.Fatal("another companion repeated a service readiness observation")
			}
			readyIDs[service] = true
		case result := <-done:
			joined++
			t.Fatalf("%s publication stopped before readiness: %v", result.name, result.err)
		case <-time.After(10 * time.Second):
			t.Fatal("companion services were not ready together")
		}
	}
	runIDs := map[string]bool{}
	for range companions {
		select {
		case run := <-prepared:
			if runIDs[run.ServiceRunId] {
				t.Fatal("independent services shared a service run")
			}
			runIDs[run.ServiceRunId] = true
		case <-time.After(10 * time.Second):
			t.Fatal("a ready companion did not report its prepared service run")
		}
	}
	permissions := make([]controlv1.VisitorTokenResponse, len(companions))
	for index, current := range companions {
		address := "https://" + current.service.Endpoint.Hostname
		if status, _, err := f.Visit(t.Context(), address); err != nil || status >= 200 && status < 300 || current.requests.Load() != 0 {
			t.Fatalf("%s restricted service admitted an anonymous visitor: status=%d err=%v", current.service.Name, status, err)
		}
		permission, err := f.OwnerVisitorToken(t.Context(), current.service.Id)
		if err != nil {
			t.Fatal(err)
		}
		permissions[index] = permission
		if status, headers, _, err := f.VisitWithHeaders(t.Context(), address, http.Header{httpaccess.VisitorTokenHeader: {permission.VisitorToken}}); err != nil ||
			status != http.StatusNoContent || headers.Get("X-Companion-Service") != current.service.Name || current.requests.Load() != 1 {
			t.Fatalf("%s did not serve its exact companion service: status=%d err=%v", current.service.Name, status, err)
		}
	}
	for index, current := range companions {
		sibling := companions[(index+1)%len(companions)]
		if _, _, err := current.native.ForService(t.Context(), sibling.service.Id); !errors.Is(err, publisheridentity.ErrScope) {
			t.Fatal("an exact companion grant selected a sibling service", err)
		}
		access, err := current.native.Access(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := control.GetPublisherService(t.Context(), sibling.service.Id, access); !errors.Is(err, clientcontrol.ErrUnauthenticated) {
			t.Fatal("signed companion access authorized another service", err)
		}
		address := "https://" + sibling.service.Endpoint.Hostname
		if status, _, _, err := f.VisitWithHeaders(t.Context(), address, http.Header{httpaccess.VisitorTokenHeader: {permissions[index].VisitorToken}}); err != nil ||
			status >= 200 && status < 300 || sibling.requests.Load() != 1 {
			t.Fatal("companion visitor permission crossed host/service bindings", status, err)
		}
	}
	cancel()
	for range companions {
		select {
		case result := <-done:
			joined++
			if result.err != nil {
				t.Fatalf("%s cleanup: %v", result.name, result.err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("publisher did not drain")
		}
	}
	for _, current := range companions {
		saved, err := control.GetService(t.Context(), current.service.Id)
		if err != nil || !saved.Enabled || saved.Id != current.service.Id {
			t.Fatal("stopping a companion publication changed its saved service", err)
		}
	}
	if f.Enrollments.Load() != 3 || f.Runs.Load() != 3 || f.Allocations.Load() != 0 || f.Deletions.Load() != 0 {
		t.Fatalf("companion grants created unrelated services: enrollments=%d runs=%d allocations=%d deletions=%d", f.Enrollments.Load(), f.Runs.Load(), f.Allocations.Load(), f.Deletions.Load())
	}
}
