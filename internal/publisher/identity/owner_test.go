package identity_test

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/publisher"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/publisher/identity/publishingtest"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestEnsureOwnerPublishesExactCompanionURLsAndReusesIdentity(t *testing.T) {
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
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	defer local.Close()
	for _, purpose := range []controlv1.PublicURLPurpose{controlv1.Oauth, controlv1.Webhooks, controlv1.Alias} {
		publicURL, err := f.SavedPublicURL(t.Context(), purpose, local.URL)
		if err != nil {
			t.Fatal(err)
		}
		native, identity, err := publisheridentity.EnsureOwner(t.Context(), profile, control, authority, publicURL)
		if err != nil {
			t.Fatal(err)
		}
		reused, again, err := publisheridentity.EnsureOwner(t.Context(), profile, control, authority, publicURL)
		if err != nil || again.ClientId != identity.ClientId || again.GrantId != identity.GrantId {
			t.Fatalf("%s owner identity was not reused: %v", purpose, err)
		}
		_ = native
		ctx, cancel := context.WithCancel(t.Context())
		ready := make(chan publisher.Event, 1)
		done := make(chan error, 1)
		go func() {
			done <- publisher.Run(ctx, publisher.Config{Control: reused, ControlURL: f.URL, State: profile, TeamID: publicURL.TeamId, DomainID: publicURL.DomainId, MembershipID: *publicURL.MembershipId, PublicURLScope: publicURL.PublicUrlScope, Purpose: purpose, PolicyRevision: uint64(publicURL.PolicyRevision), Hostname: publicURL.CanonicalHostname, Target: publicURL.Target, ServiceProtocol: controlv1.Http, QUICConnector: muxsession.QUICConnector{TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13}}, TCPConnector: muxsession.TLSYamuxConnector{TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13}}, Observe: func(event publisher.Event) error {
				if event.Type == publisher.EventReady {
					ready <- event
				}
				return nil
			}})
		}()
		select {
		case event := <-ready:
			if event.PublicURLID != publicURL.Id || event.PublicURL != "https://"+publicURL.CanonicalHostname {
				cancel()
				t.Fatalf("%s published a different enrolled URL", purpose)
			}
			if status, _, err := f.Visit(t.Context(), event.PublicURL); err != nil || status != 204 {
				cancel()
				t.Fatalf("%s did not serve the exact companion URL: status=%d err=%v", purpose, status, err)
			}
		case err := <-done:
			cancel()
			t.Fatalf("%s publication failed: %v", purpose, err)
		case <-time.After(10 * time.Second):
			cancel()
			t.Fatalf("%s publication was not ready", purpose)
		}
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("publisher did not drain")
		}
	}
	if f.Enrollments.Load() != 3 || f.Runs.Load() != 3 || f.Allocations.Load() != 0 || f.Deletions.Load() != 0 {
		t.Fatalf("companion grants created unrelated URLs: enrollments=%d runs=%d allocations=%d deletions=%d", f.Enrollments.Load(), f.Runs.Load(), f.Allocations.Load(), f.Deletions.Load())
	}
}
