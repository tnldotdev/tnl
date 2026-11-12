package local

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisher"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/publisher/invocation"
	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
	"github.com/tnldotdev/tnl/internal/testutil"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type applicationAuthority func(context.Context, invocation.ApplicationSelection) (invocation.ApplicationGrant, error)

func (f applicationAuthority) ResolveApplicationPublication(ctx context.Context, selection invocation.ApplicationSelection) (invocation.ApplicationGrant, error) {
	return f(ctx, selection)
}

type applicationControl struct {
	invocation.ApplicationControl
}

func (applicationControl) PublisherIdentityID() string { return "pub_0123456789ABCDEFGHIJKL" }

func applicationRequest(t *testing.T, a *appRuntime) (publisherprotocol.Endpoint, publisherprotocol.ApplicationPublication) {
	t.Helper()
	id, err := opaqueid.New(opaqueid.InvocationPrefix)
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := a.capabilities.Issue(publisherprotocol.CapabilityRequest{Scope: "invocation", InvocationId: &id})
	if err != nil {
		t.Fatal(err)
	}
	resource, _ := opaqueid.New(opaqueid.PublicURLPrefix)
	return endpoint, publisherprotocol.ApplicationPublication{Version: 1, InvocationId: id, Owner: "0123456789abcdef0123456789abcdef", Pid: os.Getpid(), Target: "http://127.0.0.1:3000", ServerUrl: "https://control.example", Auth: json.RawMessage(`{"kind":"oidc","machine_id":"mci_0123456789ABCDEFGHIJKL","assertion":"secret-source-only-on-ipc"}`), ResourceId: &resource}
}

func applicationGrant(selection invocation.ApplicationSelection) invocation.ApplicationGrant {
	identity := "pub_0123456789ABCDEFGHIJKL"
	resource := selection.ResourceID
	hostname := "app.example"
	if selection.Namespace != "" {
		resource, _ = opaqueid.New(opaqueid.PublicURLPrefix)
		digest := sha256.Sum256([]byte(selection.InvocationID))
		label := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(digest[:16]))
		hostname = label + "." + selection.Namespace
	}
	return invocation.ApplicationGrant{Control: applicationControl{}, PublisherIdentityID: identity, PublicURL: controlv1.PublicURL{Id: resource, CanonicalHostname: hostname, Target: selection.Target, ServiceProtocol: controlv1.Http, Purpose: controlv1.App, LifecycleState: controlv1.Enabled, AccessMode: controlv1.Restricted, Ephemeral: selection.Namespace != ""}, RefreshAuth: func(context.Context, json.RawMessage) error { return nil }, Cleanup: func(context.Context) error { return nil }}
}

func TestApplicationPublicationAcceptsBeforeTrafficReadyAndKeepsProbeSeparate(t *testing.T) {
	a, _ := testAppRuntimeWorkers(t, true)
	endpoint, request := applicationRequest(t, a)
	var resolves atomic.Int32
	var refreshes atomic.Int32
	a.ApplicationAuthority = applicationAuthority(func(_ context.Context, selection invocation.ApplicationSelection) (invocation.ApplicationGrant, error) {
		resolves.Add(1)
		if selection.ResourceID != *request.ResourceId || string(selection.Auth) != string(request.Auth) || selection.Namespace != "" {
			t.Error("explicit authority selection lost")
		}
		grant := applicationGrant(selection)
		grant.RefreshAuth = func(_ context.Context, proof json.RawMessage) error {
			refreshes.Add(1)
			if string(proof) != `{"kind":"oidc","machine_id":"mci_0123456789ABCDEFGHIJKL","assertion":"refreshed-proof"}` {
				t.Error("new proof did not reach the existing identity source")
			}
			return nil
		}
		return grant, nil
	})
	started, provision := make(chan struct{}), make(chan struct{})
	a.workers.RunPublisher = func(ctx context.Context, cfg publisher.Config) error {
		if cfg.Identity == nil || cfg.Identity.PublisherIdentityID() != cfg.PublisherIdentityID || cfg.Audit == nil || cfg.VisitorControl == nil || cfg.BrowserControl == nil || cfg.Shares == nil {
			return errors.New("application publication lost explicit native capabilities")
		}
		close(started)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-provision:
			return readyInvocation(ctx, cfg)
		}
	}
	var accepted publisherprotocol.AcceptedPublication
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if err := publisherprotocol.Call(ctx, endpoint, "POST", "/v1/publications", request, &accepted); err != nil {
		t.Fatal("publish waited for traffic readiness", err)
	}
	<-started
	var snapshot publisherapp.Snapshot
	if err := publisherprotocol.Call(t.Context(), endpoint, "GET", "/v1/status", nil, &snapshot); err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Services) != 1 || !snapshot.Services[0].Registered || snapshot.Services[0].Routable || snapshot.Services[0].Ready || accepted.PublicUrlId != *request.ResourceId {
		t.Fatalf("accepted registration conflated readiness: %+v %+v", accepted, snapshot)
	}
	encoded, _ := json.Marshal(snapshot)
	if bytes.Contains(encoded, []byte("secret-source")) {
		t.Fatal("authentication reached the journal")
	}
	// refreshed proof bytes do not replace or allocate another publication.
	request.Auth = json.RawMessage(`{"kind":"oidc","machine_id":"mci_0123456789ABCDEFGHIJKL","assertion":"refreshed-proof"}`)
	var repeated publisherprotocol.AcceptedPublication
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/publications", request, &repeated); err != nil || repeated != accepted || resolves.Load() != 1 || refreshes.Load() != 1 {
		t.Fatalf("recovery did not reuse accepted publication: %+v %v", repeated, err)
	}
	close(provision)
	waitInvocation(t, a, func(snapshot publisherapp.Snapshot) bool {
		for _, service := range snapshot.Services {
			if service.RegistrationID == accepted.Registration.RegistrationID {
				if service.Ready {
					t.Fatal("traffic readiness invented an application probe")
				}
				return service.Routable
			}
		}
		return false
	})
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/unregister", accepted.Registration, nil); err != nil {
		t.Fatal(err)
	}
	if err := publisherprotocol.Call(t.Context(), endpoint, "DELETE", "/v1/capability", nil, nil); err != nil {
		t.Fatal(err)
	}
}

func TestApplicationPublicationLaterFailureIsObservedAfterAcceptance(t *testing.T) {
	a, _ := testAppRuntimeWorkers(t, true)
	endpoint, request := applicationRequest(t, a)
	a.ApplicationAuthority = applicationAuthority(func(_ context.Context, selection invocation.ApplicationSelection) (invocation.ApplicationGrant, error) {
		return applicationGrant(selection), nil
	})
	a.workers.RunPublisher = func(context.Context, publisher.Config) error { return errors.New("later certificate failure") }
	var before publisherapp.Snapshot
	if err := publisherprotocol.Call(t.Context(), endpoint, "GET", "/v1/status", nil, &before); err != nil {
		t.Fatal(err)
	}
	var accepted publisherprotocol.AcceptedPublication
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/publications", request, &accepted); err != nil {
		t.Fatal("later worker error became a setup error", err)
	}
	waitInvocation(t, a, func(snapshot publisherapp.Snapshot) bool {
		for _, service := range snapshot.Services {
			if service.RegistrationID == accepted.Registration.RegistrationID {
				return service.Failure == "runtime.publication_failed" && !service.Routable
			}
		}
		return false
	})
	var events []publisherapp.Event
	if err := publisherprotocol.Call(t.Context(), endpoint, "GET", "/v1/events?after="+before.Cursor, nil, &events); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, event := range events {
		found = found || event.Type == "service.failed" && event.Service != nil && event.Service.RegistrationID == accepted.Registration.RegistrationID
	}
	if !found {
		t.Fatal("later failure missing from scoped native events")
	}
	var response *publisherprotocol.ResponseError
	err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/unregister", accepted.Registration, nil)
	if !errors.As(err, &response) || response.Status != 503 || response.Code != "runtime.publication_failed" {
		t.Fatal("terminal failure was reported as a bad close request or lost", err)
	}
	if _, found := a.manager.ServiceForRegistration(accepted.Registration.RegistrationID); found {
		t.Fatal("terminal publication failure prevented completed cleanup from releasing ownership")
	}
}

func TestApplicationPublicationValidationFailsBeforeAuthority(t *testing.T) {
	a, _ := testAppRuntimeWorkers(t, true)
	_, valid := applicationRequest(t, a)
	var resolves atomic.Int32
	a.ApplicationAuthority = applicationAuthority(func(_ context.Context, selection invocation.ApplicationSelection) (invocation.ApplicationGrant, error) {
		resolves.Add(1)
		return applicationGrant(selection), nil
	})
	for _, change := range []func(*publisherprotocol.ApplicationPublication){
		func(r *publisherprotocol.ApplicationPublication) { r.ResourceId = nil },
		func(r *publisherprotocol.ApplicationPublication) { r.Auth = json.RawMessage(`null`) },
		func(r *publisherprotocol.ApplicationPublication) { r.Auth = json.RawMessage(`{}`) },
		func(r *publisherprotocol.ApplicationPublication) { r.ServerUrl = "" },
		func(r *publisherprotocol.ApplicationPublication) { r.Target = "3000" },
		func(r *publisherprotocol.ApplicationPublication) { r.ResourceId = new(string) },
		func(r *publisherprotocol.ApplicationPublication) {
			r.Allocate = &struct {
				Namespace string `json:"namespace"`
			}{Namespace: "user.example"}
		},
	} {
		request := valid
		change(&request)
		if _, err := a.publishApplication(t.Context(), request); err == nil {
			t.Fatal("invalid application accepted")
		}
	}
	if resolves.Load() != 0 {
		t.Fatal("invalid setup reached authority")
	}
	for _, cause := range []error{publisherprotocol.ErrApplicationAuthInvalid, publisherprotocol.ErrApplicationDenied, publisherprotocol.ErrApplicationUnavailable} {
		a.ApplicationAuthority = applicationAuthority(func(context.Context, invocation.ApplicationSelection) (invocation.ApplicationGrant, error) {
			return invocation.ApplicationGrant{}, cause
		})
		if _, err := a.publishApplication(t.Context(), valid); !errors.Is(err, cause) {
			t.Fatalf("credential setup cause lost: %v", err)
		}
	}
}

func TestApplicationPublicationFailedSelectionCleansPartialAllocation(t *testing.T) {
	a, _ := testAppRuntimeWorkers(t, true)
	_, request := applicationRequest(t, a)
	request.ResourceId = nil
	request.Allocate = &struct {
		Namespace string `json:"namespace"`
	}{Namespace: "user.example"}
	selectionFailure := errors.New("selection failed after allocation")
	var cleaned atomic.Int32
	a.ApplicationAuthority = applicationAuthority(func(_ context.Context, selection invocation.ApplicationSelection) (invocation.ApplicationGrant, error) {
		grant := applicationGrant(selection)
		grant.Cleanup = func(context.Context) error { cleaned.Add(1); return nil }
		return grant, selectionFailure
	})
	if _, err := a.publishApplication(t.Context(), request); !errors.Is(err, selectionFailure) || cleaned.Load() != 1 {
		t.Fatal("partial allocation leaked", err)
	}
	if len(a.prepared) != 0 {
		t.Fatal("failed selection retained preparation")
	}
}

func TestApplicationPublicationRejectsGroupOwnedAndMismatchedResources(t *testing.T) {
	a, _ := testAppRuntimeWorkers(t, true)
	_, request := applicationRequest(t, a)
	for _, change := range []func(*invocation.ApplicationGrant){
		func(g *invocation.ApplicationGrant) { value := true; g.PublicURL.PublisherPool = &value },
		func(g *invocation.ApplicationGrant) { g.PublicURL.ServiceProtocol = "postgres" },
		func(g *invocation.ApplicationGrant) { g.PublicURL.Purpose = controlv1.Oauth },
		func(g *invocation.ApplicationGrant) { g.PublicURL.Id, _ = opaqueid.New(opaqueid.PublicURLPrefix) },
		func(g *invocation.ApplicationGrant) { g.PublicURL.Ephemeral = true },
	} {
		a.ApplicationAuthority = applicationAuthority(func(_ context.Context, selection invocation.ApplicationSelection) (invocation.ApplicationGrant, error) {
			grant := applicationGrant(selection)
			change(&grant)
			return grant, nil
		})
		if _, err := a.publishApplication(t.Context(), request); !errors.Is(err, publisherprotocol.ErrApplicationDenied) {
			t.Fatalf("out-of-bound resource accepted: %v", err)
		}
	}
	_, request = applicationRequest(t, a)
	request.ResourceId = nil
	request.Allocate = &struct {
		Namespace string `json:"namespace"`
	}{Namespace: "user.example"}
	a.ApplicationAuthority = applicationAuthority(func(_ context.Context, selection invocation.ApplicationSelection) (invocation.ApplicationGrant, error) {
		grant := applicationGrant(selection)
		grant.PublicURL.CanonicalHostname = "db.group." + selection.Namespace
		return grant, nil
	})
	if _, err := a.publishApplication(t.Context(), request); !errors.Is(err, publisherprotocol.ErrApplicationDenied) {
		t.Fatal("allocation rebound a nested group endpoint", err)
	}
}

func TestApplicationPublicationRejectsNoncanonicalAllocationLabels(t *testing.T) {
	a, _ := testAppRuntimeWorkers(t, true)
	_, request := applicationRequest(t, a)
	request.ResourceId = nil
	request.Allocate = &struct {
		Namespace string `json:"namespace"`
	}{Namespace: "user.example"}
	for _, label := range []string{"random", "eph-" + strings.Repeat("a", 26), strings.Repeat("A", 26), strings.Repeat("a", 25) + "b", strings.Repeat("a", 27), "db.group"} {
		var cleaned atomic.Int32
		a.ApplicationAuthority = applicationAuthority(func(_ context.Context, selection invocation.ApplicationSelection) (invocation.ApplicationGrant, error) {
			grant := applicationGrant(selection)
			grant.PublicURL.CanonicalHostname = label + "." + selection.Namespace
			grant.Cleanup = func(context.Context) error { cleaned.Add(1); return nil }
			return grant, nil
		})
		if _, err := a.publishApplication(t.Context(), request); !errors.Is(err, publisherprotocol.ErrApplicationDenied) || cleaned.Load() != 1 {
			t.Fatalf("noncanonical allocation label %q was accepted or not cleaned: %v", label, err)
		}
	}
}

func TestApplicationPublicationUncertainAckRecoversButCanceledSetupCleans(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		t.Run(map[bool]string{true: "canceled", false: "lost-ack"}[canceled], func(t *testing.T) {
			a, _ := testAppRuntimeWorkers(t, true)
			endpoint, request := applicationRequest(t, a)
			request.ResourceId = nil
			request.Allocate = &struct {
				Namespace string `json:"namespace"`
			}{Namespace: "user.example"}
			var cleaned atomic.Int32
			a.ApplicationAuthority = applicationAuthority(func(_ context.Context, selection invocation.ApplicationSelection) (invocation.ApplicationGrant, error) {
				grant := applicationGrant(selection)
				grant.Cleanup = func(context.Context) error { cleaned.Add(1); return nil }
				return grant, nil
			})
			a.workers.RunPublisher = readyInvocation
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if canceled {
				a.AttachPublication = func(context.Context, publisherapp.Service, *publisher.Config) error { cancel(); return nil }
			}
			r := invocationRequest(t, ctx, endpoint, request)
			r.URL.Path, r.RequestURI = "/v1/publications", "/v1/publications"
			a.handler().ServeHTTP(&lostInvocationAck{header: http.Header{}}, r)
			if !canceled {
				var recovered publisherprotocol.AcceptedPublication
				if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/publications", request, &recovered); err != nil || cleaned.Load() != 0 {
					t.Fatal("uncertain accepted acknowledgment destroyed its publication", err)
				}
				if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/unregister", recovered.Registration, nil); err != nil {
					t.Fatal(err)
				}
			}
			if cleaned.Load() != 1 {
				t.Fatalf("allocation cleanup count=%d", cleaned.Load())
			}
			for _, service := range a.manager.Snapshot().Services {
				if service.Name == request.InvocationId && service.RegistrationID != "" {
					t.Fatal("unacknowledged registration retained")
				}
			}
		})
	}
}

func TestApplicationPublicationLostRenewalReplyKeepsAcceptedResource(t *testing.T) {
	a, _ := testAppRuntimeWorkers(t, true)
	endpoint, request := applicationRequest(t, a)
	request.ResourceId = nil
	request.Allocate = &struct {
		Namespace string `json:"namespace"`
	}{Namespace: "user.example"}
	var cleaned, allocations atomic.Int32
	a.ApplicationAuthority = applicationAuthority(func(_ context.Context, selection invocation.ApplicationSelection) (invocation.ApplicationGrant, error) {
		allocations.Add(1)
		grant := applicationGrant(selection)
		grant.Cleanup = func(context.Context) error { cleaned.Add(1); return nil }
		return grant, nil
	})
	a.workers.RunPublisher = readyInvocation
	var accepted publisherprotocol.AcceptedPublication
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/publications", request, &accepted); err != nil {
		t.Fatal(err)
	}
	r := invocationRequest(t, t.Context(), endpoint, request)
	r.URL.Path, r.RequestURI = "/v1/publications", "/v1/publications"
	a.handler().ServeHTTP(&lostInvocationAck{header: http.Header{}}, r)
	var repeated publisherprotocol.AcceptedPublication
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/publications", request, &repeated); err != nil || repeated != accepted || allocations.Load() != 1 || cleaned.Load() != 0 {
		t.Fatal("uncertain renewal disrupted accepted publication", err)
	}
	encoded, _ := json.Marshal(repeated)
	if strings.Contains(string(encoded), "Reused") || strings.Contains(string(encoded), "reused") {
		t.Fatal("native acknowledgment ownership leaked into wire schema")
	}
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/unregister", accepted.Registration, nil); err != nil || cleaned.Load() != 1 {
		t.Fatal("resource cleanup did not join after renewal recovery", err)
	}
}

func TestApplicationPublicationSourceCannotChangeAfterUncertainExchangeOrAcceptance(t *testing.T) {
	for _, uncertain := range []bool{false, true} {
		t.Run(map[bool]string{false: "accepted", true: "uncertain-exchange"}[uncertain], func(t *testing.T) {
			a, _ := testAppRuntimeWorkers(t, true)
			endpoint, request := applicationRequest(t, a)
			var resolves, refreshes atomic.Int32
			a.ApplicationAuthority = applicationAuthority(func(_ context.Context, selection invocation.ApplicationSelection) (invocation.ApplicationGrant, error) {
				resolves.Add(1)
				if uncertain {
					return invocation.ApplicationGrant{}, publisheridentity.ErrApplicationSessionUncertain
				}
				grant := applicationGrant(selection)
				grant.RefreshAuth = func(context.Context, json.RawMessage) error { refreshes.Add(1); return nil }
				return grant, nil
			})
			a.workers.RunPublisher = readyInvocation
			var accepted publisherprotocol.AcceptedPublication
			err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/publications", request, &accepted)
			if uncertain == (err == nil) {
				t.Fatal("fixture did not reach selected acceptance state", err)
			}
			request.Auth = bytes.ReplaceAll(request.Auth, []byte("mci_0123456789ABCDEFGHIJKL"), []byte("mci_1123456789ABCDEFGHIJKL"))
			if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/publications", request, new(publisherprotocol.AcceptedPublication)); err == nil {
				t.Fatal("recovery switched its original source identity")
			}
			if resolves.Load() != 1 || refreshes.Load() != 0 {
				t.Fatal("changed source reached an exchange or refresh")
			}
		})
	}
}

func TestApplicationPublicationUncertainAckCanCloseWithOriginalOwnerWithoutRegistrationID(t *testing.T) {
	a, _ := testAppRuntimeWorkers(t, true)
	endpoint, request := applicationRequest(t, a)
	var cleaned atomic.Int32
	a.ApplicationAuthority = applicationAuthority(func(_ context.Context, selection invocation.ApplicationSelection) (invocation.ApplicationGrant, error) {
		grant := applicationGrant(selection)
		grant.Release = func(context.Context) error { cleaned.Add(1); return nil }
		return grant, nil
	})
	a.workers.RunPublisher = readyInvocation
	r := invocationRequest(t, t.Context(), endpoint, request)
	r.URL.Path, r.RequestURI = "/v1/publications", "/v1/publications"
	a.handler().ServeHTTP(&lostInvocationAck{header: http.Header{}}, r)
	registration := publisherprotocol.Registration{Version: 1, Owner: request.Owner, Target: request.Target}
	for _, change := range []func(*publisherprotocol.Registration){func(r *publisherprotocol.Registration) { r.Owner = strings.Repeat("a", 32) }, func(r *publisherprotocol.Registration) { r.Target = "http://127.0.0.1:4000" }} {
		wrong := registration
		change(&wrong)
		if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/unregister", wrong, nil); err == nil || cleaned.Load() != 0 {
			t.Fatal("uncertain close accepted another owner or target", err)
		}
	}
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/unregister", registration, nil); err != nil || cleaned.Load() != 1 {
		t.Fatal("original owner could not close its uncertain acknowledgment", err)
	}
}

func TestApplicationPublicationRealNativeTrafficAndCleanup(t *testing.T) {
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
	a, endpoint, body, fixture := invocationRuntime(t)
	var request publisherprotocol.ApplicationPublication
	identityID := body["publisher_identity_id"].(string)
	// the new API intentionally does not accept legacy identity selectors.
	delete(body, "publisher_identity_id")
	encoded, _ := json.Marshal(body)
	if err := json.Unmarshal(encoded, &request); err != nil {
		t.Fatal(err)
	}
	request.Auth = json.RawMessage(`{"kind":"oidc","machine_id":"mci_0123456789ABCDEFGHIJKL","assertion":"fixture"}`)
	request.Allocate = &struct {
		Namespace string `json:"namespace"`
	}{Namespace: fixture.Namespace}
	mode := controlv1.Anonymous
	modeWire := publisherprotocol.ApplicationPublicationAccessMode(mode)
	request.AccessMode = &modeWire
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer target.Close()
	request.Target = target.URL
	a.ApplicationAuthority = applicationAuthority(func(ctx context.Context, selection invocation.ApplicationSelection) (invocation.ApplicationGrant, error) {
		profile, err := a.state.Server(ctx, fixture.URL)
		if err != nil {
			return invocation.ApplicationGrant{}, err
		}
		control, err := clientcontrol.New(fixture.URL, fixture.HTTP, "")
		if err != nil {
			return invocation.ApplicationGrant{}, err
		}
		authority, err := clientauthority.New(fixture.URL, fixture.HTTP, "")
		if err != nil {
			return invocation.ApplicationGrant{}, err
		}
		native, err := publisheridentity.ResolveAdHoc(ctx, profile, publisheridentity.NativeControl{PublicURLControl: control}, authority, fixture.URL, "", "", "", "", "", identityID, nil)
		if err != nil {
			return invocation.ApplicationGrant{}, err
		}
		publicURL, err := native.Allocate(ctx, controlv1.AllocateEphemeralPublicURLRequest{InvocationId: selection.InvocationID, Target: selection.Target, AccessMode: selection.AccessMode})
		return invocation.ApplicationGrant{Control: native, PublisherIdentityID: native.PublisherIdentityID(), PublicURL: publicURL, RefreshAuth: func(context.Context, json.RawMessage) error { return nil }, Cleanup: func(ctx context.Context) error { return native.DeletePublicURL(ctx, publicURL.Id) }}, err
	})
	var accepted publisherprotocol.AcceptedPublication
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/publications", request, &accepted); err != nil {
		t.Fatal(err)
	}
	waitInvocation(t, a, func(snapshot publisherapp.Snapshot) bool {
		for _, service := range snapshot.Services {
			if service.RegistrationID == accepted.Registration.RegistrationID {
				if service.Failure != "" {
					t.Fatalf("real native failed: %s", service.Failure)
				}
				return service.Routable
			}
		}
		return false
	})
	if status, _, err := fixture.Visit(t.Context(), accepted.PublicUrl); err != nil || status != http.StatusNoContent {
		t.Fatalf("real native traffic status=%d err=%v", status, err)
	}
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/unregister", accepted.Registration, nil); err != nil {
		t.Fatal(err)
	}
	if fixture.Deletions.Load() != 1 || fixture.Runs.Load() != 1 {
		t.Fatalf("native did not join exact resource cleanup: runs=%d deletes=%d", fixture.Runs.Load(), fixture.Deletions.Load())
	}
}

func TestApplicationCleanupRetriesAndCachesOnlySuccess(t *testing.T) {
	failure := errors.New("cleanup failed")
	var calls atomic.Int32
	cleanup := applicationCleanup(func(ctx context.Context) error {
		if _, ok := ctx.Deadline(); !ok {
			t.Error("cleanup is unbounded")
		}
		if calls.Add(1) == 1 {
			return failure
		}
		return nil
	})
	if err := cleanup(); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	if err := cleanup(); err != nil {
		t.Fatal(err)
	}
	if err := cleanup(); err != nil || calls.Load() != 2 {
		t.Fatal("successful cleanup repeated", err)
	}
	alreadyExpired := applicationCleanup(func(context.Context) error { return clientcontrol.ErrNotFound })
	if err := alreadyExpired(); err != nil {
		t.Fatal("server-expired temporary resource retained its cleanup obligation", err)
	}
	var joinedCalls int
	joinedFailure := applicationCleanup(func(context.Context) error { joinedCalls++; return errors.Join(clientcontrol.ErrNotFound, failure) })
	for range 2 {
		if err := joinedFailure(); !errors.Is(err, failure) {
			t.Fatal("not-found hid an independent cleanup failure", err)
		}
	}
	if joinedCalls != 2 {
		t.Fatal("failed joined cleanup was cached as success")
	}
}

func TestApplicationPublicationCloseJoinsDrainWithoutStoppingSiblingOrListener(t *testing.T) {
	a, _ := testAppRuntimeWorkers(t, true)
	firstEndpoint, first := applicationRequest(t, a)
	secondEndpoint, second := applicationRequest(t, a)
	first.ResourceId = nil
	first.Allocate = &struct {
		Namespace string `json:"namespace"`
	}{Namespace: "user.example"}
	listener := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	defer listener.Close()
	first.Target = listener.URL
	var cleaned atomic.Int32
	a.ApplicationAuthority = applicationAuthority(func(_ context.Context, selection invocation.ApplicationSelection) (invocation.ApplicationGrant, error) {
		grant := applicationGrant(selection)
		grant.Cleanup = func(context.Context) error { cleaned.Add(1); return nil }
		return grant, nil
	})
	started := make(chan string, 2)
	draining, release := make(chan struct{}), make(chan struct{})
	a.workers.RunPublisher = func(ctx context.Context, cfg publisher.Config) error {
		started <- cfg.Target
		err := readyInvocation(ctx, cfg)
		if cfg.Target == first.Target {
			close(draining)
			<-release
		}
		return err
	}
	var firstAccepted, secondAccepted publisherprotocol.AcceptedPublication
	if err := publisherprotocol.Call(t.Context(), firstEndpoint, "POST", "/v1/publications", first, &firstAccepted); err != nil {
		t.Fatal(err)
	}
	if err := publisherprotocol.Call(t.Context(), secondEndpoint, "POST", "/v1/publications", second, &secondAccepted); err != nil {
		t.Fatal(err)
	}
	<-started
	<-started
	closed := make(chan error, 1)
	go func() {
		closed <- publisherprotocol.Call(t.Context(), firstEndpoint, "POST", "/v1/unregister", firstAccepted.Registration, nil)
	}()
	<-draining
	if cleaned.Load() != 0 {
		t.Fatal("allocation deleted before drain joined")
	}
	select {
	case err := <-closed:
		t.Fatal("close returned before worker join", err)
	default:
	}
	if err := publisherprotocol.Call(t.Context(), secondEndpoint, "POST", "/v1/renew", secondAccepted.Registration, nil); err != nil {
		t.Fatal("sibling renewal interrupted", err)
	}
	var sibling publisherapp.Snapshot
	if err := publisherprotocol.Call(t.Context(), secondEndpoint, "GET", "/v1/status", nil, &sibling); err != nil {
		t.Fatal(err)
	}
	if len(sibling.Services) != 1 || !sibling.Services[0].Registered {
		t.Fatal("sibling stopped during another close")
	}
	close(release)
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if cleaned.Load() != 1 {
		t.Fatal("allocation cleanup did not join")
	}
	response, err := http.Get(listener.URL)
	if err != nil {
		t.Fatal("native closed an application-owned listener", err)
	}
	response.Body.Close()
	if response.StatusCode != 204 {
		t.Fatal("application listener changed")
	}
}

func TestApplicationScopedEventsDoNotLeakSiblingsOrAuth(t *testing.T) {
	a, _ := testAppRuntimeWorkers(t, true)
	endpoint, request := applicationRequest(t, a)
	a.ApplicationAuthority = applicationAuthority(func(_ context.Context, selection invocation.ApplicationSelection) (invocation.ApplicationGrant, error) {
		return applicationGrant(selection), nil
	})
	a.workers.RunPublisher = readyInvocation
	var before publisherapp.Snapshot
	if err := publisherprotocol.Call(t.Context(), endpoint, "GET", "/v1/status", nil, &before); err != nil {
		t.Fatal(err)
	}
	var accepted publisherprotocol.AcceptedPublication
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/publications", request, &accepted); err != nil {
		t.Fatal(err)
	}
	a.manager.RecordFailure("api", "sibling-sensitive-failure")
	var events []publisherapp.Event
	if err := publisherprotocol.Call(t.Context(), endpoint, "GET", "/v1/events?after="+before.Cursor, nil, &events); err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(events)
	if len(events) == 0 || strings.Contains(string(encoded), "sibling-sensitive") || strings.Contains(string(encoded), "secret-source") {
		t.Fatalf("scoped event leak: %s", encoded)
	}
}
