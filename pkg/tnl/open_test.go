package tnl

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
	"github.com/tnldotdev/tnl/internal/security/machineproof"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	localv1 "github.com/tnldotdev/tnl/pkg/api/publisher/local/v1"
)

// this is the SDK/native IPC fixture, not another publisher engine. actual
// publisher traffic, original-key cleanup and sibling lifetimes are asserted by
// local.TestApplicationPublicationRealNativeTrafficAndCleanup and its siblings.
type sdkNative struct {
	t                 *testing.T
	server            *httptest.Server
	capabilities      *publisherprotocol.Capabilities
	mu                sync.Mutex
	request           publisherprotocol.ApplicationPublication
	accepted          publisherprotocol.AcceptedPublication
	published         chan struct{}
	ready             chan struct{}
	closed            bool
	requests, closes  int
	failCleanup       bool
	loseAck           bool
	sourcePublic      ed25519.PublicKey
	challenge         authorityv1.IdentitySourceChallenge
	challenges        int
	publicationEvents func(publisherapp.Service) []publisherapp.Event
	events            []publisherapp.Event
	eventsRead        chan string
	eventsExpired     bool
	statusReads       int
}

func newSDKNative(t *testing.T, ready bool) *sdkNative {
	t.Helper()
	f := &sdkNative{t: t, published: make(chan struct{}, 1), ready: make(chan struct{}), eventsRead: make(chan string, 16)}
	if ready {
		close(f.ready)
	}
	f.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.capabilities.Handler(http.HandlerFunc(f.serve)).ServeHTTP(w, r)
	}))
	f.server.Start()
	var err error
	f.capabilities, err = publisherprotocol.NewCapabilities(f.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.server.Close)
	return f
}

func (f *sdkNative) runtime(_ context.Context, _ Options, invocation string) (publisherprotocol.Endpoint, error) {
	return f.capabilities.Issue(publisherprotocol.CapabilityRequest{Scope: "invocation", InvocationId: &invocation})
}

func (f *sdkNative) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch r.URL.Path {
	case "/v1/identity-source-challenges":
		var request publisherprotocol.ApplicationPublication
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			f.t.Error(err)
			w.WriteHeader(400)
			return
		}
		var source localv1.ApplicationRegisteredKeyProof
		if json.Unmarshal(request.Auth, &source) != nil || source.Kind != "registered_key" || source.Reply != nil || source.MachineId != "mci_0123456789ABCDEFGHIJKL" || source.KeyId != "source-key" {
			f.t.Error("SDK lost explicit registered source")
			w.WriteHeader(403)
			return
		}
		clear(request.Auth)
		request.Auth = nil
		f.request = request
		c := registeredSDKChallenge()
		c.Id, _ = publisherprotocol.Random(16)
		encoded, _ := json.Marshal(request)
		digest := sha256.Sum256(encoded)
		c.BindingDigest = hex.EncodeToString(digest[:])
		if f.accepted.PublicUrlId != "" {
			c.Operation = "publication_refresh"
			c.Nonce = ""
			c.SessionId = "mps_0123456789ABCDEFGHIJKL"
			c.Audience = c.Server + "/v1/machine-publication-sessions/" + c.SessionId + "/refresh"
			c.Scope = machineproof.Publication("", "apps.example", "refresh", c.NativePublicKey, c.SessionId)
		}
		f.challenge = c
		f.challenges++
		_ = publisherprotocol.Write(w, 200, c)
	case "/v1/publications":
		var request publisherprotocol.ApplicationPublication
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			f.t.Error(err)
			w.WriteHeader(400)
			return
		}
		if len(f.sourcePublic) != 0 {
			var proof localv1.ApplicationRegisteredKeyProof
			if json.Unmarshal(request.Auth, &proof) != nil || proof.Reply == nil || proof.Reply.ChallengeId != f.challenge.Id {
				f.t.Error("SDK lost its common source reply")
				w.WriteHeader(403)
				return
			}
			if _, err := publisherproof.Verify(proof.Reply.Assertion, f.challenge.Source.MachineId, f.challenge.Source.KeyId, f.challenge.Scope, f.challenge.Audience, f.sourcePublic, time.Now()); err != nil {
				f.t.Error("SDK signature is not canonical", err)
				w.WriteHeader(403)
				return
			}
			f.challenge.Id = ""
		} else {
			var proof localv1.ApplicationOIDCProof
			if err := json.Unmarshal(request.Auth, &proof); err != nil || proof.MachineId != "mci_0123456789ABCDEFGHIJKL" || proof.Assertion != "private-proof" {
				f.t.Error("SDK lost its explicit identity source", err)
				w.WriteHeader(403)
				return
			}
		}
		clear(request.Auth)
		request.Auth = nil
		if f.request.InvocationId != "" && (request.InvocationId != f.request.InvocationId || request.Owner != f.request.Owner || request.Target != f.request.Target) {
			f.t.Error("SDK replaced its owner/target tuple")
			w.WriteHeader(403)
			return
		}
		f.request = request
		f.requests++
		if f.accepted.PublicUrlId == "" {
			f.accepted.Registration = publisherprotocol.Registration{Version: 1, Owner: request.Owner, Target: request.Target, RegistrationID: "reg_test"}
			f.accepted.PublicUrlId = "url_0123456789ABCDEFGHIJKL"
			f.accepted.Hostname = strings.Repeat("a", 26) + ".apps.example"
			f.accepted.PublicUrl = "https://" + f.accepted.Hostname
		}
		if f.requests == 1 && f.publicationEvents != nil {
			f.events = f.publicationEvents(publisherapp.Service{Name: request.InvocationId, RegistrationID: f.accepted.Registration.RegistrationID, Target: request.Target, PublicURL: f.accepted.PublicUrl, Registered: true, RunNumber: 1})
		}
		select {
		case f.published <- struct{}{}:
		default:
		}
		if f.loseAck {
			f.loseAck = false
			connection, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				f.t.Error(err)
				return
			}
			_ = connection.Close()
			return
		}
		_ = publisherprotocol.Write(w, 200, f.accepted)
	case "/v1/status":
		f.statusReads++
		routable := false
		select {
		case <-f.ready:
			routable = true
		default:
		}
		var services []publisherapp.Service
		if f.accepted.PublicUrlId != "" {
			services = []publisherapp.Service{{Name: f.request.InvocationId, RegistrationID: f.accepted.Registration.RegistrationID, Target: f.request.Target, PublicURL: f.accepted.PublicUrl, Registered: !f.closed, Routable: routable, RunNumber: 1}}
		}
		cursor := "sdk_fixture_cursor"
		if len(f.events) != 0 {
			cursor = f.events[len(f.events)-1].Cursor
		}
		_ = publisherprotocol.Write(w, 200, publisherapp.Snapshot{SchemaVersion: 1, Cursor: cursor, Services: services})
	case "/v1/events":
		after := r.URL.Query().Get("after")
		select {
		case f.eventsRead <- after:
		default:
		}
		if f.eventsExpired {
			_ = publisherprotocol.Write(w, 410, publisherprotocol.Problem{Code: "runtime.cursor_expired"})
			return
		}
		if after == "sdk_fixture_cursor" {
			_ = publisherprotocol.Write(w, 200, f.events)
			return
		}
		for index, event := range f.events {
			if event.Cursor == after {
				_ = publisherprotocol.Write(w, 200, f.events[index+1:])
				return
			}
		}
		f.t.Error("SDK lost the exclusive journal cursor", after)
		w.WriteHeader(400)
	case "/v1/renew":
		w.WriteHeader(204)
	case "/v1/unregister":
		var registration publisherprotocol.Registration
		if err := json.NewDecoder(r.Body).Decode(&registration); err != nil {
			f.t.Error(err)
			w.WriteHeader(400)
			return
		}
		if registration.Owner != f.request.Owner || registration.Target != f.request.Target {
			f.t.Error("cleanup replaced its original owner/target")
			w.WriteHeader(403)
			return
		}
		f.closes++
		if f.failCleanup {
			f.failCleanup = false
			_ = publisherprotocol.Write(w, 503, publisherprotocol.Problem{Code: "runtime.cleanup_failed"})
			return
		}
		f.closed = true
		w.WriteHeader(204)
	case "/v1/capability":
		f.capabilities.Release(publisherprotocol.Grant(r))
		w.WriteHeader(204)
	default:
		f.t.Error("unexpected SDK operation", r.URL.Path)
		w.WriteHeader(404)
	}
}

func sdkOptions() Options {
	return Options{ServerURL: "https://control.example", Namespace: "apps.example", OIDCSource: &OIDCSource{MachineID: "mci_0123456789ABCDEFGHIJKL", Assertion: func(context.Context) (OIDCAssertion, error) {
		return OIDCAssertion{Token: "private-proof", ExpiresAt: time.Now().Add(time.Minute)}, nil
	}}}
}

func TestOpenUsesCanonicalNativePublicationAndSDKOwnedListener(t *testing.T) {
	t.Setenv("TNL_SERVER", "https://wrong.example")
	t.Setenv("TNL_PUBLISHER_CREDENTIAL_FILE", "/must-not-read")
	t.Setenv("TNL_ACCESS_TOKEN", "must-not-use")
	f := newSDKNative(t, true)
	options := sdkOptions()
	options.RequirePostQuantum = true
	identity, err := PreparePublisherIdentity(t.Context(), options)
	if err != nil {
		t.Fatal(err)
	}
	options.OIDCSource, options.PublisherIdentity = nil, identity
	tunnel, err := openApplication(t.Context(), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }), options, f.runtime)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	request := f.request
	f.mu.Unlock()
	if request.ServerUrl != options.ServerURL || request.RequirePostQuantum == nil || !*request.RequirePostQuantum || request.Allocate == nil || request.Allocate.Namespace != options.Namespace || tunnel.URL() == "" {
		t.Fatal("SDK lost exact native selection or HTTPS requirement")
	}
	response, err := http.Get(request.Target)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != 204 {
		t.Fatal("SDK handler listener not reachable")
	}
	if err := tunnel.Close(); err != nil {
		t.Fatal(err)
	}
	if err := tunnel.Close(); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	closes := f.closes
	f.mu.Unlock()
	if closes != 1 {
		t.Fatal("successful cleanup repeated")
	}
	if response, err := http.Get(request.Target); err == nil {
		_ = response.Body.Close()
		t.Fatal("SDK leaked its own listener")
	}
}

func TestOpenCancellationBeforeReadyStillCleansExactAllocation(t *testing.T) {
	f := newSDKNative(t, false)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		tunnel, err := openApplication(ctx, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), sdkOptions(), f.runtime)
		if tunnel != nil {
			err = errors.Join(err, tunnel.Close(), errors.New("Open returned an unready registration"))
		}
		done <- err
	}()
	<-f.published
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal("canceled Open lost its cause", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closes != 1 || !f.closed {
		t.Fatal("canceled Open returned before exact native cleanup")
	}
}

func TestOpenFailedCloseRetainsOriginalCleanupForRetryWithoutSource(t *testing.T) {
	f := newSDKNative(t, true)
	f.failCleanup = true
	options := sdkOptions()
	var acquisitions atomic.Int32
	options.OIDCSource.Assertion = func(context.Context) (OIDCAssertion, error) {
		acquisitions.Add(1)
		return OIDCAssertion{Token: "private-proof", ExpiresAt: time.Now().Add(time.Minute)}, nil
	}
	tunnel, err := openApplication(t.Context(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), options, f.runtime)
	if err != nil {
		t.Fatal(err)
	}
	if err := tunnel.Close(); err == nil {
		t.Fatal("failed native cleanup was forgotten")
	}
	if err := tunnel.Close(); err != nil {
		t.Fatal("native cleanup could not retry", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closes != 2 || acquisitions.Load() != 1 {
		t.Fatal("cleanup reacquired source authority or lost original obligation")
	}
}

func TestOpenUncertainNativeReplyRecoversOriginalInvocationAndURL(t *testing.T) {
	f := newSDKNative(t, true)
	f.loseAck = true
	tunnel, err := openApplication(t.Context(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), sdkOptions(), f.runtime)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	requests, closes, accepted := f.requests, f.closes, f.accepted
	f.mu.Unlock()
	if requests != 2 || closes != 0 || tunnel.URL() != accepted.PublicUrl {
		t.Fatal("uncertain native reply replaced or cleaned accepted authority")
	}
	if err := tunnel.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRegisteredSourceOpenRecoversLostReplyWithoutReplacingNativeTuple(t *testing.T) {
	f := newSDKNative(t, true)
	private := ed25519.NewKeyFromSeed([]byte(strings.Repeat("k", 32)))
	f.sourcePublic = private.Public().(ed25519.PublicKey)
	f.loseAck = true
	options := Options{ServerURL: "https://control.example", Namespace: "apps.example", RegisteredKeySource: &RegisteredKeySource{MachineID: "mci_0123456789ABCDEFGHIJKL", KeyID: "source-key", PrivateKey: private}}
	tunnel, err := openApplication(t.Context(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), options, f.runtime)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	challenges, requests, closes := f.challenges, f.requests, f.closes
	f.mu.Unlock()
	if challenges != 2 || requests != 2 || closes != 0 {
		t.Fatal("lost registered reply did not reacquire only the original native challenge")
	}
	if err := tunnel.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestOpenRequiresExplicitSourceAndSelectionBeforeNativeStartup(t *testing.T) {
	for _, options := range []Options{{ServerURL: "https://control.example", Namespace: "apps.example"}, {OIDCSource: sdkOptions().OIDCSource, Namespace: "apps.example"}, {ServerURL: "https://control.example", OIDCSource: sdkOptions().OIDCSource}, {ServerURL: "https://control.example", Namespace: "apps.example", ResourceID: "url_0123456789ABCDEFGHIJKL", OIDCSource: sdkOptions().OIDCSource}} {
		_, err := openApplication(t.Context(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), options, func(context.Context, Options, string) (publisherprotocol.Endpoint, error) {
			t.Error("invalid identity or selection reached native startup")
			return publisherprotocol.Endpoint{}, nil
		})
		if err == nil {
			t.Fatal("implicit identity/selection accepted")
		}
	}
}

func TestOIDCAcquisitionCancellationJoinsIndependentFailure(t *testing.T) {
	ctx, cancel := context.WithCancelCause(t.Context())
	defer cancel(nil)
	entered, joined := make(chan struct{}), make(chan struct{})
	independent, cause := errors.New("source transport failed"), errors.New("SDK owner stopped")
	done := make(chan error, 1)
	go func() {
		_, err := acquireApplicationProof(ctx, OIDCSource{Assertion: func(ctx context.Context) (OIDCAssertion, error) {
			close(entered)
			<-ctx.Done()
			close(joined)
			return OIDCAssertion{}, errors.Join(ctx.Err(), independent)
		}}, time.Now().Add(time.Minute))
		done <- err
	}()
	<-entered
	cancel(cause)
	if err := <-done; !errors.Is(err, cause) || !errors.Is(err, independent) {
		t.Fatal("source cancellation hid an independent error", err)
	}
	select {
	case <-joined:
	default:
		t.Fatal("acquisition returned without joining source")
	}
}
