package local

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/publisher"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
	"github.com/tnldotdev/tnl/internal/publisher/invocation"
	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
	"github.com/tnldotdev/tnl/internal/security/machineproof"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestApplicationPublicationShutdownPreservesIndependentPreparationFailure(t *testing.T) {
	a, _ := testAppRuntimeWorkers(t, true)
	_, request := applicationRequest(t, a)
	entered, joined := make(chan struct{}), make(chan struct{})
	independent, cause := errors.New("source acquisition failed independently"), errors.New("native owner stopped")
	a.ApplicationAuthority = applicationAuthority(func(ctx context.Context, _ invocation.ApplicationSelection) (invocation.ApplicationGrant, error) {
		close(entered)
		<-ctx.Done()
		close(joined)
		return invocation.ApplicationGrant{}, errors.Join(ctx.Err(), independent)
	})
	ctx, cancel := context.WithCancelCause(t.Context())
	defer cancel(nil)
	done := make(chan error, 1)
	go func() { _, err := a.publishApplication(ctx, request); done <- err }()
	<-entered
	a.mu.Lock()
	a.shuttingDown = true
	a.mu.Unlock()
	cancel(cause)
	if err := <-done; !errors.Is(err, cause) || !errors.Is(err, independent) {
		t.Fatal("canceled preparation hid independent failure", err)
	}
	a.mu.Lock()
	shutdownErr := a.shutdownPreparationErr
	a.mu.Unlock()
	if !errors.Is(shutdownErr, cause) || !errors.Is(shutdownErr, independent) {
		t.Fatal("native shutdown lost the admitted preparation result", shutdownErr)
	}
	select {
	case <-joined:
	default:
		t.Fatal("preparation returned before its source joined")
	}
}

type applicationStateHTTP func(*http.Request) (*http.Response, error)

func (f applicationStateHTTP) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestApplicationPublicationDurablePreRegistrationCleanupReopensWithoutProof(t *testing.T) {
	a, _ := testAppRuntimeWorkers(t, true)
	endpoint, request := applicationRequest(t, a)
	request.ResourceId = nil
	request.Allocate = &struct {
		Namespace string `json:"namespace"`
	}{Namespace: "apps.example"}
	request.Auth = json.RawMessage(`{"kind":"oidc","machine_id":"mci_0123456789ABCDEFGHIJKL","assertion":"private-source-proof"}`)
	const suffix = "0123456789ABCDEFGHIJKL"
	response := authorityv1.MachinePublicationSession{Id: "mps_" + suffix, AccessToken: "source-access-token", TokenType: "Bearer", ExpiresAt: time.Now().Add(time.Minute), IdentityExpiresAt: time.Now().Add(5 * time.Minute), RenewAfter: time.Now().Add(30 * time.Second), Publisher: authorityv1.PublisherEnrollmentResult{ClientId: "pub_" + suffix, KeyId: "pkey_" + suffix, GrantId: "pgrant_" + suffix, TeamId: "tm_" + suffix, Kind: authorityv1.Namespace, Namespace: new("apps.example"), DomainId: new("dom_" + suffix)}}
	url := controlv1.PublicURL{Id: "url_" + suffix, TeamId: response.Publisher.TeamId, DomainId: *response.Publisher.DomainId, CanonicalHostname: strings.Repeat("a", 26) + ".apps.example", Target: request.Target, ServiceProtocol: controlv1.Http, Purpose: controlv1.App, AccessMode: controlv1.Restricted, LifecycleState: controlv1.Enabled, Ephemeral: true}
	var public ed25519.PublicKey
	var exchanges, tokens, allocations, cleanups int
	cleanupFailure := errors.New("dedicated cleanup unavailable")
	transport := applicationStateHTTP(func(r *http.Request) (*http.Response, error) {
		decode := func(value any) {
			t.Helper()
			defer r.Body.Close()
			if err := json.NewDecoder(r.Body).Decode(value); err != nil {
				t.Fatal(err)
			}
		}
		reply := func(value any) (*http.Response, error) {
			data, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(data))}, nil
		}
		switch r.URL.Path {
		case "/v1/machine-publication-sessions/exchange":
			exchanges++
			var body authorityv1.MachinePublicationExchange
			decode(&body)
			key, err := base64.RawURLEncoding.Strict().DecodeString(body.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			public = key
			return reply(response)
		case "/v1/publisher-token":
			tokens++
			return reply(authorityv1.PublisherTokenResponse{AccessToken: "serving-token", ExpiresIn: 60, TokenType: "Bearer", GrantId: response.Publisher.GrantId})
		case "/v1/publisher/public-urls":
			allocations++
			return reply(url)
		case "/v1/machine-publication-sessions/" + response.Id + "/cleanup":
			cleanups++
			if r.Header.Get("Authorization") != "" {
				t.Fatal("cleanup acquired a bearer token")
			}
			var body authorityv1.MachinePublicationCleanup
			decode(&body)
			if _, err := publisherproof.Verify(body.Assertion, response.Publisher.ClientId, response.Publisher.KeyId, machineproof.PublicationCleanup(response.Id, request.InvocationId), request.ServerUrl+r.URL.Path, public, time.Now()); err != nil {
				t.Fatal(err)
			}
			if cleanups == 1 {
				return nil, cleanupFailure
			}
			return &http.Response{StatusCode: 204, Body: http.NoBody}, nil
		default:
			t.Fatalf("recovery acquired new authority: %s", r.URL.Path)
			return nil, errors.New("unexpected operation")
		}
	})
	original := http.DefaultTransport
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = original })
	authority := NewControlApplicationAuthority(&http.Client{Transport: transport})
	setupFailure := errors.New("setup failed before registration existed")
	a.ApplicationAuthority = applicationAuthority(func(ctx context.Context, selection invocation.ApplicationSelection) (invocation.ApplicationGrant, error) {
		grant, err := authority.ResolveApplicationPublication(ctx, selection)
		if err != nil {
			return grant, err
		}
		return grant, setupFailure
	})
	if _, err := a.publishApplication(t.Context(), request); !errors.Is(err, setupFailure) || !errors.Is(err, cleanupFailure) {
		t.Fatal("pre-registration cleanup lost an independent error", err)
	}
	entries, err := a.publications.Pending(t.Context())
	if err != nil || len(entries) != 1 {
		t.Fatal("failed cleanup lost its durable owner", err)
	}
	before, err := entries[0].Snapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(before.NativeKey)
	if before.Phase != clientstate.ApplicationCleanupPending || len(a.prepared) != 0 {
		t.Fatal("cleanup intent did not precede registration")
	}
	if err := a.publications.Close(); err != nil {
		t.Fatal(err)
	}
	a.publications = nil
	if _, err := a.applicationState(); err != nil {
		t.Fatal(err)
	}
	// unregister authenticates the fresh capability, stable owner and target even
	// though no registration ever existed. it needs neither source nor token.
	wrong := publisherprotocol.Registration{Version: 1, RegistrationID: "reg_uncertain", Owner: strings.Repeat("f", 32), Target: request.Target}
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/unregister", wrong, nil); err == nil {
		t.Fatal("another stable owner claimed cleanup")
	}
	pending, err := a.retryApplicationCleanup(t.Context())
	if err != nil || pending || cleanups != 2 || exchanges != 1 || tokens != 1 || allocations != 1 {
		t.Fatal("native owner did not retry only original-key cleanup", err)
	}
	entry, err := a.publications.FindOwned(t.Context(), request.InvocationId, before.Binding.OwnerHash, request.Target)
	if err != nil {
		t.Fatal(err)
	}
	after, err := entry.Snapshot(t.Context())
	if err != nil || after.Phase != clientstate.ApplicationCleanupDone || after.SessionID != before.SessionID || after.Nonce != before.Nonce || len(after.NativeKey) != 0 {
		t.Fatal("cleanup completion lost tuple or retained credential", err)
	}
}

func TestApplicationPublicationDurableCanceledSetupPreservesStorageFailure(t *testing.T) {
	a, _ := testAppRuntimeWorkers(t, true)
	_, request := applicationRequest(t, a)
	ctx, cancel := context.WithCancelCause(t.Context())
	defer cancel(nil)
	cause := errors.New("app aborted setup")
	var recordPath string
	a.ApplicationAuthority = applicationAuthority(func(_ context.Context, selection invocation.ApplicationSelection) (invocation.ApplicationGrant, error) {
		// use the existing real private-file boundary, not a production fault hook.
		if err := filepath.WalkDir(a.state.Root(), func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if strings.HasPrefix(entry.Name(), "publication-") && strings.HasSuffix(path, ".json") {
				recordPath = path
				return os.Chmod(path, 0644)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		cancel(cause)
		return invocation.ApplicationGrant{}, cause
	})
	_, err := a.publishApplication(ctx, request)
	reason, _ := failure.ReasonOf(err)
	if !errors.Is(err, cause) || reason != failure.PublisherIdentityStateInvalid {
		t.Fatal("canceled setup discarded independent private-state failure", err)
	}
	if recordPath == "" {
		t.Fatal("no original pending record")
	}
	if err := os.Chmod(recordPath, 0600); err != nil {
		t.Fatal(err)
	}
	entries, err := a.publications.Pending(t.Context())
	if err != nil || len(entries) != 1 {
		t.Fatal("failed cleanup obligation disappeared", err)
	}
}

func TestApplicationPublicationDurableStoppedWorkerCanRecoverWithoutAllocation(t *testing.T) {
	a, _ := testAppRuntimeWorkers(t, true)
	_, request := applicationRequest(t, a)
	started := make(chan struct{}, 2)
	stop := make(chan struct{})
	var entry *clientstate.ApplicationPublication
	var resolves, cleaned int
	a.ApplicationAuthority = applicationAuthority(func(_ context.Context, selection invocation.ApplicationSelection) (invocation.ApplicationGrant, error) {
		resolves++
		entry = selection.Publication
		grant := applicationGrant(selection)
		grant.PublicURL.TeamId = "tm_0123456789ABCDEFGHIJKL"
		grant.PublicURL.DomainId = "dom_0123456789ABCDEFGHIJKL"
		record, err := entry.Snapshot(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer clear(record.NativeKey)
		record.Phase = clientstate.ApplicationSessionAccepted
		record.SessionID = "mps_0123456789ABCDEFGHIJKL"
		record.Publisher = &authorityv1.PublisherEnrollmentResult{ClientId: grant.PublisherIdentityID, KeyId: "pkey_0123456789ABCDEFGHIJKL", GrantId: "pgrant_0123456789ABCDEFGHIJKL", TeamId: grant.PublicURL.TeamId, Kind: authorityv1.SavedPublicUrl, PublicUrlId: new(selection.ResourceID)}
		record.AccessExpiresAt, record.IdentityExpiresAt, record.RenewAfter = time.Now().Add(time.Minute), time.Now().Add(5*time.Minute), time.Now().Add(30*time.Second)
		if err := entry.Checkpoint(t.Context(), record); err != nil {
			t.Fatal(err)
		}
		record, err = entry.Snapshot(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer clear(record.NativeKey)
		record.Phase, record.PublicURL = clientstate.ApplicationURLAccepted, &grant.PublicURL
		if err := entry.Checkpoint(t.Context(), record); err != nil {
			t.Fatal(err)
		}
		grant.RefreshAuth = func(ctx context.Context, _ json.RawMessage) error {
			record, err := entry.Snapshot(ctx)
			if err != nil {
				return err
			}
			defer clear(record.NativeKey)
			record.Phase, record.ResumePhase = clientstate.ApplicationURLAccepted, ""
			return entry.Checkpoint(ctx, record)
		}
		grant.Release = func(context.Context) error { cleaned++; return nil }
		return grant, nil
	})
	var workers atomic.Int32
	a.workers.RunPublisher = func(ctx context.Context, _ publisher.Config) error {
		number := workers.Add(1)
		started <- struct{}{}
		if number == 1 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-stop:
				return errors.New("old confirmed fence expired")
			}
		}
		<-ctx.Done()
		return ctx.Err()
	}
	accepted, err := a.publishApplication(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	<-started
	record, err := entry.Snapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(record.NativeKey)
	record.ResumePhase, record.Phase = record.Phase, clientstate.ApplicationRefreshPending
	if err := entry.Checkpoint(t.Context(), record); err != nil {
		t.Fatal(err)
	}
	close(stop)
	waitInvocation(t, a, func(snapshot publisherapp.Snapshot) bool {
		for _, service := range snapshot.Services {
			if service.Name == request.InvocationId {
				return service.Failure == "runtime.publication_failed"
			}
		}
		return false
	})
	repeated, err := a.publishApplication(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("recovered registration never restarted its worker")
	}
	if !repeated.Reused || repeated.PublicUrlId != accepted.PublicUrlId || resolves != 1 || workers.Load() != 2 || cleaned != 0 {
		t.Fatal("recovery allocated again or deleted an accepted URL")
	}
	if err := a.unregisterApplication(t.Context(), request.InvocationId, repeated.Registration); err != nil || cleaned != 1 {
		t.Fatal("explicit close did not join recovered worker", err)
	}
}
