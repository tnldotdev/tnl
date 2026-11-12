package local

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/publisher/invocation"
	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestControlApplicationAuthorityRejectsSourceBeforeNetwork(t *testing.T) {
	var calls atomic.Int32
	authority := NewControlApplicationAuthority(&http.Client{Transport: invocationTransport(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, errors.New("must not reach network")
	})})
	for _, raw := range []string{`null`, `{}`, `{"source":"old"}`, `{"kind":"signing_key","machine_id":"mci_0123456789ABCDEFGHIJKL","assertion":"proof"}`, `{"kind":"oidc","assertion":"proof"}`, `{"kind":"oidc","machine_id":"mci_bad","assertion":"proof"}`, `{"kind":"oidc","machine_id":"mci_0123456789ABCDEFGHIJKL","assertion":""}`, `{"kind":"oidc","machine_id":"mci_0123456789ABCDEFGHIJKL","assertion":"with space"}`, `{"kind":"oidc","machine_id":"mci_0123456789ABCDEFGHIJKL","assertion":"proof","private_key":"secret"}`, `{"Kind":"oidc","machine_id":"mci_0123456789ABCDEFGHIJKL","assertion":"proof"}`, `{"kind":"oidc","kind":"oidc","machine_id":"mci_0123456789ABCDEFGHIJKL","assertion":"proof"}`, `{"kind":"oidc","machine_id":"mci_0123456789ABCDEFGHIJKL","assertion":"\ufeffproof"}`, `{"kind":"oidc","machine_id":"mci_0123456789ABCDEFGHIJKL","assertion":"proof"} {}`, `{"kind":"oidc","machine_id":"mci_0123456789ABCDEFGHIJKL","assertion":"` + strings.Repeat("a", 32769) + `"}`} {
		_, err := authority.ResolveApplicationPublication(t.Context(), invocation.ApplicationSelection{ServerURL: "https://control.example", Auth: json.RawMessage(raw)})
		if !errors.Is(err, publisherprotocol.ErrApplicationAuthInvalid) {
			t.Fatal("invalid source was not rejected before selection", err)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("invalid source reached authority")
	}
}

func TestControlApplicationAuthorityClassifiesFailuresWithoutFallback(t *testing.T) {
	for _, test := range []struct {
		status int
		body   string
		want   error
	}{
		{401, `{"code":"unauthenticated"}`, publisherprotocol.ErrApplicationDenied},
		{403, `{"code":"forbidden"}`, publisherprotocol.ErrApplicationDenied},
		{404, `{"code":"not_found"}`, publisherprotocol.ErrApplicationDenied},
		{503, `{"code":"unavailable"}`, publisherprotocol.ErrApplicationUnavailable},
		{200, `null`, publisherprotocol.ErrApplicationAuthInvalid},
	} {
		t.Run(http.StatusText(test.status), func(t *testing.T) {
			var calls int
			authority := NewControlApplicationAuthority(&http.Client{Transport: invocationTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.URL.Path != "/v1/machine-publication-sessions/exchange" {
					t.Fatal("source failure selected another authority")
				}
				return &http.Response{StatusCode: test.status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(test.body))}, nil
			})})
			a, _ := testAppRuntimeWorkers(t, true)
			_, request := applicationRequest(t, a)
			request.Auth = json.RawMessage(`{"kind":"oidc","machine_id":"mci_0123456789ABCDEFGHIJKL","assertion":"explicit-proof"}`)
			entry, err := a.applicationCheckpoint(t.Context(), request, sha256.Sum256([]byte("public request")))
			if err != nil {
				t.Fatal(err)
			}
			_, err = authority.ResolveApplicationPublication(t.Context(), invocation.ApplicationSelection{ServerURL: request.ServerUrl, InvocationID: request.InvocationId, Target: request.Target, ResourceID: *request.ResourceId, Publication: entry, Auth: request.Auth})
			if !errors.Is(err, test.want) || calls != 1 {
				t.Fatal("source failure was misclassified or fell back", err)
			}
		})
	}
}

func TestControlApplicationAuthorityNativeWireJoinsRetryableCleanup(t *testing.T) {
	a, _ := testAppRuntimeWorkers(t, true)
	endpoint, request := applicationRequest(t, a)
	request.Auth = json.RawMessage(`{"kind":"oidc","machine_id":"mci_0123456789ABCDEFGHIJKL","assertion":"private-source-proof"}`)
	request.ResourceId = nil
	request.Allocate = &struct {
		Namespace string `json:"namespace"`
	}{Namespace: "apps.example"}
	listener := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	defer listener.Close()
	request.Target = listener.URL
	const suffix = "0123456789ABCDEFGHIJKL"
	response := authorityv1.MachinePublicationSession{Id: "mps_" + suffix, TokenType: "Bearer", AccessToken: "session-access", ExpiresAt: time.Now().Add(time.Minute), IdentityExpiresAt: time.Now().Add(5 * time.Minute), RenewAfter: time.Now().Add(30 * time.Second), Publisher: authorityv1.PublisherEnrollmentResult{ClientId: "pub_" + suffix, KeyId: "pkey_" + suffix, GrantId: "pgrant_" + suffix, TeamId: "tm_" + suffix, Kind: authorityv1.Namespace, DomainId: new("dom_" + suffix), Namespace: new(request.Allocate.Namespace)}}
	publicURL := controlv1.PublicURL{Id: "url_" + suffix, TeamId: response.Publisher.TeamId, DomainId: *response.Publisher.DomainId, CanonicalHostname: strings.Repeat("a", 26) + "." + request.Allocate.Namespace, Target: request.Target, ServiceProtocol: controlv1.Http, Purpose: controlv1.App, AccessMode: controlv1.Restricted, LifecycleState: controlv1.Enabled, Ephemeral: true, PolicyRevision: 1}
	var cleanups, exchanges, allocations, tokens atomic.Int32
	a.ApplicationAuthority = NewControlApplicationAuthority(&http.Client{Transport: invocationTransport(func(r *http.Request) (*http.Response, error) {
		var body any
		switch r.URL.Path {
		case "/v1/machine-publication-sessions/exchange":
			exchanges.Add(1)
			body = response
		case "/v1/publisher-token":
			tokens.Add(1)
			body = authorityv1.PublisherTokenResponse{AccessToken: "publisher-token", GrantId: response.Publisher.GrantId, ExpiresIn: 60, TokenType: "Bearer"}
		case "/v1/publisher/public-urls":
			allocations.Add(1)
			body = publicURL
		case "/v1/machine-publication-sessions/" + response.Id + "/cleanup":
			if r.Header.Get("Authorization") != "" {
				t.Error("cleanup used serving authority")
			}
			if cleanups.Add(1) <= 2 {
				return &http.Response{StatusCode: 503, Body: http.NoBody}, nil
			}
			return &http.Response{StatusCode: 204, Body: http.NoBody}, nil
		default:
			t.Errorf("unexpected authority path %s", r.URL.Path)
			return nil, errors.New("unexpected authority operation")
		}
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(encoded))}, nil
	})})
	started, draining, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	a.workers.RunPublisher = func(ctx context.Context, cfg publisher.Config) error {
		if cfg.PublisherIdentityID != response.Publisher.ClientId || cfg.Identity == nil || cfg.Control == nil || cfg.Audit == nil || cfg.VisitorControl == nil || cfg.BrowserControl == nil || cfg.Shares == nil {
			return errors.New("production adapter lost worker capabilities")
		}
		close(started)
		<-ctx.Done()
		close(draining)
		<-release
		return ctx.Err()
	}
	var accepted publisherprotocol.AcceptedPublication
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/publications", request, &accepted); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("production adapter did not start the native worker")
	}
	if accepted.PublicUrlId != publicURL.Id || accepted.PublicUrl != "https://"+publicURL.CanonicalHostname {
		t.Fatal("native wire changed accepted allocation")
	}
	closed := make(chan error, 1)
	go func() {
		closed <- publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/unregister", accepted.Registration, nil)
	}()
	select {
	case <-draining:
	case <-time.After(3 * time.Second):
		t.Fatal("native close did not start drain")
	}
	if cleanups.Load() != 0 {
		t.Fatal("allocation was deleted before worker join")
	}
	select {
	case <-closed:
		t.Fatal("unregister returned before worker join")
	default:
	}
	unblock()
	var problem *publisherprotocol.ResponseError
	if err := <-closed; !errors.As(err, &problem) || problem.Code != "runtime.cleanup_failed" {
		t.Fatal("failed cleanup obligation was not retained", err)
	}
	if _, found := a.manager.ServiceForRegistration(accepted.Registration.RegistrationID); !found {
		t.Fatal("failed cleanup released its owner")
	}
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/unregister", accepted.Registration, nil); err != nil {
		t.Fatal(err)
	}
	if _, found := a.manager.ServiceForRegistration(accepted.Registration.RegistrationID); found {
		t.Fatal("successful cleanup retained owner")
	}
	if cleanups.Load() != 3 || exchanges.Load() != 1 || allocations.Load() != 1 || tokens.Load() != 1 {
		t.Fatal("cleanup retried through a fresh source/serving grant")
	}
	result, err := http.Get(listener.URL)
	if err != nil {
		t.Fatal("publication closed the app-owned listener", err)
	}
	_ = result.Body.Close()
	if result.StatusCode != 204 {
		t.Fatal("app listener changed")
	}
	encoded, _ := json.Marshal(a.manager.Snapshot())
	if bytes.Contains(encoded, []byte("private-source-proof")) || bytes.Contains(encoded, []byte("publisher-token")) || bytes.Contains(encoded, []byte("session-access")) {
		t.Fatal("source credentials leaked into observations")
	}
}
