package integrations

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/client/webhooksource"
	"github.com/tnldotdev/tnl/internal/config"
)

func TestRunningWebhookPolicyRefreshTightensAndExpiresWithoutChangingAdmittedWork(t *testing.T) {
	state, _ := callbackState(t)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(target.Close)
	definitions := map[string]config.Webhook{
		"stripe": {Service: "api", Path: "/stripe", Provider: "stripe"},
		"github": {Service: "api", Path: "/github", Provider: "github"},
		"fixed":  {Service: "api", Path: "/fixed", Provider: "stripe", SourceIPs: []string{"203.0.113.0/24"}},
	}
	tunnel, _ := readyTunnel(t, state, target.URL, "receiver.example.test")
	for name, definition := range definitions {
		encoded, _, err := DefinitionBytes(definition)
		if err != nil {
			t.Fatal(err)
		}
		if err := tunnel.RegisterWebhookEndpoint(t.Context(), name, encoded); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now()
	start := now
	var failStripe bool
	var tight bool
	lookups := map[string]int{}
	resolve := func(_ context.Context, _ webhooksource.Cache, _, provider string) (webhooksource.Source, error) {
		lookups[provider]++
		if provider == "stripe" && failStripe {
			return webhooksource.Source{}, errors.New("provider fetch failed")
		}
		prefix := "198.51.100.0/24"
		if provider == "stripe" {
			prefix = "192.0.2.0/24"
			if tight {
				prefix = "192.0.2.0/25"
			}
		}
		return webhooksource.Source{Name: provider, Prefixes: []string{prefix}, Revision: prefix,
			RefreshAt: now.Add(15 * time.Minute), ValidUntil: now.Add(24 * time.Hour)}, nil
	}
	h, union, err := newWebhooks(t.Context(), state, testServer, testIntegrationScope, "hooks.project.example.test", definitions, nil, resolve)
	if err != nil || !slices.Equal(union, []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"}) {
		t.Fatal("initial provider union", union, err)
	}
	// the owner supplies a clock only in this deterministic white-box proof.
	h.now = func() time.Time { return now }
	now = start.Add(14 * time.Minute)
	if err := h.RefreshPolicies(t.Context(), func(context.Context, []string) error {
		t.Error("fresh policies triggered a service-union rewrite")
		return nil
	}); err != nil || lookups["stripe"] != 1 || lookups["github"] != 1 {
		t.Fatal("fresh provider policies were fetched again", lookups, err)
	}
	send := func(path, source string, body io.ReadCloser) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, "https://hooks.project.example.test"+path, body)
		r.RemoteAddr = source + ":1234"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	held := &heldWebhookBody{entered: make(chan struct{}), release: make(chan struct{})}
	release := sync.OnceFunc(func() { close(held.release) })
	t.Cleanup(release)
	done := make(chan *httptest.ResponseRecorder, 1)
	joined := make(chan struct{})
	t.Cleanup(func() {
		release()
		select {
		case <-joined:
		case <-time.After(5 * time.Second):
			t.Error("held webhook request did not join cleanup")
		}
	})
	go func() { defer close(joined); done <- send("/stripe", "192.0.2.200", held) }()
	select {
	case <-held.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("original allowed request did not reach its body-read boundary")
	}
	tight, now = true, start.Add(15*time.Minute)
	var installed []string
	install := func(_ context.Context, prefixes []string) error {
		installed = slices.Clone(prefixes)
		return nil
	}
	if err := h.RefreshPolicies(t.Context(), install); err != nil ||
		!slices.Equal(installed, []string{"192.0.2.0/25", "198.51.100.0/24", "203.0.113.0/24"}) {
		t.Fatal("running refresh did not install the current provider union", installed, err)
	}
	denied := &untrustedBody{}
	if response := send("/stripe", "192.0.2.200", denied); response.Code != http.StatusForbidden || denied.reads.Load() != 0 {
		t.Fatal("tightened provider policy read or admitted a newly excluded request", response.Code)
	}
	if response := send("/stripe", "192.0.2.1", io.NopCloser(strings.NewReader("new"))); response.Code != http.StatusOK {
		t.Fatal("current source could not reach the running handler", response.Code)
	}
	select {
	case <-done:
		t.Fatal("source refresh completed or interrupted an original held request")
	default:
	}
	failStripe, now = true, start.Add(30*time.Minute)
	if err := h.RefreshPolicies(t.Context(), install); err != nil {
		t.Fatal(err)
	}
	if response := send("/stripe", "192.0.2.1", io.NopCloser(strings.NewReader("cached"))); response.Code != http.StatusOK {
		t.Fatal("fetch failure discarded a still-valid last policy", response.Code)
	}
	// no refresh tick is required to enforce the actual policy expiry.
	now = start.Add(24*time.Hour + 15*time.Minute)
	expired := &untrustedBody{}
	if response := send("/stripe", "192.0.2.1", expired); response.Code != http.StatusServiceUnavailable || expired.reads.Load() != 0 {
		t.Fatal("actually expired source policy admitted or read a new request", response.Code)
	}
	for _, test := range []struct{ path, ip string }{{"/github", "198.51.100.1"}, {"/fixed", "203.0.113.1"}} {
		if response := send(test.path, test.ip, io.NopCloser(strings.NewReader("independent"))); response.Code != http.StatusOK {
			t.Error("one expired provider blocked an independent endpoint or explicit replacement", test.path, response.Code)
		}
	}
	// provider freshness bounds new request admission, not the lifetime of an
	// already-admitted delivery. service/run authority and target deadlines are
	// independent and remain owned by the publication and delivery paths.
	release()
	select {
	case response := <-done:
		if response.Code != http.StatusOK {
			t.Error("refresh/expiry changed an already-admitted request's captured rules", response.Code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("admitted request did not join after release")
	}
	if lookups["stripe"] != 3 || lookups["github"] != 3 {
		t.Error("explicit source_ips unexpectedly fetched or joined the provider's policy", lookups)
	}
}

type heldWebhookBody struct {
	entered, release chan struct{}
	once             sync.Once
}

func (b *heldWebhookBody) Read([]byte) (int, error) {
	b.once.Do(func() { close(b.entered) })
	<-b.release
	return 0, io.EOF
}

func (*heldWebhookBody) Close() error { return nil }

func TestWebhookPolicyRefreshNeverWidensOnFailureOrEmptyUnion(t *testing.T) {
	state, _ := callbackState(t)
	now := time.Now()
	var unrestricted, unavailable bool
	resolver := func(context.Context, webhooksource.Cache, string, string) (webhooksource.Source, error) {
		if unavailable {
			return webhooksource.Source{}, errors.New("provider unavailable")
		}
		return webhooksource.Source{Name: "stripe", Any: unrestricted, Revision: "restricted",
			Prefixes: []string{"192.0.2.0/24"}, RefreshAt: now, ValidUntil: now.Add(24 * time.Hour)}, nil
	}
	h, _, err := newWebhooks(t.Context(), state, testServer, testIntegrationScope, "hooks.project.example.test",
		map[string]config.Webhook{"stripe": {Service: "api", Path: "/stripe", Provider: "stripe"}}, nil, resolver)
	if err != nil {
		t.Fatal(err)
	}
	h.now = func() time.Time { return now }
	installs := 0
	install := func(context.Context, []string) error { installs++; return nil }
	unrestricted = true
	if err := h.RefreshPolicies(t.Context(), install); err != nil {
		t.Fatal(err)
	}
	body := &untrustedBody{}
	request := httptest.NewRequest(http.MethodPost, "https://hooks.project.example.test/stripe", body)
	request.RemoteAddr = "203.0.113.1:1234"
	response := httptest.NewRecorder()
	h.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || body.reads.Load() != 0 || installs != 0 {
		t.Fatal("an implicit unrestricted response widened the endpoint or its coarse filter", response.Code, installs)
	}
	unavailable, now = true, now.Add(24*time.Hour)
	if err := h.RefreshPolicies(t.Context(), install); err != nil {
		t.Fatal(err)
	}
	if h.HasAvailablePolicy() || h.PolicyStatus("stripe") != "unavailable" || installs != 0 {
		t.Fatal("empty expired policy union removed the service's coarse source restriction", installs)
	}
	response = httptest.NewRecorder()
	h.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || body.reads.Load() != 0 {
		t.Fatal("expired provider policy read or forwarded a body", response.Code)
	}
}

func TestWebhookPolicyTightensBeforeAFailedCoarseUnionWrite(t *testing.T) {
	state, _ := callbackState(t)
	now := time.Now()
	tight := false
	h, _, err := newWebhooks(t.Context(), state, testServer, testIntegrationScope, "hooks.project.example.test",
		map[string]config.Webhook{"stripe": {Service: "api", Path: "/stripe", Provider: "stripe"}}, nil,
		func(context.Context, webhooksource.Cache, string, string) (webhooksource.Source, error) {
			prefix := "192.0.2.0/24"
			if tight {
				prefix = "192.0.2.0/25"
			}
			return webhooksource.Source{Name: "stripe", Revision: prefix, Prefixes: []string{prefix},
				RefreshAt: now, ValidUntil: now.Add(24 * time.Hour)}, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	h.now = func() time.Time { return now }
	tight = true
	cause := errors.New("coarse source union write unavailable")
	if err := h.RefreshPolicies(t.Context(), func(_ context.Context, prefixes []string) error {
		if !slices.Equal(prefixes, []string{"192.0.2.0/25"}) {
			t.Error("wrong provider union sent to its existing service", prefixes)
		}
		return cause
	}); !errors.Is(err, cause) {
		t.Fatal("coarse source update failure was hidden", err)
	}
	body := &untrustedBody{}
	request := httptest.NewRequest(http.MethodPost, "https://hooks.project.example.test/stripe", body)
	request.RemoteAddr = "192.0.2.200:1234"
	response := httptest.NewRecorder()
	h.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || body.reads.Load() != 0 || !h.HasAvailablePolicy() {
		t.Fatal("failed coarse write discarded tightening, read a denied body, or blocked every endpoint", response.Code)
	}
}
