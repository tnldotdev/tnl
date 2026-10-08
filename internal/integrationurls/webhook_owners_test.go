package integrationurls

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/config"
)

func TestExclusiveWebhookOwnerCannotBeStolenDuringReprovisioning(t *testing.T) {
	state, _ := callbackState(t)
	definition := config.Webhook{Service: "api", Path: "/hooks/respond", Delivery: "exclusive", AllowFrom: config.WebhookSources{IPs: []string{"192.0.2.0/24"}}}
	encoded, digest, err := DefinitionBytes(definition)
	if err != nil {
		t.Fatal(err)
	}
	var calls [2]atomic.Int32
	var owner *clientstate.Tunnel
	var other *clientstate.Tunnel
	for index, host := range []string{"main.example.test", "feature.example.test"} {
		server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			calls[index].Add(1)
			response.Header().Set("Content-Type", "application/xml")
			if index == 0 {
				response.WriteHeader(http.StatusAccepted)
				_, _ = io.WriteString(response, "<first/>")
			} else {
				response.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(response, "<second/>")
			}
		}))
		t.Cleanup(server.Close)
		tunnel, _ := readyTunnel(t, state, server.URL, host)
		if err := tunnel.RegisterWebhookEndpoint(t.Context(), "respond", encoded); err != nil {
			t.Fatal(err)
		}
		if index == 0 {
			owner = tunnel
		} else {
			other = tunnel
		}
	}
	if err := state.ClaimWebhookReceiver(t.Context(), testServer, testOAuthHost, "respond", owner.ID(), digest, false); err != nil {
		t.Fatal(err)
	}
	if err := state.ClaimWebhookReceiver(t.Context(), testServer, testOAuthHost, "respond", other.ID(), digest, false); !errors.Is(err, clientstate.ErrWebhookOwned) {
		t.Fatalf("stole ready owner: %v", err)
	}
	if err := state.ReleaseWebhookReceiver(t.Context(), testServer, testOAuthHost, "respond", other.ID()); !errors.Is(err, clientstate.ErrWebhookNotSelected) {
		t.Fatalf("another worktree released the owner: %v", err)
	}
	if err := owner.SetProvisioning(t.Context(), 2); err != nil {
		t.Fatal(err)
	}
	if err := state.ClaimWebhookReceiver(t.Context(), testServer, testOAuthHost, "respond", other.ID(), digest, false); !errors.Is(err, clientstate.ErrWebhookOwned) {
		t.Fatalf("reprovisioning lost the live owner's claim: %v", err)
	}
	if err := owner.SetReady(t.Context(), "https://main.example.test", 2); err != nil {
		t.Fatal(err)
	}
	handler, _, err := NewWebhooks(t.Context(), state, testServer, testOAuthHost, "hooks.project.example.test", map[string]config.Webhook{"respond": definition}, nil)
	if err != nil {
		t.Fatal(err)
	}
	send := func(wantStatus int, wantBody string) {
		t.Helper()
		request := httptest.NewRequest(http.MethodPost, "https://hooks.project.example.test/hooks/respond", strings.NewReader("signed-body"))
		request.RemoteAddr = "192.0.2.1:1234"
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != wantStatus || response.Body.String() != wantBody || response.Header().Get("Content-Type") != "application/xml" {
			t.Fatalf("exclusive reply = %d %q", response.Code, response.Body.String())
		}
	}
	send(http.StatusAccepted, "<first/>")
	if calls[0].Load() != 1 || calls[1].Load() != 0 {
		t.Fatal("exclusive request fanned out")
	}
	if err := owner.Finish(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	if err := state.ClaimWebhookReceiver(t.Context(), testServer, testOAuthHost, "respond", other.ID(), digest, false); err != nil {
		t.Fatal(err)
	}
	// the sole receiver's HTTP error is meaningful to the provider too.
	send(http.StatusBadRequest, "<second/>")
	if calls[1].Load() != 1 {
		t.Fatal("successor did not receive the request")
	}
}

func TestExclusiveWebhookForceRequiresReadyReceiverAndSwitchesAtomically(t *testing.T) {
	state, _ := callbackState(t)
	definition := config.Webhook{Service: "api", Path: "/hooks/payments", Delivery: "exclusive", AllowFrom: config.WebhookSources{IPs: []string{"192.0.2.0/24"}}}
	encoded, digest, err := DefinitionBytes(definition)
	if err != nil {
		t.Fatal(err)
	}
	owner, _ := readyTunnel(t, state, "3000", "main.example.test")
	other, _ := readyTunnel(t, state, "4000", "feature.example.test")
	for _, tunnel := range []*clientstate.Tunnel{owner, other} {
		if err := tunnel.RegisterWebhookEndpoint(t.Context(), "payments", encoded); err != nil {
			t.Fatal(err)
		}
	}
	if err := state.ClaimWebhookReceiver(t.Context(), testServer, testOAuthHost, "payments", owner.ID(), digest, false); err != nil {
		t.Fatal(err)
	}
	if err := other.SetProvisioning(t.Context(), 2); err != nil {
		t.Fatal(err)
	}
	if err := state.ClaimWebhookReceiver(t.Context(), testServer, testOAuthHost, "payments", other.ID(), digest, true); !errors.Is(err, clientstate.ErrWebhookReceiverUnavailable) {
		t.Fatalf("unready receiver displaced its owner: %v", err)
	}
	selected, err := state.ExclusiveWebhookReceiver(t.Context(), testServer, testOAuthHost, "payments", digest)
	if err != nil || selected.ID != owner.ID() {
		t.Fatalf("owner changed after rejected takeover: %+v, %v", selected, err)
	}
	if err := other.SetReady(t.Context(), "https://feature.example.test", 2); err != nil {
		t.Fatal(err)
	}
	if err := state.ClaimWebhookReceiver(t.Context(), testServer, testOAuthHost, "payments", other.ID(), digest, true); err != nil {
		t.Fatal(err)
	}
	selected, err = state.ExclusiveWebhookReceiver(t.Context(), testServer, testOAuthHost, "payments", digest)
	if err != nil || selected.ID != other.ID() {
		t.Fatalf("forced takeover did not switch: %+v, %v", selected, err)
	}
	if err := state.ClaimWebhookReceiver(t.Context(), testServer, testOAuthHost, "payments", owner.ID(), digest, false); !errors.Is(err, clientstate.ErrWebhookOwned) {
		t.Fatalf("old owner silently reclaimed selection: %v", err)
	}
}
