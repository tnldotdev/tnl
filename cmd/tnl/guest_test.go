package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/clientauth"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisheridentity"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type guestDemoControlStub struct {
	created int
	token   string
}

func TestGuestDemoPublisherUsesTrialOnlyToEnrollAndSignedKeyToStartRun(t *testing.T) {
	guestToken, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	guest := clientstate.GuestSession{
		AccessToken: guestToken.String(), TeamID: "tm_0123456789abcdefghijkl",
		DomainID: "dom_0123456789abcdefghijkl", Namespace: "guest-01234567.example.test",
	}
	clientID, _ := opaqueid.New(opaqueid.PublisherIdentityPrefix)
	keyID, _ := opaqueid.New(opaqueid.PublisherIdentityKeyPrefix)
	grantID, _ := opaqueid.New(opaqueid.PublisherGrantPrefix)
	const routeID = "url_0123456789abcdefghijkl"
	const runKey = "guest-first-run"
	access := "pta_" + base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	var public ed25519.PublicKey
	var server *httptest.Server
	var started bool
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/guest-demo/publisher":
			if r.Header.Get("Authorization") != "Bearer "+guestToken.String() {
				t.Errorf("registration did not use the guest trial")
			}
			var body controlv1.RegisterGuestPublisherIdentityRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			public, _ = base64.RawURLEncoding.DecodeString(body.PublicKey)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(controlv1.GuestPublisherIdentity{
				ClientId: clientID, KeyId: keyID, GrantId: grantID, TeamId: guest.TeamID,
				DomainId: guest.DomainID, Namespace: guest.Namespace,
			})
		case "/v1/publisher/token":
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			if r.PostForm.Get("client_id") != clientID || r.PostForm.Get("scope") != grantID {
				t.Errorf("wrong publisher grant: %v", r.PostForm)
			}
			if _, err := publisheridentity.Verify(r.PostForm.Get("client_assertion"), clientID,
				server.URL+"/v1/publisher/token", keyID, public, time.Now()); err != nil {
				t.Errorf("unsigned publisher token request: %v", err)
			}
			_, _ = w.Write([]byte(`{"access_token":"` + access + `","token_type":"Bearer","expires_in":300,"scope":"` + grantID + `"}`))
		case "/v1/public-urls/" + routeID + "/publish-runs":
			if r.Header.Get("Authorization") != "Bearer "+access || r.Header.Get("Idempotency-Key") != runKey {
				t.Errorf("run used the wrong token or key")
			}
			var body controlv1.CreatePublishRunRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.PublisherProof == nil {
				t.Errorf("missing run proof: %v", err)
			} else if _, err := publisheridentity.VerifyRun(public, *body.PublisherProof, routeID, runKey); err != nil {
				t.Errorf("invalid signed run proof: %v", err)
			}
			started = true
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Errorf("unexpected request: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	trial, err := controlclient.New(server.URL, server.Client(), guestToken)
	if err != nil {
		t.Fatal(err)
	}
	control, err := newGuestSignedControlWithHTTP(t.Context(), server.URL, guest, &clientauth.Client{Control: trial}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := control.CreatePublishRun(t.Context(), routeID, runKey); err != nil || !started {
		t.Fatalf("guest signed publish run: started=%t, error=%v", started, err)
	}
}

func (c *guestDemoControlStub) Discovery(context.Context) (controlv1.ControlDiscovery, error) {
	return controlv1.ControlDiscovery{GuestDemo: true}, nil
}

func (c *guestDemoControlStub) CreateGuestDemo(context.Context) (controlv1.GuestDemoSession, error) {
	c.created++
	return controlv1.GuestDemoSession{
		AccessToken: c.token, GuestId: "gst_0123456789abcdefghijkl",
		TeamId: "tm_0123456789abcdefghijkl", MembershipId: "mem_0123456789abcdefghijkl",
		DomainId: "dom_0123456789abcdefghijkl", Namespace: "guest-01234567.example",
		ExpiresAt: time.Now().UTC().Add(72 * time.Hour),
	}, nil
}

func TestGuestDemoReusesOneCredentialAndRejectsAccessOverrides(t *testing.T) {
	database, err := clientstate.Open(t.Context(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	token, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	control := &guestDemoControlStub{token: token.String()}
	for range 2 {
		guest, err := guestForDemoWithControl(t.Context(), database, "https://control.example", publishCommand{Demo: true}, control)
		if err != nil || guest == nil || guest.Namespace != "guest-01234567.example" ||
			guest.AccessToken != token.String() || control.created != 1 {
			t.Fatalf("guest = %+v; created = %d; error = %v", guest, control.created, err)
		}
	}
	if _, err := guestForDemoWithControl(t.Context(), database, "https://control.example", publishCommand{
		Demo: true, tunnelFlags: tunnelFlags{AllowAllIPs: true},
	}, control); err == nil {
		t.Fatal("guest changed the visitor IP policy")
	}
}

func TestGuestDemoReplacesExpiredLocalCredential(t *testing.T) {
	database, err := clientstate.Open(t.Context(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	store, err := database.Server(t.Context(), "https://control.example")
	if err != nil {
		t.Fatal(err)
	}
	token, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveGuestSession(t.Context(), clientstate.GuestSession{
		GuestID: "gst_0123456789abcdefghijkl", AccessToken: token.String(),
		TeamID: "tm_0123456789abcdefghijkl", MembershipID: "mem_0123456789abcdefghijkl",
		DomainID: "dom_0123456789abcdefghijkl", Namespace: "guest-01234567.example",
		ExpiresAt: time.Now().Add(-time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	control := &guestDemoControlStub{token: token.String()}
	guest, err := guestForDemoWithControl(t.Context(), database, "https://control.example", publishCommand{Demo: true}, control)
	if err != nil || guest == nil || control.created != 1 || !guest.ExpiresAt.After(time.Now()) {
		t.Fatalf("replacement guest = %+v; created = %d; error = %v", guest, control.created, err)
	}
}
