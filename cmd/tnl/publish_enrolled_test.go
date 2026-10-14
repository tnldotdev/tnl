package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/authorityclient"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/publisheridentity"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestEnrolledControlSendsScopedBearerAndSignedRun(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const clientID, keyID, grantID, urlID = "pi_test", "pik_test", "pg_test", "pu_test"
	const attempt = "run-attempt"
	var origin string
	var runs int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/publisher/token":
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			if r.Form.Get("scope") != grantID || r.Form.Get("client_id") != clientID {
				t.Errorf("wrong grant or identity: %v", r.Form)
			}
			if _, err := publisheridentity.Verify(r.Form.Get("client_assertion"), clientID,
				origin+r.URL.Path, keyID, public, time.Now()); err != nil {
				t.Errorf("publisher assertion: %v", err)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(authorityv1.PublisherTokenResponse{
				AccessToken: "pta_" + strings.Repeat("a", 43), TokenType: "Bearer", Scope: grantID, ExpiresIn: 300,
			})
		case "/v1/public-urls/" + urlID + "/publish-runs":
			runs++
			if r.Header.Get("Authorization") != "Bearer pta_"+strings.Repeat("a", 43) || r.Header.Get("Idempotency-Key") != attempt {
				t.Errorf("unscoped publisher request: %s %s", r.Header.Get("Authorization"), r.Header.Get("Idempotency-Key"))
			}
			var body controlv1.CreatePublishRunRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.PublisherProof == nil {
				t.Errorf("missing signed run proof: %+v, %v", body, err)
			} else if _, err := publisheridentity.VerifyRun(public, *body.PublisherProof, urlID, attempt); err != nil {
				t.Errorf("invalid signed run proof: %v", err)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	origin = server.URL
	client, err := controlclient.New(origin, server.Client(), "")
	if err != nil {
		t.Fatal(err)
	}
	authority, err := authorityclient.New(origin, server.Client(), "")
	if err != nil {
		t.Fatal(err)
	}
	control := &enrolledControl{Client: client, authority: authority, private: private,
		identity: authorityv1.PublisherEnrollmentResult{ClientId: clientID, KeyId: keyID, GrantId: grantID}}
	if _, err := control.CreatePublishRun(context.Background(), urlID, attempt); err != nil || runs != 1 {
		t.Fatalf("native publisher run = %d, %v", runs, err)
	}
}
