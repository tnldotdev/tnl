package publisherauth

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/authorityclient"
	"github.com/tnldotdev/tnl/internal/clientauth"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/publisheridentity"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestInteractiveOwnerCreatesOneIdentityWithSeparateURLGrants(t *testing.T) {
	const urlA = "url_0123456789abcdefghijkl"
	const urlB = "url_abcdefghijkl0123456789"
	const clientID = "pub_0123456789abcdefghijkl"
	const keyID = "pik_0123456789abcdefghijkl"
	const firstGrant = "pgr_0123456789abcdefghijkl"
	const secondGrant = "pgr_abcdefghijkl0123456789"
	access := "pta_" + strings.Repeat("a", 43)
	var public ed25519.PublicKey
	var enrollmentCount, grantCount, runCount, revocations int
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		write := func(code int, body any) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(code)
			if err := json.NewEncoder(w).Encode(body); err != nil {
				t.Error(err)
			}
		}
		path := r.URL.Path
		switch {
		case strings.HasPrefix(path, "/v1/public-urls/") && r.Method == http.MethodGet:
			if r.Header.Get("Authorization") != "Bearer human" {
				t.Errorf("URL lookup did not use the human session: %q", r.Header.Get("Authorization"))
			}
			id := strings.TrimPrefix(path, "/v1/public-urls/")
			write(http.StatusOK, controlv1.PublicURL{Id: id, TeamId: "tm_team", CanonicalHostname: id + ".example.test"})
		case path == "/v1/publisher/enrollments":
			enrollmentCount++
			id := urlA
			if r.Header.Get("Authorization") != "Bearer human" {
				t.Errorf("enrollment lacked human authorization: %q", r.Header.Get("Authorization"))
			}
			write(http.StatusCreated, controlv1.IssuedPublisherEnrollment{
				Id: "pen_0123456789abcdefghijkl", EnrollmentKey: "one-use-key", TeamId: "tm_team",
				PublicUrlId: &id, Name: "local-publisher", Kind: "saved_url", ExpiresAt: time.Now().Add(time.Hour),
			})
		case path == "/v1/publisher/enrollments/redeem":
			if r.Header.Get("Authorization") != "" {
				t.Errorf("human token forwarded to enrollment redemption: %q", r.Header.Get("Authorization"))
			}
			var body struct {
				PublicKey string `json:"public_key"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			decoded, _ := base64.RawURLEncoding.DecodeString(body.PublicKey)
			public = ed25519.PublicKey(decoded)
			write(http.StatusOK, map[string]any{"client_id": clientID, "key_id": keyID, "grant_id": firstGrant,
				"public_url_id": urlA, "team_id": "tm_team", "kind": "saved_url"})
		case path == "/v1/publisher-identities/"+clientID+"/grants":
			grantCount++
			id := urlB
			if r.Header.Get("Authorization") != "Bearer human" {
				t.Errorf("adding a grant lacked human authorization: %q", r.Header.Get("Authorization"))
			}
			write(http.StatusCreated, controlv1.PublisherGrant{Id: secondGrant, TeamId: "tm_team", PublicUrlId: &id, Kind: "saved_url"})
		case path == "/v1/publisher-identities/"+clientID && r.Method == http.MethodDelete:
			revocations++
			if r.Header.Get("Authorization") != "Bearer human" || r.URL.Query().Get("team_id") != "tm_team" {
				t.Errorf("owner revocation lost human team authorization: %q", r.Header.Get("Authorization"))
			}
			w.WriteHeader(http.StatusNoContent)
		case path == "/v1/publisher/token":
			if r.Header.Get("Authorization") != "" {
				t.Errorf("human token forwarded to publisher token exchange: %q", r.Header.Get("Authorization"))
			}
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			if _, err := publisheridentity.Verify(r.Form.Get("client_assertion"), clientID,
				server.URL+"/v1/publisher/token", keyID, public, time.Now()); err != nil {
				t.Errorf("publisher assertion: %v", err)
			}
			write(http.StatusOK, map[string]any{"access_token": access, "token_type": "Bearer", "expires_in": 299, "scope": r.Form.Get("scope")})
		case strings.HasSuffix(path, "/publish-runs"):
			runCount++
			if r.Header.Get("Authorization") != "Bearer "+access {
				t.Errorf("run used a human token: %q", r.Header.Get("Authorization"))
			}
			id := strings.TrimSuffix(strings.TrimPrefix(path, "/v1/public-urls/"), "/publish-runs")
			var body controlv1.CreatePublishRunRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.PublisherProof == "" {
				t.Errorf("run request: %+v, %v", body, err)
			}
			if body.PublisherProof != "" {
				if _, err := publisheridentity.VerifyRun(public, body.PublisherProof, id, r.Header.Get("Idempotency-Key")); err != nil {
					t.Errorf("run proof: %v", err)
				}
			}
			write(http.StatusCreated, map[string]any{"publish_run": map[string]any{}})
		default:
			t.Errorf("unexpected owner request: %s %s", r.Method, path)
			write(http.StatusNotFound, map[string]any{"code": "not_found"})
		}
	}))
	defer server.Close()
	humanControl, err := controlclient.New(server.URL, server.Client(), credentials.AccessToken("human"))
	if err != nil {
		t.Fatal(err)
	}
	rawControl, err := controlclient.New(server.URL, server.Client(), "")
	if err != nil {
		t.Fatal(err)
	}
	rawAuthority, err := authorityclient.New(server.URL, server.Client(), "")
	if err != nil {
		t.Fatal(err)
	}
	human := &clientauth.Client{Control: humanControl, PublisherControl: rawControl, PublisherAuthority: rawAuthority}
	owner, err := Interactive(human, "local-publisher")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := owner.CreateRun(t.Context(), urlA, "ik_first"); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.CreateRun(t.Context(), urlB, "ik_second"); err != nil {
		t.Fatal(err)
	}
	if enrollmentCount != 1 || grantCount != 1 || runCount != 2 {
		t.Fatalf("owner operations: enrollments=%d grants=%d runs=%d", enrollmentCount, grantCount, runCount)
	}
	if err := owner.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := owner.Close(t.Context()); err != nil || revocations != 1 {
		t.Fatalf("run-scoped publisher revocations = %d, %v", revocations, err)
	}
	if _, err := owner.CreateRun(t.Context(), urlA, "after-close"); !errors.Is(err, ErrGrant) {
		t.Fatalf("closed native owner reused its publisher identity: %v", err)
	}
}

func TestInstalledOwnerSignsRunsAfterPrivateKeyRestart(t *testing.T) {
	const id = "url_0123456789abcdefghijkl"
	access := "pta_" + strings.Repeat("a", 43)
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	public := private.Public().(ed25519.PublicKey)
	var requests int
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/publisher/token":
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			if _, err := publisheridentity.Verify(r.Form.Get("client_assertion"), "pub_installed",
				server.URL+"/v1/publisher/token", "pik_key", public, time.Now()); err != nil {
				t.Errorf("restored publisher assertion: %v", err)
			}
			if r.Form.Get("scope") != "pgr_scope" {
				t.Error("restored publisher used a different grant")
			}
			_, _ = w.Write([]byte(`{"access_token":"` + access + `","token_type":"Bearer","expires_in":299,"scope":"pgr_scope"}`))
		case "/v1/public-urls/" + id + "/publish-runs":
			requests++
			if r.Header.Get("Authorization") != "Bearer "+access {
				t.Error("restored publisher sent a human credential")
			}
			var body controlv1.CreatePublishRunRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			} else if _, err := publisheridentity.VerifyRun(public, body.PublisherProof, id, r.Header.Get("Idempotency-Key")); err != nil {
				t.Errorf("restored publisher run proof: %v", err)
			}
			_, _ = w.Write([]byte(`{"publish_run":{}}`))
		default:
			t.Errorf("unexpected restored publisher request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	control, err := controlclient.New(server.URL, server.Client(), "")
	if err != nil {
		t.Fatal(err)
	}
	authority, err := authorityclient.New(server.URL, server.Client(), "")
	if err != nil {
		t.Fatal(err)
	}
	url := id
	installed := InstalledIdentity{PrivateKey: private, Enrollment: authorityv1.PublisherEnrollmentResult{
		ClientId: "pub_installed", KeyId: "pik_key", GrantId: "pgr_scope", TeamId: "tm_team",
		Kind: "saved_url", PublicUrlId: &url,
	}}
	first, err := Restore(control, authority, installed)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := first.InstalledIdentity()
	if err != nil {
		t.Fatal(err)
	}
	serialized, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	var loaded InstalledIdentity
	if err := json.Unmarshal(serialized, &loaded); err != nil {
		t.Fatal(err)
	}
	restarted, err := Restore(control, authority, loaded)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.CreateRun(t.Context(), id, "ik_restarted"); err != nil || requests != 1 {
		t.Fatalf("restored owner run count = %d, %v", requests, err)
	}
}
