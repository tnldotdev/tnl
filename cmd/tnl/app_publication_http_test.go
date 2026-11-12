package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/publisher/invocation"
	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
	"github.com/tnldotdev/tnl/internal/security/machineproof"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	"github.com/tnldotdev/tnl/internal/security/workloadproof"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type applicationHTTPTransport func(*http.Request) (*http.Response, error)

func (f applicationHTTPTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestNativePublicationProductionAuthorityHTTP(t *testing.T) {
	// the actual production constructor chooses the authority. only remote HTTP
	// is replaced; no saved login, installed publisher, or test authority exists.
	for _, allocate := range []bool{false, true} {
		t.Run(map[bool]string{false: "saved", true: "allocated"}[allocate], func(t *testing.T) {
			t.Setenv("TNL_SERVER", "https://wrong.example")
			t.Setenv("TNL_PUBLISHER_CREDENTIAL_FILE", "/must-not-read/publisher.json")
			t.Setenv("TNL_ACCESS_TOKEN", "must-not-use-human-token")
			const suffix = "0123456789ABCDEFGHIJKL"
			const server = "https://control.example"
			selection := invocation.ApplicationSelection{ServerURL: server, InvocationID: "ivk_" + suffix, ResourceID: "url_" + suffix, Target: "http://127.0.0.1:3000", Auth: json.RawMessage(`{"kind":"oidc","machine_id":"mci_0123456789ABCDEFGHIJKL","assertion":"initial-private-proof"}`)}
			response := authorityv1.MachinePublicationSession{Id: "mps_" + suffix, TokenType: "Bearer", AccessToken: "source-bound-access", ExpiresAt: time.Now().Add(time.Minute), IdentityExpiresAt: time.Now().Add(5 * time.Minute), RenewAfter: time.Now().Add(30 * time.Second), Publisher: authorityv1.PublisherEnrollmentResult{ClientId: "pub_" + suffix, KeyId: "pkey_" + suffix, GrantId: "pgrant_" + suffix, TeamId: "tm_" + suffix, Kind: authorityv1.SavedPublicUrl, PublicUrlId: new(selection.ResourceID)}}
			url := controlv1.PublicURL{Id: selection.ResourceID, TeamId: response.Publisher.TeamId, DomainId: "dom_" + suffix, CanonicalHostname: "saved.example", Target: "http://saved-target.example:4000", ServiceProtocol: controlv1.Http, Purpose: controlv1.App, AccessMode: controlv1.Restricted, LifecycleState: controlv1.Enabled, PolicyRevision: 1}
			if allocate {
				selection.ResourceID, selection.Namespace = "", "apps.example"
				response.Publisher.Kind, response.Publisher.PublicUrlId = authorityv1.Namespace, nil
				response.Publisher.Namespace, response.Publisher.DomainId = new(selection.Namespace), new(url.DomainId)
				url.CanonicalHostname, url.Target, url.Ephemeral = strings.Repeat("a", 26)+"."+selection.Namespace, selection.Target, true
			}
			var public ed25519.PublicKey
			var exchanges, tokens, allocations, refreshes, cleanups int
			var revoked bool
			jsonResponse := func(status int, value any) *http.Response {
				encoded, err := json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(encoded))}
			}
			decode := func(r *http.Request, value any) {
				t.Helper()
				defer r.Body.Close()
				if err := json.NewDecoder(r.Body).Decode(value); err != nil {
					t.Fatal(err)
				}
			}
			original := http.DefaultTransport
			http.DefaultTransport = applicationHTTPTransport(func(r *http.Request) (*http.Response, error) {
				if r.URL.Scheme+"://"+r.URL.Host != server {
					t.Fatal("authority used an ambient server")
				}
				if _, bounded := r.Context().Deadline(); !bounded {
					t.Fatal("unbounded authority request")
				}
				path := r.URL.Path
				if strings.HasPrefix(path, "/v1/machine-publication-sessions/") && r.Header.Get("Authorization") != "" {
					t.Fatal("machine proof used a bearer credential")
				}
				switch path {
				case "/v1/machine-publication-sessions/exchange":
					exchanges++
					var body authorityv1.MachinePublicationExchange
					decode(r, &body)
					key, err := base64.RawURLEncoding.Strict().DecodeString(body.PublicKey)
					if err != nil || len(key) != ed25519.PublicKeySize {
						t.Fatal("invalid native session public key")
					}
					public = ed25519.PublicKey(key)
					sig, err := base64.RawURLEncoding.Strict().DecodeString(body.Signature)
					if err != nil || body.MachineId != "mci_0123456789ABCDEFGHIJKL" || body.Resource != selection.ResourceID || body.Namespace != selection.Namespace || !workloadproof.ValidNonce(body.Nonce) || body.Assertion != "initial-private-proof" || !ed25519.Verify(public, machineproof.PublicationPossession(body.Resource, body.Namespace, "exchange", body.PublicKey, body.Nonce, sha256.Sum256([]byte(body.Assertion))), sig) {
						t.Fatal("exchange lost exact source/key/scope possession")
					}
					return jsonResponse(200, response), nil
				case "/v1/publisher-token":
					tokens++
					if revoked {
						t.Fatal("cleanup reacquired a serving token after revocation")
					}
					var body authorityv1.PublisherTokenRequest
					decode(r, &body)
					if body.ClientId != response.Publisher.ClientId || body.GrantId != response.Publisher.GrantId {
						t.Fatal("publisher identity changed")
					}
					if _, err := publisherproof.Verify(body.ClientAssertion, body.ClientId, response.Publisher.KeyId, body.GrantId, server+path, public, time.Now()); err != nil {
						t.Fatal("publisher token did not use original native key")
					}
					return jsonResponse(200, authorityv1.PublisherTokenResponse{AccessToken: "publisher-only-token", ExpiresIn: 60, GrantId: body.GrantId, TokenType: "Bearer"}), nil
				case "/v1/publisher/public-url", "/v1/publisher/public-urls":
					if r.Header.Get("Authorization") != "Bearer publisher-only-token" {
						t.Fatal("URL operation used another authority")
					}
					if allocate {
						allocations++
						var body controlv1.AllocateEphemeralPublicURLRequest
						decode(r, &body)
						if path != "/v1/publisher/public-urls" || body.InvocationId != selection.InvocationID || body.Target != selection.Target {
							t.Fatal("allocation lost exact invocation/target")
						}
					} else if path != "/v1/publisher/public-url" || r.Method != "GET" {
						t.Fatal("saved URL was mutated")
					}
					return jsonResponse(200, url), nil
				case "/v1/machine-publication-sessions/" + response.Id + "/refresh":
					refreshes++
					if revoked {
						return jsonResponse(403, map[string]string{"code": "forbidden"}), nil
					}
					var body authorityv1.MachinePublicationRefresh
					decode(r, &body)
					encoded := base64.RawURLEncoding.EncodeToString(public)
					sig, err := base64.RawURLEncoding.Strict().DecodeString(body.Signature)
					if err != nil || body.Assertion != "fresh-private-proof" || !ed25519.Verify(public, machineproof.PublicationPossession(selection.ResourceID, selection.Namespace, "refresh", encoded, response.Id, sha256.Sum256([]byte(body.Assertion))), sig) {
						t.Fatal("refresh lost original session possession")
					}
					return jsonResponse(200, response), nil
				case "/v1/machine-publication-sessions/" + response.Id + "/cleanup":
					cleanups++
					var body authorityv1.MachinePublicationCleanup
					decode(r, &body)
					if !allocate || body.InvocationId != selection.InvocationID {
						t.Fatal("cleanup escaped allocation tuple")
					}
					if _, err := publisherproof.Verify(body.Assertion, response.Publisher.ClientId, response.Publisher.KeyId, machineproof.PublicationCleanup(response.Id, selection.InvocationID), server+path, public, time.Now()); err != nil {
						t.Fatal("cleanup lost original key/scope/audience")
					}
					if cleanups == 1 {
						return jsonResponse(503, map[string]string{"code": "unavailable"}), nil
					}
					return &http.Response{StatusCode: 204, Body: http.NoBody}, nil
				default:
					t.Fatalf("unexpected authority operation: %s %s", r.Method, path)
					return nil, errors.New("unexpected authority operation")
				}
			})
			t.Cleanup(func() { http.DefaultTransport = original })
			authority := (runtimeOptions{Directory: t.TempDir(), StateDir: t.TempDir()}).settings().ApplicationAuthority
			prepareApplicationCheckpoint(t, &selection)
			grant, err := authority.ResolveApplicationPublication(t.Context(), selection)
			if err != nil {
				t.Fatal(err)
			}
			if grant.Control == nil || grant.PublisherIdentityID != response.Publisher.ClientId || grant.PublicURL.Id != url.Id || grant.PublicURL.CanonicalHostname != url.CanonicalHostname || grant.PublicURL.Target != url.Target || grant.RefreshAuth == nil {
				t.Fatal("production authority lost the exact grant capabilities")
			}
			if err := grant.RefreshAuth(t.Context(), json.RawMessage(`{"kind":"oidc","machine_id":"mci_0123456789ABCDEFGHIJKL","assertion":"fresh-private-proof"}`)); err != nil {
				t.Fatal(err)
			}
			revoked = true
			if err := grant.RefreshAuth(t.Context(), json.RawMessage(`{"kind":"oidc","machine_id":"mci_0123456789ABCDEFGHIJKL","assertion":"fresh-private-proof"}`)); !errors.Is(err, publisherprotocol.ErrApplicationDenied) {
				t.Fatal("source revocation did not fail closed", err)
			}
			if allocate {
				if grant.Cleanup == nil {
					t.Fatal("allocation lacks original-key cleanup")
				}
				if err := grant.Cleanup(t.Context()); err == nil {
					t.Fatal("failed cleanup was cached as success")
				}
				if err := grant.Cleanup(t.Context()); err != nil {
					t.Fatal(err)
				}
				if err := grant.Cleanup(t.Context()); err != nil || cleanups != 2 {
					t.Fatal("cleanup did not cache only success", err)
				}
			} else if grant.Cleanup != nil {
				t.Fatal("saved URL acquired deletion cleanup")
			}
			if exchanges != 1 || tokens != 1 || refreshes != 2 || allocations != map[bool]int{false: 0, true: 1}[allocate] {
				t.Fatal("production path repeated exchange/allocation or changed serving authority")
			}
		})
	}
}

func prepareApplicationCheckpoint(t *testing.T, selection *invocation.ApplicationSelection) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	owner, err := clientstate.OpenApplicationPublications(root, root, root, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close() })
	binding := clientstate.ApplicationPublicationBinding{ServerURL: selection.ServerURL, InvocationID: selection.InvocationID, OwnerHash: strings.Repeat("1", 64), PID: os.Getpid(), Target: selection.Target, ConfigurationDigest: strings.Repeat("2", 64), RequestDigest: strings.Repeat("3", 64), ResourceID: selection.ResourceID, Namespace: selection.Namespace, SourceKind: "oidc", SourceMachineID: "mci_0123456789ABCDEFGHIJKL"}
	selection.Publication, err = owner.Publication(t.Context(), binding, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
}
