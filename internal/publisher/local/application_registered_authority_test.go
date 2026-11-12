package local

import (
	"bytes"
	"context"
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
	"sync"
	"testing"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/publisher"
	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
	"github.com/tnldotdev/tnl/internal/security/machineproof"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestRegisteredApplicationCanonicalReplyRecoveryAndRevokedSourceCleanup(t *testing.T) {
	a, _ := testAppRuntimeWorkers(t, true)
	endpoint, request, sourcePrivate := registeredApplicationRequest(t, a)
	request.ResourceId = nil
	request.Allocate = &struct {
		Namespace string `json:"namespace"`
	}{Namespace: "apps.example"}
	const suffix = "0123456789ABCDEFGHIJKL"
	response := authorityv1.MachinePublicationSession{Id: "mps_" + suffix, TokenType: "Bearer", AccessToken: "private-access", ExpiresAt: time.Now().Add(time.Minute), IdentityExpiresAt: time.Now().Add(5 * time.Minute), RenewAfter: time.Now().Add(30 * time.Second), Publisher: authorityv1.PublisherEnrollmentResult{ClientId: "pub_" + suffix, KeyId: "pkey_" + suffix, GrantId: "pgrant_" + suffix, TeamId: "tm_" + suffix, Kind: authorityv1.Namespace, DomainId: new("dom_" + suffix), Namespace: new("apps.example")}}
	url := controlv1.PublicURL{Id: "url_" + suffix, TeamId: response.Publisher.TeamId, DomainId: *response.Publisher.DomainId, CanonicalHostname: strings.Repeat("a", 26) + ".apps.example", Target: request.Target, Ephemeral: true, ServiceProtocol: controlv1.Http, Purpose: controlv1.App, LifecycleState: controlv1.Enabled, AccessMode: controlv1.Restricted}
	var mu sync.Mutex
	var nativePublic ed25519.PublicKey
	var originalNonce string
	var assertions []string
	var exchanges, refreshes, allocations, tokens, cleanups int
	loseExchange, loseRefresh, revoked := true, false, false
	lost := errors.New("remote reply lost after commit")
	a.ApplicationAuthority = NewControlApplicationAuthority(&http.Client{Transport: invocationTransport(func(r *http.Request) (*http.Response, error) {
		mu.Lock()
		defer mu.Unlock()
		if _, bounded := r.Context().Deadline(); !bounded {
			t.Error("unbounded registered authority request")
		}
		decode := func(value any) {
			t.Helper()
			if err := json.NewDecoder(r.Body).Decode(value); err != nil {
				t.Fatal(err)
			}
		}
		reply := func(value any) (*http.Response, error) {
			encoded, _ := json.Marshal(value)
			return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(encoded))}, nil
		}
		verifySource := func(assertion, operation, nonce string) {
			t.Helper()
			scope := machineproof.Publication("", "apps.example", operation, base64.RawURLEncoding.EncodeToString(nativePublic), nonce)
			if _, err := publisherproof.Verify(assertion, "mci_"+suffix, "source-key", scope, request.ServerUrl+r.URL.Path, sourcePrivate.Public().(ed25519.PublicKey), time.Now()); err != nil {
				t.Fatal("source JWT did not bind canonical scope/audience", err)
			}
			assertions = append(assertions, assertion)
		}
		switch r.URL.Path {
		case "/v1/machine-publication-sessions/exchange":
			exchanges++
			var body authorityv1.MachinePublicationExchange
			decode(&body)
			public, _ := base64.RawURLEncoding.Strict().DecodeString(body.PublicKey)
			if nativePublic == nil {
				nativePublic = append(ed25519.PublicKey(nil), public...)
				originalNonce = body.Nonce
			}
			signature, _ := base64.RawURLEncoding.Strict().DecodeString(body.Signature)
			if body.MachineId != "mci_"+suffix || body.Namespace != "apps.example" || body.Nonce != originalNonce || !bytes.Equal(public, nativePublic) || !ed25519.Verify(nativePublic, machineproof.PublicationPossession("", "apps.example", "exchange", body.PublicKey, body.Nonce, sha256.Sum256([]byte(body.Assertion))), signature) {
				t.Fatal("uncertain exchange replaced original source/native tuple")
			}
			verifySource(body.Assertion, "exchange", body.Nonce)
			if loseExchange {
				loseExchange = false
				return nil, lost
			}
			return reply(response)
		case "/v1/publisher-token":
			tokens++
			var body authorityv1.PublisherTokenRequest
			decode(&body)
			if _, err := publisherproof.Verify(body.ClientAssertion, response.Publisher.ClientId, response.Publisher.KeyId, response.Publisher.GrantId, request.ServerUrl+r.URL.Path, nativePublic, time.Now()); err != nil {
				t.Fatal(err)
			}
			return reply(authorityv1.PublisherTokenResponse{AccessToken: "native-serving-token", GrantId: response.Publisher.GrantId, ExpiresIn: 60, TokenType: "Bearer"})
		case "/v1/publisher/public-urls":
			allocations++
			var body controlv1.AllocateEphemeralPublicURLRequest
			decode(&body)
			if body.InvocationId != request.InvocationId || body.Target != request.Target {
				t.Fatal("allocation replaced original immutable request")
			}
			return reply(url)
		case "/v1/machine-publication-sessions/" + response.Id + "/refresh":
			refreshes++
			var body authorityv1.MachinePublicationRefresh
			decode(&body)
			verifySource(body.Assertion, "refresh", response.Id)
			if revoked {
				return &http.Response{StatusCode: 403, Body: io.NopCloser(strings.NewReader(`{"code":"forbidden"}`))}, nil
			}
			if loseRefresh {
				loseRefresh = false
				response.IdentityExpiresAt = response.IdentityExpiresAt.Add(time.Minute)
				return nil, lost
			}
			return reply(response)
		case "/v1/machine-publication-sessions/" + response.Id + "/cleanup":
			cleanups++
			var body authorityv1.MachinePublicationCleanup
			decode(&body)
			if r.Header.Get("Authorization") != "" || body.InvocationId != request.InvocationId {
				t.Fatal("cleanup requested serving/source authority")
			}
			if _, err := publisherproof.Verify(body.Assertion, response.Publisher.ClientId, response.Publisher.KeyId, machineproof.PublicationCleanup(response.Id, request.InvocationId), request.ServerUrl+r.URL.Path, nativePublic, time.Now()); err != nil {
				t.Fatal("cleanup did not use original native key", err)
			}
			return &http.Response{StatusCode: 204, Body: http.NoBody}, nil
		default:
			t.Fatalf("unexpected registered authority operation %s", r.URL.Path)
			return nil, errors.New("unexpected authority operation")
		}
	})})
	a.workers.RunPublisher = func(ctx context.Context, _ publisher.Config) error { <-ctx.Done(); return ctx.Err() }
	publish := func() (publisherprotocol.AcceptedPublication, error) {
		t.Helper()
		fresh := request
		challenge := issueApplicationChallenge(t, endpoint, fresh)
		reply := signApplicationReply(t, challenge, sourcePrivate)
		fresh.Auth = registeredApplicationAuth(t, &reply)
		var accepted publisherprotocol.AcceptedPublication
		err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/publications", fresh, &accepted)
		return accepted, err
	}
	if _, err := publish(); err == nil {
		t.Fatal("lost exchange was acknowledged")
	}
	accepted, err := publish()
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	loseRefresh = true
	mu.Unlock()
	if _, err := publish(); err == nil {
		t.Fatal("lost refresh was acknowledged")
	}
	recovered, err := publish()
	if err != nil || recovered != accepted {
		t.Fatal("registered recovery replaced accepted URL", err)
	}
	rotated := request
	rotated.Auth = json.RawMessage(strings.ReplaceAll(string(request.Auth), "source-key", "rotated-key"))
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/identity-source-challenges", rotated, new(authorityv1.IdentitySourceChallenge)); err == nil {
		t.Fatal("source key rotation replaced durable source binding")
	}
	mu.Lock()
	revoked = true
	mu.Unlock()
	if _, err := publish(); err == nil {
		t.Fatal("revoked source refreshed serving authority")
	}
	closeErr := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/unregister", accepted.Registration, nil)
	if closeErr != nil {
		var problem *publisherprotocol.ResponseError
		if !errors.As(closeErr, &problem) || problem.Code != "runtime.publication_failed" {
			t.Fatal(closeErr)
		}
	}
	entries, err := a.publications.Entries(t.Context())
	if err != nil || len(entries) != 1 {
		t.Fatal(err)
	}
	record, err := entries[0].Snapshot(t.Context())
	if err != nil || record.Phase != clientstate.ApplicationCleanupDone || len(record.NativeKey) != 0 {
		t.Fatal("revoked-source cleanup was not durable", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if exchanges != 3 || refreshes != 2 || allocations != 1 || tokens != 1 || cleanups != 1 {
		t.Fatalf("recovery/cleanup reacquired authority: exchange=%d refresh=%d allocation=%d token=%d cleanup=%d", exchanges, refreshes, allocations, tokens, cleanups)
	}
	if err := filepath.WalkDir(filepath.Join(a.state.Root(), "identities"), func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, assertion := range assertions {
			if bytes.Contains(data, []byte(assertion)) {
				t.Error("raw registered assertion persisted")
			}
		}
		if bytes.Contains(data, []byte(base64.StdEncoding.EncodeToString(sourcePrivate))) {
			t.Error("source key crossed native persistence")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestRegisteredApplicationPrivateStateFaultPreventsChallengeDelivery(t *testing.T) {
	a, _ := testAppRuntimeWorkers(t, true)
	endpoint, request, _ := registeredApplicationRequest(t, a)
	fingerprint, _ := applicationRequestFingerprint(request)
	entry, err := a.applicationCheckpoint(t.Context(), request, fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	original, err := entry.Snapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(original.NativeKey)
	var scope string
	if err := filepath.WalkDir(filepath.Join(a.state.Root(), "identities"), func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if strings.HasPrefix(entry.Name(), "publication-") {
			scope = filepath.Dir(path)
		}
		return nil
	}); err != nil || scope == "" {
		t.Fatal(err)
	}
	if err := os.Chmod(scope, 0755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(scope, 0700) })
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/identity-source-challenges", request, new(authorityv1.IdentitySourceChallenge)); err == nil {
		t.Fatal("private-state fault delivered a source challenge")
	}
	a.mu.Lock()
	slots := len(a.applicationChallenges)
	a.mu.Unlock()
	if slots != 0 {
		t.Fatal("failed durable handoff retained a deliverable challenge")
	}
	if err := os.Chmod(scope, 0700); err != nil {
		t.Fatal(err)
	}
	challenge := issueApplicationChallenge(t, endpoint, request)
	if challenge.Nonce != original.Nonce || challenge.NativePublicKey != base64.RawURLEncoding.EncodeToString(ed25519.PrivateKey(original.NativeKey).Public().(ed25519.PublicKey)) {
		t.Fatal("private-state recovery replaced original native intent")
	}
}
