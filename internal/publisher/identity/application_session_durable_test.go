package identity

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

	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/security/machineproof"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type publicationHTTP func(*http.Request) (*http.Response, error)

func (f publicationHTTP) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

var lostApplicationReply = errors.New("reply lost after remote commit")

// this fixture uses the canonical clients and wire contracts. only HTTP is
// replaced; each remote mutation checks the real, synced private checkpoint.
type durableApplicationHTTP struct {
	t                                                              *testing.T
	root                                                           string
	owner                                                          *clientstate.ApplicationPublications
	entry                                                          *clientstate.ApplicationPublication
	binding                                                        clientstate.ApplicationPublicationBinding
	control                                                        *clientcontrol.Client
	authority                                                      *clientauthority.Client
	response                                                       authorityv1.MachinePublicationSession
	url                                                            controlv1.PublicURL
	public                                                         ed25519.PublicKey
	nonce                                                          string
	lose                                                           string
	revoked                                                        bool
	exchanges, refreshes, tokens, allocations, creations, cleanups int
	verifySource                                                   func(string, string, string, string)
}

func newDurableApplicationHTTP(t *testing.T, configure ...func(*clientstate.ApplicationPublicationBinding)) *durableApplicationHTTP {
	t.Helper()
	f := &durableApplicationHTTP{t: t, response: applicationSessionResponse()}
	var err error
	f.root, err = filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f.response.Publisher.Kind, f.response.Publisher.PublicUrlId = authorityv1.Namespace, nil
	f.response.Publisher.Namespace, f.response.Publisher.DomainId = new("apps.example"), new("dom_0123456789ABCDEFGHIJKL")
	f.binding = clientstate.ApplicationPublicationBinding{ServerURL: "https://control.example", InvocationID: "ivk_0123456789ABCDEFGHIJKL", OwnerHash: strings.Repeat("1", 64), PID: os.Getpid(), Target: "http://127.0.0.1:3000", ConfigurationDigest: strings.Repeat("2", 64), RequestDigest: strings.Repeat("3", 64), Namespace: "apps.example", SourceKind: "oidc", SourceMachineID: "mci_0123456789ABCDEFGHIJKL"}
	for _, change := range configure {
		change(&f.binding)
	}
	f.url = controlv1.PublicURL{Id: "url_0123456789ABCDEFGHIJKL", TeamId: f.response.Publisher.TeamId, DomainId: *f.response.Publisher.DomainId, CanonicalHostname: strings.Repeat("a", 26) + ".apps.example", Target: f.binding.Target, Ephemeral: true, ServiceProtocol: controlv1.Http, Purpose: controlv1.App, LifecycleState: controlv1.Enabled, AccessMode: controlv1.Restricted}
	client := &http.Client{Transport: publicationHTTP(f.roundTrip)}
	f.control, err = clientcontrol.New(f.binding.ServerURL, client, "")
	if err != nil {
		t.Fatal(err)
	}
	f.authority, err = clientauthority.New(f.binding.ServerURL, client, "")
	if err != nil {
		t.Fatal(err)
	}
	f.reopen()
	t.Cleanup(func() { _ = f.owner.Close() })
	return f
}

func (f *durableApplicationHTTP) reopen() {
	f.t.Helper()
	if f.owner != nil {
		if err := f.owner.Close(); err != nil {
			f.t.Fatal(err)
		}
	}
	var err error
	f.owner, err = clientstate.OpenApplicationPublications(f.root, f.root, f.root, 0)
	if err != nil {
		f.t.Fatal(err)
	}
	f.entry, err = f.owner.Publication(f.t.Context(), f.binding, time.Now().Add(time.Minute))
	if err != nil {
		f.t.Fatal(err)
	}
}

func (f *durableApplicationHTTP) snapshot() clientstate.ApplicationPublicationRecord {
	f.t.Helper()
	r, err := f.entry.Snapshot(f.t.Context())
	if err != nil {
		f.t.Fatal(err)
	}
	return r
}

func (f *durableApplicationHTTP) open(proof string) *ApplicationSession {
	f.t.Helper()
	s, err := OpenApplicationSession(f.t.Context(), f.control, f.authority, f.entry, proof)
	if err != nil {
		f.t.Fatal(err)
	}
	return s
}

func (f *durableApplicationHTTP) roundTrip(r *http.Request) (*http.Response, error) {
	t := f.t
	if r.URL.Scheme+"://"+r.URL.Host != f.binding.ServerURL {
		t.Fatal("ambient server used")
	}
	if _, bounded := r.Context().Deadline(); !bounded {
		t.Fatal("unbounded HTTP request")
	}
	record, err := f.entry.Snapshot(r.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(record.NativeKey)
	decode := func(value any) {
		t.Helper()
		defer r.Body.Close()
		if err := json.NewDecoder(r.Body).Decode(value); err != nil {
			t.Fatal(err)
		}
	}
	reply := func(status int, body any) (*http.Response, error) {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		if f.lose == r.URL.Path {
			f.lose = ""
			return nil, lostApplicationReply
		}
		if status == http.StatusNoContent {
			return &http.Response{StatusCode: status, Body: http.NoBody}, nil
		}
		return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(encoded))}, nil
	}
	path := r.URL.Path
	if strings.HasPrefix(path, "/v1/machine-publication-sessions/") && r.Header.Get("Authorization") != "" {
		t.Fatal("source/cleanup request used bearer credentials")
	}
	switch path {
	case "/v1/machine-publication-sessions/exchange":
		f.exchanges++
		var body authorityv1.MachinePublicationExchange
		decode(&body)
		public, _ := base64.RawURLEncoding.Strict().DecodeString(body.PublicKey)
		sig, _ := base64.RawURLEncoding.Strict().DecodeString(body.Signature)
		if record.Phase != clientstate.ApplicationExchangePending && record.Phase != clientstate.ApplicationRefreshPending || body.MachineId != f.binding.SourceMachineID || body.Resource != "" || body.Namespace != f.binding.Namespace || len(public) != ed25519.PublicKeySize || !ed25519.Verify(public, machineproof.PublicationPossession("", body.Namespace, "exchange", body.PublicKey, body.Nonce, sha256.Sum256([]byte(body.Assertion))), sig) {
			t.Fatal("exchange preceded synced exact intent or lost possession")
		}
		if !bytes.Equal(public, ed25519.PrivateKey(record.NativeKey).Public().(ed25519.PublicKey)) || body.Nonce != record.Nonce {
			t.Fatal("exchange did not use durable original key/nonce")
		}
		if f.nonce == "" {
			f.nonce, f.public = body.Nonce, append(ed25519.PublicKey(nil), public...)
		}
		if f.nonce != body.Nonce || !bytes.Equal(f.public, public) {
			t.Fatal("recovery replaced original session tuple")
		}
		if f.verifySource != nil {
			f.verifySource(body.Assertion, "exchange", body.Nonce, f.binding.ServerURL+path)
		}
		if f.revoked || !time.Now().Before(f.response.IdentityExpiresAt) {
			return reply(403, map[string]string{"code": "forbidden"})
		}
		return reply(200, f.response)
	case "/v1/publisher-token":
		f.tokens++
		if f.revoked {
			t.Fatal("cleanup or denied recovery acquired a token")
		}
		var body authorityv1.PublisherTokenRequest
		decode(&body)
		if body.ClientId != f.response.Publisher.ClientId || body.GrantId != f.response.Publisher.GrantId || record.Publisher == nil {
			t.Fatal("token preceded accepted session checkpoint")
		}
		if _, err := publisherproof.Verify(body.ClientAssertion, body.ClientId, f.response.Publisher.KeyId, body.GrantId, f.binding.ServerURL+path, f.public, time.Now()); err != nil {
			t.Fatal(err)
		}
		return reply(200, authorityv1.PublisherTokenResponse{AccessToken: "private-serving-token", ExpiresIn: 60, TokenType: "Bearer", GrantId: body.GrantId})
	case "/v1/publisher/public-urls":
		f.allocations++
		var body controlv1.AllocateEphemeralPublicURLRequest
		decode(&body)
		if record.Phase != clientstate.ApplicationAllocationPending || record.Publisher == nil || record.Publisher.GrantId != f.response.Publisher.GrantId || body.InvocationId != f.binding.InvocationID || body.Target != f.binding.Target || r.Header.Get("Authorization") != "Bearer private-serving-token" {
			t.Fatal("allocation escaped durable publisher/grant/invocation intent")
		}
		// control's idempotency tuple is publisher + grant + invocation.
		if f.creations == 0 {
			f.creations++
		}
		return reply(200, f.url)
	case "/v1/machine-publication-sessions/" + f.response.Id + "/refresh":
		f.refreshes++
		var body authorityv1.MachinePublicationRefresh
		decode(&body)
		public := base64.RawURLEncoding.EncodeToString(f.public)
		sig, _ := base64.RawURLEncoding.Strict().DecodeString(body.Signature)
		if record.Phase != clientstate.ApplicationRefreshPending || !ed25519.Verify(f.public, machineproof.PublicationPossession("", f.binding.Namespace, "refresh", public, f.response.Id, sha256.Sum256([]byte(body.Assertion))), sig) {
			t.Fatal("refresh lost synced old fence or original possession")
		}
		if f.verifySource != nil {
			f.verifySource(body.Assertion, "refresh", f.response.Id, f.binding.ServerURL+path)
		}
		if f.revoked {
			return reply(403, map[string]string{"code": "forbidden"})
		}
		return reply(200, f.response)
	case "/v1/machine-publication-sessions/" + f.response.Id + "/cleanup":
		f.cleanups++
		var body authorityv1.MachinePublicationCleanup
		decode(&body)
		if record.Phase != clientstate.ApplicationCleanupPending || body.InvocationId != f.binding.InvocationID {
			t.Fatal("cleanup preceded durable intent")
		}
		if _, err := publisherproof.Verify(body.Assertion, f.response.Publisher.ClientId, f.response.Publisher.KeyId, machineproof.PublicationCleanup(f.response.Id, body.InvocationId), f.binding.ServerURL+path, f.public, time.Now()); err != nil {
			t.Fatal(err)
		}
		return reply(204, nil)
	default:
		t.Fatalf("unexpected HTTP operation: %s", path)
		return nil, errors.New("unexpected HTTP operation")
	}
}

func TestApplicationSessionDurableLostExchangeAndAllocation(t *testing.T) {
	f := newDurableApplicationHTTP(t)
	original := f.snapshot()
	defer clear(original.NativeKey)
	f.lose = "/v1/machine-publication-sessions/exchange"
	if s, err := OpenApplicationSession(t.Context(), f.control, f.authority, f.entry, "private-first-proof"); s != nil || !errors.Is(err, lostApplicationReply) {
		t.Fatal("lost exchange was acknowledged", err)
	}
	f.reopen()
	s := f.open("private-fresh-proof")
	accepted := f.snapshot()
	if !bytes.Equal(original.NativeKey, accepted.NativeKey) || original.Nonce != accepted.Nonce || accepted.SessionID != f.response.Id || accepted.Phase != clientstate.ApplicationSessionAccepted {
		t.Fatal("reopened exchange replaced its original tuple")
	}
	clear(accepted.NativeKey)
	f.lose = "/v1/publisher/public-urls"
	body := controlv1.AllocateEphemeralPublicURLRequest{InvocationId: f.binding.InvocationID, Target: f.binding.Target}
	if _, err := s.Allocate(t.Context(), body); !errors.Is(err, lostApplicationReply) {
		t.Fatal("lost allocation was acknowledged", err)
	}
	f.reopen()
	s = f.open("private-third-proof")
	u, err := s.Allocate(t.Context(), body)
	if err != nil || u.Id != f.url.Id || f.creations != 1 || f.allocations != 2 || f.exchanges != 2 {
		t.Fatal("recovery replaced its allocation", err)
	}
	final := f.snapshot()
	defer clear(final.NativeKey)
	if final.Phase != clientstate.ApplicationURLAccepted || final.PublicURL == nil || final.PublicURL.Id != u.Id || !bytes.Equal(original.NativeKey, final.NativeKey) {
		t.Fatal("URL acknowledgment preceded its durable checkpoint")
	}
	_ = filepath.WalkDir(f.root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			t.Fatal(err)
		}
		if !entry.IsDir() && strings.HasSuffix(path, ".json") {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			for _, secret := range []string{"private-first-proof", "private-fresh-proof", "private-third-proof", "private-serving-token", f.response.AccessToken} {
				if bytes.Contains(data, []byte(secret)) {
					t.Fatal("transient credential persisted")
				}
			}
		}
		return nil
	})
}

func TestApplicationSessionDurableLostRefreshRecoversSameSession(t *testing.T) {
	for _, reopen := range []bool{false, true} {
		t.Run(map[bool]string{false: "same-object", true: "reopened"}[reopen], func(t *testing.T) {
			f := newDurableApplicationHTTP(t)
			s := f.open("initial-proof")
			body := controlv1.AllocateEphemeralPublicURLRequest{InvocationId: f.binding.InvocationID, Target: f.binding.Target}
			if _, err := s.Allocate(t.Context(), body); err != nil {
				t.Fatal(err)
			}
			before := f.snapshot()
			defer clear(before.NativeKey)
			f.response.IdentityExpiresAt = f.response.IdentityExpiresAt.Add(time.Minute)
			f.lose = "/v1/machine-publication-sessions/" + f.response.Id + "/refresh"
			if err := s.Refresh(t.Context(), "refresh-proof"); !errors.Is(err, lostApplicationReply) {
				t.Fatal(err)
			}
			pending := f.snapshot()
			clear(pending.NativeKey)
			if pending.Phase != clientstate.ApplicationRefreshPending || !pending.IdentityExpiresAt.Equal(before.IdentityExpiresAt) || !s.fence.Load().deadline.Equal(before.IdentityExpiresAt) {
				t.Fatal("lost refresh advanced serving authority")
			}
			if reopen {
				f.reopen()
				s = f.open("recovery-proof")
			} else if err := s.Refresh(t.Context(), "recovery-proof"); err != nil {
				t.Fatal(err)
			}
			after := f.snapshot()
			defer clear(after.NativeKey)
			if after.Phase != clientstate.ApplicationURLAccepted || after.PublicURL.Id != before.PublicURL.Id || after.SessionID != before.SessionID || after.Nonce != before.Nonce || !bytes.Equal(after.NativeKey, before.NativeKey) || f.exchanges != 2 || f.refreshes != 1 || f.allocations != 1 || f.cleanups != 0 {
				t.Fatal("uncertain refresh replaced or deleted accepted publication")
			}
		})
	}
}

func TestApplicationSessionDurableDenialCannotRecoverButCleanupRetries(t *testing.T) {
	f := newDurableApplicationHTTP(t)
	s := f.open("initial-proof")
	if _, err := s.Allocate(t.Context(), controlv1.AllocateEphemeralPublicURLRequest{InvocationId: f.binding.InvocationID, Target: f.binding.Target}); err != nil {
		t.Fatal(err)
	}
	f.revoked = true
	if err := s.Refresh(t.Context(), "fresh-proof"); err == nil {
		t.Fatal("revocation accepted")
	}
	if err := s.CheckServing(); err == nil {
		t.Fatal("known denial left admissions open")
	}
	f.reopen()
	if _, err := OpenApplicationSession(t.Context(), f.control, f.authority, f.entry, "replacement-proof"); !errors.Is(err, ErrScope) || f.exchanges != 1 {
		t.Fatal("known denial opened a replacement session", err)
	}
	f.lose = "/v1/machine-publication-sessions/" + f.response.Id + "/cleanup"
	if err := CleanupApplicationPublication(t.Context(), f.entry, f.authority); !errors.Is(err, lostApplicationReply) {
		t.Fatal("failed cleanup was cached", err)
	}
	f.reopen()
	if err := CleanupApplicationPublication(t.Context(), f.entry, f.authority); err != nil {
		t.Fatal(err)
	}
	final := f.snapshot()
	if final.Phase != clientstate.ApplicationCleanupDone || len(final.NativeKey) != 0 || f.cleanups != 2 || f.tokens != 1 || f.refreshes != 1 || f.exchanges != 1 {
		t.Fatal("cleanup reacquired authority or discarded failed obligation")
	}
}

func TestApplicationSessionDurableKnownExpiryNeverExchangesReplacement(t *testing.T) {
	f := newDurableApplicationHTTP(t)
	record := f.snapshot()
	defer clear(record.NativeKey)
	record.Phase, record.Publisher, record.SessionID = clientstate.ApplicationSessionAccepted, &f.response.Publisher, f.response.Id
	record.IdentityExpiresAt, record.AccessExpiresAt, record.RenewAfter = time.Now().Add(-time.Second), time.Now().Add(-2*time.Second), time.Now().Add(-3*time.Second)
	if err := f.entry.Checkpoint(t.Context(), record); err != nil {
		t.Fatal(err)
	}
	f.reopen()
	if _, err := OpenApplicationSession(t.Context(), f.control, f.authority, f.entry, "fresh-but-not-replacement-proof"); !errors.Is(err, ErrScope) {
		t.Fatal("known expired record revived", err)
	}
	denied := f.snapshot()
	defer clear(denied.NativeKey)
	if denied.Phase != clientstate.ApplicationDenied || f.exchanges != 0 || f.refreshes != 0 || f.tokens != 0 || f.allocations != 0 || denied.Nonce != record.Nonce || !bytes.Equal(denied.NativeKey, record.NativeKey) {
		t.Fatal("known expiry replaced or discarded the original session")
	}
}

func TestApplicationSessionDurableExpiredUncertainOwnerCannotExchangeAgain(t *testing.T) {
	f := newDurableApplicationHTTP(t)
	f.lose = "/v1/machine-publication-sessions/exchange"
	if _, err := OpenApplicationSession(t.Context(), f.control, f.authority, f.entry, "first-proof"); !errors.Is(err, lostApplicationReply) {
		t.Fatal(err)
	}
	record := f.snapshot()
	defer clear(record.NativeKey)
	// model a native process that was down beyond the SDK owner's saved lease.
	record.OwnerExpiresAt = time.Now().Add(-time.Second)
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(data)
	var recordPath string
	if err := filepath.WalkDir(f.root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if strings.HasPrefix(entry.Name(), "publication-") && strings.HasSuffix(entry.Name(), ".json") {
			recordPath = path
		}
		return nil
	}); err != nil || recordPath == "" {
		t.Fatal("missing private checkpoint", err)
	}
	if err := os.WriteFile(recordPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	f.reopen()
	if _, err := OpenApplicationSession(t.Context(), f.control, f.authority, f.entry, "fresh-proof"); !errors.Is(err, ErrScope) || f.exchanges != 1 {
		t.Fatal("expired uncertain owner obtained replacement authority", err)
	}
	if err := f.entry.RenewOwner(t.Context(), time.Now().Add(time.Minute)); err == nil {
		t.Fatal("expired owner lease was revived")
	}
	if err := CleanupApplicationPublication(t.Context(), f.entry, f.authority); err != nil {
		t.Fatal("expired intent could not complete original-key cleanup", err)
	}
}
