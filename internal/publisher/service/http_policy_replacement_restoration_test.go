package service

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	servicestream "github.com/tnldotdev/tnl/internal/publisher/service/stream"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestServiceHTTPPolicyRestorationCurrentPermissionKeepsSamePublisherSession(t *testing.T) {
	canceled := make(chan struct{})
	f := newPendingHTTPFixture(t, 1, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/held" {
			_, _ = io.WriteString(w, "prefix")
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			close(canceled)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	update := f.source.update
	update.Anonymous = false
	apply := func() {
		t.Helper()
		update.View.VisitorPolicyRevision++
		now := time.Now()
		update.View.ObservedAt, update.View.ValidUntil = now, now.Add(visitortoken.PolicyLifetime)
		if err := f.source.prepared.policy.Apply(f.source.prepared.policy.Begin(), update); err != nil {
			t.Fatal(err)
		}
	}
	apply()
	slot := f.current[0]
	ref, publisher, relay := slot.claimed.ref, slot.claimed.session, slot.relay
	initial := sourcePolicyPermission(t, f)
	first := newCompositionHTTPClient(t, f, 0, true)
	response := first.request(t, http.MethodGet, "/held", "", initial.Reveal(), "")
	if response.StatusCode != http.StatusOK {
		t.Fatal("current permission did not enter its real HTTP application")
	}
	prefix := make([]byte, len("prefix"))
	if _, err := io.ReadFull(response.Body, prefix); err != nil || string(prefix) != "prefix" {
		t.Fatal("admitted request did not stream its prefix", string(prefix), err)
	}
	assertHTTPAdmissionCharges(t, first.visitor.admission, 0, 0, 1)
	apply()
	if _, err := io.ReadAll(response.Body); err == nil {
		t.Fatal("policy revision left the old streaming permission usable")
	}
	_ = response.Body.Close()
	claimedAwait(t, canceled)
	first.visitor.close()
	first.visitor.join(t)
	if publisher.Err() != nil || relay.Err() != nil || f.current[0] != slot || slot.claimed.ref != ref {
		t.Fatal("visitor revocation stopped or replaced its publisher/relay session")
	}
	select {
	case <-slot.served:
		t.Fatal("visitor revocation returned the production claimed serving owner")
	default:
	}
	// these are new visitor streams over the exact original publisher session,
	// not the other relay slot or a newly connected publisher.
	denied := newCompositionHTTPClient(t, f, 0, true)
	pendingHTTPResponse(t, denied.request(t, http.MethodGet, "/", "", initial.Reveal(), ""), http.StatusForbidden)
	denied.visitor.close()
	denied.visitor.join(t)
	fresh := newCompositionHTTPClient(t, f, 0, true)
	pendingHTTPResponse(t, fresh.request(t, http.MethodGet, "/current", "", sourcePolicyPermission(t, f).Reveal(), ""), http.StatusNoContent)
	_ = first.visitor.admission.retire()
	assertHTTPAdmissionCharges(t, fresh.visitor.admission, 0, 0, 1)
	if f.calls.Load() != 2 || f.capacity.Load() != 2 || len(f.slots) != 2 ||
		fresh.visitor.header.PublisherConnectionID != ref.PublisherConnectionID ||
		fresh.visitor.header.ConnectionAssignmentRevision != ref.ConnectionAssignmentRevision ||
		publisher.Err() != nil || relay.Err() != nil {
		t.Fatal("fresh permission changed the actual publisher session or repeated denied application work")
	}
}

func TestServiceHTTPPolicyRestorationStaleClaimCleanupKeepsReplacementLifetime(t *testing.T) {
	canceled := make(chan string, 2)
	f := newPendingHTTPFixture(t, 2, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/old" || r.URL.Path == "/replacement" {
			_, _ = io.WriteString(w, "prefix")
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			canceled <- r.URL.Path
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	first := newCompositionHTTPClient(t, f, 0, true)
	oldResponse := first.request(t, http.MethodGet, "/old", "", "", "")
	defer oldResponse.Body.Close()
	if oldResponse.StatusCode != http.StatusOK {
		t.Fatal("old claim did not enter its visitor lifetime")
	}
	old := f.current[0]
	released := make(chan struct{})
	release := sync.OnceFunc(func() { close(released) })
	defer release()
	first.visitor.wire.holdCleanup(released)
	next := f.source.bound.connections
	id, err := opaqueid.New(opaqueid.PublisherConnectionPrefix)
	if err != nil {
		t.Fatal(err)
	}
	next[0].PublisherConnectionId = id
	next[0].ConnectionAssignmentRevision++
	state := controlv1.ServiceRunState{ServiceId: f.source.prepared.Preparation.ServiceId,
		ServiceRunId: f.source.prepared.Preparation.ServiceRunId, RunNumber: f.source.prepared.Preparation.RunNumber,
		State: "ready", PublisherExpiresAt: time.Now().Add(time.Minute),
		PublisherConnections: []controlv1.ConnectionAssignment{next[0], next[1]}}
	if err := f.source.bound.ApplyHeartbeat(state); err != nil {
		t.Fatal(err)
	}
	// the old request already holds capacity. join its relay's reply cleanup
	// before canceling the publisher, but keep the old visitor cleanup held.
	old.stopCapacity(t)
	old.cancel()
	if path := claimedAwait(t, canceled); path != "/old" {
		t.Fatal("replacement did not cancel the old visitor lifetime", path)
	}
	claimedAwait(t, first.visitor.wire.entered)
	f.current[0] = f.connect(t, 0)
	replacement := f.current[0]
	current := newCompositionHTTPClient(t, f, 0, true)
	response := current.request(t, http.MethodGet, "/replacement", "", "", "")
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || current.visitor.header.PublisherConnectionID == old.claimed.ref.PublisherConnectionID {
		t.Fatal("replacement did not acquire its distinct current claim")
	}
	f.source.bound.mu.Lock()
	final, active := f.source.bound.reservedStreams, len(f.source.bound.active)
	f.source.bound.mu.Unlock()
	if final != 2 || active != 2 {
		t.Fatal("replacement borrowed the old claim's unjoined capacity", final, active)
	}
	release()
	old.stop(t)
	// repeat both obsolete cleanup paths only after the replacement is live.
	_ = old.claimed.Close()
	_ = first.visitor.admission.retire()
	assertHTTPAdmissionCharges(t, current.visitor.admission, 0, 0, 1)
	if !f.source.bound.current(replacement.claimed.ref) || replacement.claimed.session.Err() != nil ||
		replacement.relay.Err() != nil {
		t.Fatal("stale claim cleanup retired the current replacement")
	}
	select {
	case path := <-canceled:
		t.Fatal("old cleanup canceled the replacement's active HTTP lifetime", path)
	default:
	}
	pendingHTTPResponse(t, current.request(t, http.MethodGet, "/after-old-cleanup", "", "", ""), http.StatusNoContent)
	if f.calls.Load() != 3 || f.capacity.Load() != 2 {
		t.Fatal("old cleanup lost replacement capacity or replayed application work")
	}
	// current owner shutdown, unlike obsolete cleanup, must cancel this lifetime.
	f.source.bound.Invalidate()
	if path := claimedAwait(t, canceled); path != "/replacement" {
		t.Fatal("current owner shutdown left its replacement lifetime alive", path)
	}
	current.visitor.close()
	current.visitor.join(t)
	assertHTTPAdmissionCharges(t, current.visitor.admission, 0, 0, 0)
}

func TestServiceHTTPPolicyRestorationMissingOwnerFactsFailBeforeApplication(t *testing.T) {
	var valid HTTP
	_, _, _, _ = serviceHTTPConfiguredFixture(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("missing HTTP owner facts reached the application")
	}), false, true, func(frontend *HTTP) { valid = *frontend })
	cases := []struct {
		name   string
		change func(*HTTP)
	}{
		{"zero-owner", func(f *HTTP) { *f = HTTP{} }},
		{"capacity-owner", func(f *HTTP) { f.ReserveCapacity = nil }},
		{"policy-owner", func(f *HTTP) { f.Policy = nil }},
		{"subject", func(f *HTTP) { f.Subject.ID = "" }},
		{"run", func(f *HTTP) { f.RunID = "" }},
		{"run-number", func(f *HTTP) { f.Number = 0 }},
		{"service-binding", func(f *HTTP) { f.Header.ServiceID = "svc_other" }},
		{"public-admission", func(f *HTTP) { f.Header.PublicService = nil }},
		{"publisher-connection", func(f *HTTP) { f.Header.PublisherConnectionID = "" }},
		{"assignment", func(f *HTTP) { f.Header.ConnectionAssignmentRevision = 0 }},
		{"endpoint-port", func(f *HTTP) { f.Port = 0 }},
		{"source", func(f *HTTP) { f.Source = netip.AddrPort{} }},
		{"source-port", func(f *HTTP) { f.Source = netip.AddrPortFrom(f.Source.Addr(), 0) }},
		{"source-binding", func(f *HTTP) { f.Source = netip.MustParseAddrPort("198.51.100.1:1234") }},
		{"hostname-binding", func(f *HTTP) { f.Hostname = "other.example.test" }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			frontend := valid
			test.change(&frontend)
			if frontend.ReserveCapacity != nil {
				frontend.ReserveCapacity = func(context.Context) error {
					t.Error("missing owner facts entered ingress capacity")
					return nil
				}
			}
			visitor, server := net.Pipe()
			defer visitor.Close()
			defer server.Close()
			_ = server.SetDeadline(time.Now().Add(5 * time.Second))
			secured := tls.Server(server, &tls.Config{})
			err := frontend.Forward(t.Context(), secured, servicestream.HTTPTarget{Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Error("incomplete HTTP owner reached its target")
			})})
			if !errors.Is(err, servicestream.ErrEndpoint) {
				t.Fatal("incomplete HTTP owner did not fail at its required-facts boundary", err)
			}
		})
	}
}

func TestServiceHTTPPolicyRestorationAbsentPermissionDeadlineIsDenied(t *testing.T) {
	f := newPendingHTTPFixture(t, 1, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	update := f.source.update
	update.Anonymous = false
	update.View.VisitorPolicyRevision++
	now := time.Now()
	update.View.ObservedAt, update.View.ValidUntil = now, now.Add(visitortoken.PolicyLifetime)
	if err := f.source.prepared.policy.Apply(f.source.prepared.policy.Begin(), update); err != nil {
		t.Fatal(err)
	}
	valid := sourcePolicyPermission(t, f)
	view, _, _ := f.source.prepared.policy.Current()
	verified, err := visitortoken.VerifyBearer(valid, view, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	facts := verified.Facts()
	facts.ExpiresAt = time.Time{}
	if token, err := visitortoken.Sign(view.Issuer, "lifecycle", key, facts, time.Now()); token != "" || !errors.Is(err, visitortoken.ErrToken) {
		t.Fatal("current signer accepted an unbounded permission", err)
	}
	original, err := jose.ParseSigned(valid.Reveal(), []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := original.Verify(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	client := newCompositionHTTPClient(t, f, 0, true)
	for _, absent := range []bool{true, false} {
		var claims map[string]json.RawMessage
		if err := json.Unmarshal(payload, &claims); err != nil {
			t.Fatal(err)
		}
		if absent {
			delete(claims, "exp")
		} else {
			claims["exp"] = json.RawMessage("0")
		}
		body, err := json.Marshal(claims)
		if err != nil {
			t.Fatal(err)
		}
		// use the existing fixture's exact current key and claims. only the
		// required deadline is absent/zero; this is not an invalid signature.
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: key},
			(&jose.SignerOptions{}).WithType(visitortoken.Type).WithHeader("kid", "lifecycle"))
		if err != nil {
			t.Fatal(err)
		}
		signed, err := signer.Sign(body)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := signed.CompactSerialize()
		if err != nil {
			t.Fatal(err)
		}
		if permission, err := visitortoken.VerifyBearer(visitortoken.Token(raw), view, time.Now()); permission.Valid() || !errors.Is(err, visitortoken.ErrToken) {
			t.Fatal("absent/zero deadline produced verified permission", absent, err)
		}
		pendingHTTPResponse(t, client.request(t, http.MethodGet, "/", "", raw, ""), http.StatusForbidden)
	}
	if f.calls.Load() != 0 || f.capacity.Load() != 0 {
		t.Fatal("unbounded permission entered the app or acquired final connection capacity")
	}
	pendingHTTPResponse(t, client.request(t, http.MethodGet, "/bounded", "", valid.Reveal(), ""), http.StatusNoContent)
	if f.calls.Load() != 1 || f.capacity.Load() != 1 {
		t.Fatal("missing-deadline fixture rejected its genuine bounded permission")
	}
}
