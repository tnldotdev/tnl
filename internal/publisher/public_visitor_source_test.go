package publisher

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestVisitorSourceReplayWindowPreservesEveryReorderAndRejectsOldSequences(t *testing.T) {
	for _, shift := range []uint64{1, 63, 64, 65, 127, 128, 191, 192, 255, 256, 257, 1024} {
		var window visitorSourceHistory
		if err := window.consume(256); err != nil {
			t.Fatal(err)
		}
		for sequence := uint64(1); sequence < 256; sequence += 2 {
			if err := window.consume(sequence); err != nil {
				t.Fatal("reordered sequence rejected", shift, sequence, err)
			}
		}
		if err := window.consume(256 + shift); err != nil {
			t.Fatal(err)
		}
		for sequence := uint64(1); sequence < 256+shift; sequence++ {
			wantReplay := sequence <= shift || sequence == 256 || sequence < 256 && sequence%2 == 1
			err := window.consume(sequence)
			if errors.Is(err, errVisitorSourceReplay) != wantReplay || err != nil && !errors.Is(err, errVisitorSourceReplay) {
				t.Fatal("window lost consumed evidence or bounded reordering", shift, sequence, err)
			}
		}
		if err := window.consume(0); !errors.Is(err, errVisitorSourceReplay) {
			t.Fatal("zero sequence was consumed", err)
		}
	}
}

func sourceMetadataFixture(t *testing.T, route *PublicURLServer) (tunnelv1.VisitorStreamHeader, proxyproto.Header) {
	t.Helper()
	header := testPublicStreamHeader(route, tunnelv1.VisitorStreamHeader{})
	wire, err := encodeTestPublicMetadata(route, header, proxyproto.Header{Source: netip.MustParseAddrPort("192.0.2.1:1234"), Destination: netip.MustParseAddrPort("127.0.0.1:443")})
	if err != nil {
		t.Fatal(err)
	}
	metadata, _, err := proxyproto.Decode(bytes.NewReader(wire))
	if err != nil {
		t.Fatal(err)
	}
	return header, metadata
}

func TestVisitorSourceReplayHasOneRunOwnerAndImmutableRetirement(t *testing.T) {
	route, err := newTestPublicURLServer(t, PublicURLServerConfig{Hostname: "route.example", Handler: http.NotFoundHandler()})
	if err != nil {
		t.Fatal(err)
	}
	defer route.Close()
	header, metadata := sourceMetadataFixture(t, route)
	var accepted atomic.Int32
	var workers sync.WaitGroup
	for range 100 {
		workers.Go(func() {
			if err := route.authenticateVisitorSource(header, metadata); err == nil {
				accepted.Add(1)
			} else if !errors.Is(err, errVisitorSourceReplay) {
				t.Error(err)
			}
		})
	}
	workers.Wait()
	if accepted.Load() != 1 || len(route.sourceHistory) != 1 || len(route.sourceExpirations) != 1 {
		t.Fatal("concurrent relays consumed one proof more than once or multiplied its history", accepted.Load())
	}
	// alternate JSON encodings of the same signed facts share the authenticated
	// authority MAC, not a raw-wire cache key.
	metadata.VisitorSourceProof = " \n" + metadata.VisitorSourceProof + "\n"
	if err := route.authenticateVisitorSource(header, metadata); !errors.Is(err, errVisitorSourceReplay) {
		t.Fatal("wire alias reopened consumed source evidence", err)
	}
	proof, err := tunnelv1.ReadVisitorSourceProof([]byte(metadata.VisitorSourceProof))
	if err != nil {
		t.Fatal(err)
	}
	until := proof.Authority.ValidUntil
	// a renewed authority has its own history; it must not retire older evidence
	// that is still valid or extend that evidence's immutable deadline.
	renewed := proof
	renewed.Authority.MAC = bytes.Repeat([]byte{2}, 32)
	renewed.Authority.ValidUntil = until + 10
	if err := route.consumeVisitorSource(renewed, time.Unix(until-1, 0)); err != nil {
		t.Fatal(err)
	}
	if len(route.sourceHistory) != 2 {
		t.Fatal("new authority retired still-current history")
	}
	if err := route.consumeVisitorSource(proof, time.Unix(until-1, 0)); !errors.Is(err, errVisitorSourceReplay) {
		t.Fatal("renewal cleared an old replay fence", err)
	}
	renewed.Sequence++
	if err := route.consumeVisitorSource(renewed, time.Unix(until, 0)); err != nil || len(route.sourceHistory) != 1 {
		t.Fatal("expired evidence was not retired at its original deadline", err)
	}
	if err := route.consumeVisitorSource(proof, time.Unix(until, 0)); !errors.Is(err, visitortoken.ErrVisitorSource) {
		t.Fatal("retired authority became usable again", err)
	}
}

func TestVisitorSourceCannotSupplyMissingOrDifferentServerRunIdentity(t *testing.T) {
	route, err := newTestPublicURLServer(t, PublicURLServerConfig{Hostname: "route.example", Handler: http.NotFoundHandler()})
	if err != nil {
		t.Fatal(err)
	}
	defer route.Close()
	header, metadata := sourceMetadataFixture(t, route)
	for _, mutate := range []func(*PublishRunIdentity){
		func(run *PublishRunIdentity) { *run = PublishRunIdentity{} },
		func(run *PublishRunIdentity) { run.PublicURLID = "" },
		func(run *PublishRunIdentity) { run.PublishRunID = "" },
		func(run *PublishRunIdentity) { run.Number = 0 },
		func(run *PublishRunIdentity) { run.PublicURLID = "different-url" },
		func(run *PublishRunIdentity) { run.PublishRunID = "different-run" },
		func(run *PublishRunIdentity) { run.Number++ },
	} {
		owner := &PublicURLServer{policy: route.policy, visitorSourceKey: route.visitorSourceKey, run: route.run}
		mutate(&owner.run)
		if err := owner.authenticateVisitorSource(header, metadata); !errors.Is(err, visitortoken.ErrVisitorSource) {
			t.Fatal("stream evidence supplied or replaced the server's run identity", err)
		}
		if len(owner.sourceHistory) != 0 {
			t.Fatal("wrong run identity consumed source evidence")
		}
	}
}

func TestVisitorSourceCannotBeRewrittenOrReplayAcrossRelayConnectionsAfterRelease(t *testing.T) {
	var calls atomic.Int32
	f := newPublicCapacityFixture(t, 1, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); w.WriteHeader(204) }))
	header, metadata := sourceMetadataFixture(t, f.route)
	open := func(index int, metadata proxyproto.Header) (*http.Response, error) {
		ref := f.refs[index]
		header.ProtocolVersion, header.Kind = tunnelv1.Version, tunnelv1.VisitorStream
		header.PublisherConnectionID, header.ConnectionAssignmentRevision = ref.PublisherConnectionID, ref.ConnectionAssignmentRevision
		stream, err := f.relays[index].OpenVisitorStream(f.ctx, header)
		if err != nil {
			return nil, err
		}
		t.Cleanup(func() { _ = stream.Close() })
		wire, err := proxyproto.Encode(metadata)
		if err != nil {
			t.Fatal(err)
		}
		return f.request(&publicCapacityStream{Stream: stream, metadata: wire}, "/")
	}
	// authentication failures do not consume a valid proof or reach HTTP work.
	for _, mutate := range []func(*proxyproto.Header){
		func(m *proxyproto.Header) { m.VisitorSourceProof = "" },
		func(m *proxyproto.Header) { m.Source = netip.MustParseAddrPort("198.51.100.1:1234") },
		func(m *proxyproto.Header) { m.Destination = netip.MustParseAddrPort("127.0.0.2:443") },
	} {
		changed := metadata
		mutate(&changed)
		if response, err := open(1, changed); err == nil {
			_ = response.Body.Close()
			t.Fatal("unsigned or rewritten metadata reached HTTP")
		}
		f.wait(0, 0)
	}
	response, err := open(0, metadata)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	f.wait(0, 0)
	for _, index := range []int{0, 1} {
		if response, err := open(index, metadata); err == nil {
			_ = response.Body.Close()
			t.Fatal("capacity release reopened consumed evidence through a relay", index)
		}
		f.wait(0, 0)
	}
	if calls.Load() != 1 {
		t.Fatal("invalid source or replay reached the application", calls.Load())
	}
}

func TestVisitorSourcePolicyChangeClosesPermissionButRetainsReplayAndStaleReleaseFence(t *testing.T) {
	policy, update, token := httpPermissionScopeFixture(t, visitorscope.Scope{Kind: visitorscope.PublicURL, ID: certificateTestPublicURLID}, "route.example", 443, false)
	view, _, _ := policy.Current()
	permission, err := visitortoken.VerifyBearer(token, view, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	f := newPublicCapacityFixture(t, 1, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path == "/held" {
			_, _ = io.WriteString(w, "prefix")
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			return
		}
		w.WriteHeader(204)
	}), func(c *PublicURLServerConfig) { c.AccessMode, c.VisitorPolicy = "restricted", policy })
	stream, err := f.open(0, false)
	if err != nil {
		t.Fatal(err)
	}
	metadata, _, err := proxyproto.Decode(bytes.NewReader(f.metadataFor(stream)))
	if err != nil {
		t.Fatal(err)
	}
	proof, err := tunnelv1.ReadVisitorSourceProof([]byte(metadata.VisitorSourceProof))
	if err != nil {
		t.Fatal(err)
	}
	client, err := f.secure(stream)
	if err != nil {
		t.Fatal(err)
	}
	response, err := capacityRequest(client, "/held", false, token.Reveal())
	if err != nil || response.StatusCode != 200 {
		t.Fatal("current permission did not reach the application", err)
	}
	defer response.Body.Close()
	f.wait(0, 1)
	f.route.mu.Lock()
	var retired *publicVisitorAdmission
	for _, admission := range f.route.streams {
		retired = admission
	}
	f.route.mu.Unlock()
	update.View.VisitorPolicyRevision++
	now := time.Now()
	update.View.ObservedAt, update.View.ValidUntil = now, now.Add(10*time.Second)
	if err := policy.Apply(policy.Begin(), update); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(response.Body); err == nil {
		t.Fatal("policy change retained a streaming request authorized by old permission")
	}
	f.wait(0, 0)
	if err := f.route.consumeVisitorSource(proof, now); !errors.Is(err, errVisitorSourceReplay) {
		t.Fatal("policy change or connection cleanup cleared source history", err)
	}
	denied, err := f.open(1, false)
	if err != nil {
		t.Fatal(err)
	}
	denial, err := f.request(denied, "/", token.Reveal())
	if err != nil || denial.StatusCode != 403 {
		t.Fatal("fresh source proof authorized an obsolete HTTP permission", err)
	}
	_ = denial.Body.Close()
	f.wait(0, 0)
	facts := permission.Facts()
	facts.VisitorPolicyRevision = update.View.VisitorPolicyRevision
	freshToken, err := visitortoken.Sign(view.Issuer, facts.SigningKeyID, ed25519.NewKeyFromSeed([]byte(strings.Repeat("h", 32))), facts, now)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := f.open(1, false)
	if err != nil {
		t.Fatal(err)
	}
	current, err := f.secure(fresh)
	if err != nil {
		t.Fatal(err)
	}
	result, err := capacityRequest(current, "/", false, freshToken.Reveal())
	if err != nil || result.StatusCode != 204 {
		t.Fatal("current source and permission did not reuse retired capacity", err)
	}
	_ = result.Body.Close()
	retired.retire()
	f.wait(0, 1)
	if calls.Load() != 2 {
		t.Fatal("source proof bypassed permission or replayed application work", calls.Load())
	}
	_ = current.Close()
	f.wait(0, 0)
}

func TestPublisherVisitorPolicyRejectsMissingOrChangedSourceMasterWithoutExtendingPolicy(t *testing.T) {
	for _, mutate := range []func(*controlv1.VisitorPolicyUpdate){
		func(update *controlv1.VisitorPolicyUpdate) { update.VisitorSourceKey = nil },
		func(update *controlv1.VisitorPolicyUpdate) { update.VisitorSourceKey = new([]byte{1}) },
		func(update *controlv1.VisitorPolicyUpdate) { update.VisitorSourceKey = new(make([]byte, 32)) },
		func(update *controlv1.VisitorPolicyUpdate) {
			update.VisitorSourceKey = new(bytes.Repeat([]byte{2}, 32))
		},
		func(update *controlv1.VisitorPolicyUpdate) { update.VisitorSourceAuthority = new([]byte{1}) },
	} {
		synctest.Test(t, func(t *testing.T) {
			base := &policyClientFixture{key: ed25519.NewKeyFromSeed([]byte(strings.Repeat("p", 32)))}
			base.revision.Store(1)
			var changed bool
			client := policyClientFunc(func(ctx context.Context, request controlv1.PublisherVisitorPolicyRequest, token string) (controlv1.VisitorPolicyUpdate, error) {
				update, err := base.ReadPublisherVisitorPolicy(ctx, request, token)
				if changed {
					mutate(&update)
				}
				return update, err
			})
			policy, err := prepareVisitorPolicy(t.Context(), client, visitorscope.Scope{Kind: visitorscope.PublicURL, ID: certificateTestPublicURLID}, "run", 1, "run-secret", nil)
			if err != nil {
				t.Fatal(err)
			}
			defer policy.Close()
			before, _, _ := policy.lease.Current()
			changed = true
			if err := policy.refresh(t.Context()); !errors.Is(err, visitorlease.ErrUpdate) {
				t.Fatal("invalid run master lost its policy classification", err)
			}
			after, enabled, _ := policy.lease.Current()
			if !enabled || !after.ValidUntil.Equal(before.ValidUntil) || policy.sourceKey != testPublicVisitorSourceKey {
				t.Fatal("invalid source-key renewal changed serving authority")
			}
		})
	}
}
