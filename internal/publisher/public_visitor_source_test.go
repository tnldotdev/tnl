package publisher

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/testutil/visitorfixture"

	"github.com/tnldotdev/tnl/internal/policy/ippolicy"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestPublicHTTPAuthorizationUsesAcceptedVisitorSource(t *testing.T) {
	trusted := netip.MustParseAddrPort("198.51.100.7:5678")
	var forwarded int
	route, err := newTestPublicURLServer(t, PublicURLServerConfig{Hostname: "preview.example.test", Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded++
		if r.RemoteAddr != trusted.String() || r.Header.Get("Authorization") != "Bearer application-secret" {
			t.Error("HTTP authorization lost accepted visitor metadata or application authentication")
		}
		w.WriteHeader(http.StatusNoContent)
	})})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = route.Close() })
	for _, remote := range []string{"192.0.2.1:1234", "not visitor metadata"} {
		r := visitorfixture.Request()
		r.RemoteAddr = remote
		r.Header.Set("Authorization", "Bearer application-secret")
		r.Header.Set("X-Forwarded-For", "203.0.113.99")
		session := &visitorSession{visitor: Visitor{Run: route.run, Source: trusted}}
		r = r.WithContext(context.WithValue(r.Context(), visitorSessionKey{}, session))
		w := httptest.NewRecorder()
		serveTestPublicRequest(t, route, w, r)
		if w.Code != http.StatusNoContent {
			t.Fatal("accepted visitor source was replaced by request metadata", w.Code)
		}
	}
	if forwarded != 2 {
		t.Fatal("accepted visitor did not reach the application", forwarded)
	}
}

func TestVisitorSourceMetadataOnlyOpeningDoesNotConsumeFallbackProof(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int32
		route, err := newTestPublicURLServer(t, PublicURLServerConfig{Hostname: "route.example", Certificate: visitorfixture.Certificate(t, "route.example"), Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			w.WriteHeader(http.StatusNoContent)
		})})
		if err != nil {
			t.Fatal(err)
		}
		defer route.Close()
		if err := route.Start(); err != nil {
			t.Fatal(err)
		}
		header, metadata := sourceMetadataFixture(t, route)
		wire, err := proxyproto.Encode(metadata)
		if err != nil {
			t.Fatal(err)
		}
		open := func(connectionID string) net.Conn {
			t.Helper()
			local, remote := net.Pipe()
			t.Cleanup(func() { _ = remote.Close() })
			streamHeader := header
			streamHeader.PublisherConnectionID = connectionID
			done := make(chan struct{})
			go func() {
				defer close(done)
				serveTestPublicVisitor(t, route, local, streamHeader)
			}()
			t.Cleanup(func() { _ = remote.Close(); <-done })
			if _, err := remote.Write(wire); err != nil {
				t.Fatal(err)
			}
			return remote
		}
		stalled := open("connection-a")
		synctest.Wait()
		route.mu.Lock()
		consumed := len(route.sourceHistory)
		route.mu.Unlock()
		if consumed != 0 {
			t.Fatal("metadata without visitor bytes consumed fallback source proof")
		}
		fallback := tls.Client(open("connection-b"), &tls.Config{RootCAs: visitorfixture.Roots(t, *route.certificate.Load()), ServerName: "route.example"})
		defer fallback.Close()
		if err := fallback.HandshakeContext(t.Context()); err != nil {
			t.Fatal("fallback could not use the uncommitted source proof", err)
		}
		response, err := capacityRequest(fallback, "/", true)
		if err != nil || response.StatusCode != http.StatusNoContent {
			t.Fatal("fallback did not reach the application", err)
		}
		_ = response.Body.Close()
		// a delayed first byte on the abandoned path must not reuse the proof
		// after the healthy path has committed it.
		if _, err := stalled.Write([]byte{22}); err != nil {
			t.Fatal(err)
		}
		if n, err := stalled.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
			t.Fatal("abandoned path replayed committed source proof", n, err)
		}
		if calls.Load() != 1 {
			t.Fatal("visitor application work was replayed", calls.Load())
		}
	})
}

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
	// a faster policy refresh can project an earlier authority time. retirement
	// must remain final even after its history has left the bounded replay table.
	for _, rollback := range []time.Duration{time.Second, time.Hour} {
		if err := route.consumeVisitorSource(proof, time.Unix(until, 0).Add(-rollback)); !errors.Is(err, visitortoken.ErrVisitorSource) {
			t.Fatal("clock rollback reopened retired source evidence", rollback, err)
		}
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
		header.ConfirmBeforeBytes = true
		stream, err := f.relays[index].OpenVisitorStream(f.ctx, header, nil, tunnel.ReturnEvents{})
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
	policy, update, token := visitorfixture.ScopePolicy(t, visitorscope.Scope{Kind: visitorscope.PublicURL, ID: certificateTestPublicURLID}, "route.example", 443, false)
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
	if err := f.route.authenticateVisitorSource(stream.(*publicCapacityStream).header, metadata); !errors.Is(err, errVisitorSourceReplay) {
		t.Fatal("policy change or connection cleanup cleared source history", err)
	}
	denied, err := f.open(1, false)
	if err != nil {
		t.Fatal(err)
	}
	olderSource := func(stream *publicCapacityStream) {
		t.Helper()
		stream.metadata, err = encodeTestPublicSource(testPublicVisitorSourceKey, stream.header, proof.Authority.VisitorPolicyRevision,
			view.AuthorityTime(time.Now()), time.Unix(proof.Authority.ValidUntil, 0), metadata)
		if err != nil {
			t.Fatal(err)
		}
	}
	olderSource(denied.(*publicCapacityStream))
	denial, err := f.request(denied, "/", token.Reveal())
	if err != nil || denial.StatusCode != 403 {
		t.Fatal("unexpired older source evidence authorized an obsolete HTTP permission", err)
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
	olderSource(fresh.(*publicCapacityStream))
	current, err := f.secure(fresh)
	if err != nil {
		t.Fatal(err)
	}
	result, err := capacityRequest(current, "/", false, freshToken.Reveal())
	if err != nil || result.StatusCode != 204 {
		t.Fatal("unexpired older source evidence and current permission did not reuse retired capacity", err)
	}
	_ = result.Body.Close()
	retired.retire()
	f.wait(0, 1)
	if calls.Load() != 2 {
		t.Fatal("source proof bypassed permission or replayed application work", calls.Load())
	}
	_ = current.Close()
	f.wait(0, 0)
	// old origin evidence also cannot bypass a newly installed IP restriction,
	// even when the HTTP permission itself is signed for the current revision.
	ip, err := ippolicy.Hash([32]byte{1}, netip.MustParsePrefix("198.51.100.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	restriction, err := ippolicy.New([32]byte{1}, []ippolicy.Entry{ip})
	if err != nil {
		t.Fatal(err)
	}
	update.IP = &restriction
	update.View.VisitorPolicyRevision++
	now = time.Now()
	update.View.ObservedAt, update.View.ValidUntil = now, now.Add(10*time.Second)
	if err := policy.Apply(policy.Begin(), update); err != nil {
		t.Fatal(err)
	}
	facts.VisitorPolicyRevision = update.View.VisitorPolicyRevision
	currentToken, err := visitortoken.Sign(view.Issuer, facts.SigningKeyID, ed25519.NewKeyFromSeed([]byte(strings.Repeat("h", 32))), facts, now)
	if err != nil {
		t.Fatal(err)
	}
	outside, err := f.open(0, false)
	if err != nil {
		t.Fatal(err)
	}
	olderSource(outside.(*publicCapacityStream))
	blocked, err := f.request(outside, "/", currentToken.Reveal())
	if err != nil || blocked.StatusCode != 403 {
		t.Fatal("old source evidence bypassed current IP policy", err)
	}
	_ = blocked.Body.Close()
	f.wait(0, 0)
	if calls.Load() != 2 {
		t.Fatal("new IP restriction reached the application", calls.Load())
	}
}
