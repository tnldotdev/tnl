package service

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/ippolicy"
	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func sourcePolicyPermission(t *testing.T, f *pendingHTTPFixture) visitortoken.Token {
	t.Helper()
	view, _, _ := f.source.prepared.policy.Current()
	now := time.Now()
	token, err := visitortoken.Sign(view.Issuer, "lifecycle", ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)),
		visitortoken.Permission{Scope: view.Scope, Hostname: view.Hostname, Port: view.Port,
			VisitorPolicyRevision: view.VisitorPolicyRevision,
			Subject:               visitortoken.Share{ShareID: "shr_" + strings.Repeat("S", 22)},
			ExpiresAt:             now.Add(5 * time.Minute).Truncate(time.Second)}, now)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func sourcePolicyRequest(t *testing.T, v *pendingHTTPVisitor, path string, token visitortoken.Token) *http.Response {
	t.Helper()
	request, err := http.NewRequestWithContext(v.fixture.ctx, http.MethodGet,
		"https://"+v.fixture.source.prepared.managedHostname+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set(httpaccess.VisitorTokenHeader, token.Reveal())
	request.Header.Set("Authorization", "Bearer unchanged-application")
	if err := request.Write(v.secure); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(v.reader, request)
	if err != nil {
		t.Fatal("source-policy request lost its HTTP response", err)
	}
	return response
}

func sourcePolicyHandshake(t *testing.T, v *pendingHTTPVisitor, metadata []byte) error {
	t.Helper()
	if _, err := v.raw.Write(metadata); err != nil {
		return err
	}
	v.secure = tls.Client(v.raw, v.fixture.source.verification.Clone())
	if err := v.secure.HandshakeContext(v.fixture.ctx); err != nil {
		return err
	}
	v.reader = bufio.NewReader(v.secure)
	return nil
}

func TestServiceHTTPSourcePolicyRevisionRetainsReplayAndStaleReleaseFence(t *testing.T) {
	canceled := make(chan struct{})
	f := newPendingHTTPFixture(t, 1, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(httpaccess.VisitorTokenHeader) != "" {
			t.Error("source-policy visitor permission reached the application")
		}
		if r.URL.Path == "/held" {
			_, _ = io.WriteString(w, "prefix")
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			close(canceled)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	policy := f.source.prepared.policy
	update := f.source.update
	update.Anonymous = false
	apply := func() {
		t.Helper()
		update.View.VisitorPolicyRevision++
		now := time.Now()
		update.View.ObservedAt, update.View.ValidUntil = now, now.Add(visitortoken.PolicyLifetime)
		if err := policy.Apply(policy.Begin(), update); err != nil {
			t.Fatal(err)
		}
	}
	apply()
	oldToken := sourcePolicyPermission(t, f)
	first := f.mustOpen(t, 0, netip.MustParseAddr("192.0.2.10"))
	oldMetadata := f.metadata(t, first.header, first.source, false)
	metadata, _, err := proxyproto.Decode(bytes.NewReader(oldMetadata))
	if err != nil {
		t.Fatal(err)
	}
	proof, err := tunnelv1.ReadVisitorSourceProof([]byte(metadata.VisitorSourceProof))
	if err != nil {
		t.Fatal(err)
	}
	if err := sourcePolicyHandshake(t, first, oldMetadata); err != nil {
		t.Fatal(err)
	}
	response := sourcePolicyRequest(t, first, "/held", oldToken)
	if response.StatusCode != http.StatusOK {
		t.Fatal("current permission did not enter the streaming application", response.Status)
	}
	prefix := make([]byte, len("prefix"))
	if _, err := io.ReadFull(response.Body, prefix); err != nil || string(prefix) != "prefix" {
		t.Fatal("streaming request did not deliver its admitted prefix", string(prefix), err)
	}
	assertHTTPAdmissionCharges(t, first.admission, 0, 0, 1)
	if f.calls.Load() != 1 || f.capacity.Load() != 1 {
		t.Fatal("admitted stream did not use exactly one authenticated capacity exchange")
	}
	apply()
	if _, err := io.ReadAll(response.Body); err == nil {
		t.Fatal("revision retained the streaming request authorized by the old permission")
	}
	_ = response.Body.Close()
	claimedAwait(t, canceled)
	first.close()
	first.join(t)
	assertHTTPAdmissionCharges(t, first.admission, 0, 0, 0)
	if err := f.source.bound.checkVisitorSource(f.ctx, first.header, metadata, proof); !errors.Is(err, errSourceProofReplay) {
		t.Fatal("policy revision or joined retirement cleared source replay history", err)
	}
	replayed, err := f.open(t, 1, first.source, func(header *tunnelv1.ServiceForwardingHeader) {
		header.VisitorConnectionID = first.header.VisitorConnectionID
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := sourcePolicyHandshake(t, replayed, oldMetadata); err == nil {
		t.Fatal("a real claimed stream replayed the retired visitor proof")
	}
	replayed.close()
	replayed.join(t)
	// retain the exact old, still-live authority. only the visitor binding and
	// sequence change; no current-revision delegation is minted for these tails.
	oldAuthority, sourceKey, err := visitortoken.IssueVisitorSourceAuthority(f.source.prepared.sourceKey, proof.Authority, time.Now())
	if err != nil || !bytes.Equal(oldAuthority.MAC, proof.Authority.MAC) {
		t.Fatal("could not retain the original source authority", err)
	}
	olderSource := func(v *pendingHTTPVisitor) []byte {
		t.Helper()
		view, _, _ := policy.Current()
		now := view.AuthorityTime(time.Now())
		if oldAuthority.VisitorPolicyRevision >= view.VisitorPolicyRevision ||
			!time.Unix(oldAuthority.ValidUntil, 0).After(now) {
			t.Fatal("older-source tail lost its old but unexpired delegation")
		}
		input := metadata
		signed, err := visitortoken.SignVisitorSource(sourceKey, oldAuthority, f.sequence.Add(1),
			tunnelv1.VisitorSourceBinding{ServiceID: v.header.ServiceID, ServiceRunID: v.header.ServiceRunID,
				RunNumber: v.header.RunNumber, VisitorConnectionID: v.header.VisitorConnectionID,
				Source: input.Source, Destination: input.Destination}, now)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := signed.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		input.VisitorSourceProof = string(wire)
		encoded, err := proxyproto.Encode(input)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	denied := f.mustOpen(t, 1, first.source)
	if err := sourcePolicyHandshake(t, denied, olderSource(denied)); err != nil {
		t.Fatal("old live source evidence was confused with HTTP permission", err)
	}
	pendingHTTPResponse(t, sourcePolicyRequest(t, denied, "/", oldToken), http.StatusForbidden)
	denied.close()
	denied.join(t)
	if f.calls.Load() != 1 || f.capacity.Load() != 1 {
		t.Fatal("old source authority admitted an obsolete visitor permission")
	}
	fresh := f.mustOpen(t, 1, first.source)
	if err := sourcePolicyHandshake(t, fresh, olderSource(fresh)); err != nil {
		t.Fatal(err)
	}
	pendingHTTPResponse(t, sourcePolicyRequest(t, fresh, "/", sourcePolicyPermission(t, f)), http.StatusNoContent)
	assertHTTPAdmissionCharges(t, fresh.admission, 0, 0, 1)
	_ = first.admission.retire()
	assertHTTPAdmissionCharges(t, fresh.admission, 0, 0, 1)
	if f.calls.Load() != 2 || f.capacity.Load() != 2 {
		t.Fatal("stale release debited replacement capacity or duplicated application work")
	}
	fresh.close()
	fresh.join(t)
	entry, err := ippolicy.Hash([32]byte{1}, netip.MustParsePrefix("198.51.100.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	restriction, err := ippolicy.New([32]byte{1}, []ippolicy.Entry{entry})
	if err != nil {
		t.Fatal(err)
	}
	update.IP = &restriction
	apply()
	// current HTTP permission cannot bypass public source admission. unlike
	// the retired frontend, this owner rejects the connection before HTTP/TLS.
	current := sourcePolicyPermission(t, f)
	view, _, _ := policy.Current()
	if _, err := visitortoken.VerifyBearer(current, view, time.Now()); err != nil {
		t.Fatal("IP tail did not carry independently current permission", err)
	}
	outside := f.mustOpen(t, 0, first.source)
	if err := sourcePolicyHandshake(t, outside, olderSource(outside)); err == nil {
		t.Fatal("old source delegation bypassed the current IP restriction")
	}
	outside.close()
	outside.join(t)
	assertHTTPAdmissionCharges(t, outside.admission, 0, 0, 0)
	if f.calls.Load() != 2 || f.capacity.Load() != 2 {
		t.Fatal("new IP restriction reached application or ingress capacity work")
	}
}
