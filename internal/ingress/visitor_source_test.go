package ingress

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

var testForwardingSourceSequence atomic.Uint64

func TestVisitorSourceRefreshesBeforeShortIngressLeaseDelegationExpires(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// whole-second delegation timestamps leave only 1.25 seconds initially.
		time.Sleep(time.Until(time.Now().Truncate(time.Second).Add(750 * time.Millisecond)))
		now := time.Now()
		var c *Controller
		var failed atomic.Bool
		var calls atomic.Int64
		client := publicPolicyTestClient{read: func(_ context.Context, _ string, body ingressv1.IngressVisitorPolicyRequest) (controlv1.VisitorPolicyUpdate, error) {
			calls.Add(1)
			if failed.Load() {
				return controlv1.VisitorPolicyUpdate{}, errors.New("control unavailable")
			}
			update := publicPolicyWire(body, "pool.example", time.Now())
			authority, child, err := visitortoken.IssueVisitorSourceAuthority([32]byte{1}, tunnelv1.VisitorSourceAuthority{
				PublicURLID: body.Resource.Id, PublishRunID: body.PublishRunId, PublishRunNumber: uint64(body.PublishRunNumber),
				IngressID: "ingress", IngressRunID: body.IngressRunId, IngressLeaseRevision: uint64(body.IngressLeaseRevision),
				VisitorPolicyRevision: 1, ValidUntil: c.Lease().LeaseExpiresAt.Unix(),
			}, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			wire, err := authority.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			update.VisitorSourceKey, update.VisitorSourceAuthority = new(child[:]), &wire
			return update, nil
		}}
		c = testLeaseController(t, client)
		owner := testIngressLease(now)
		owner.LeaseExpiresAt = now.Add(2 * time.Second)
		if err := c.setLease(owner); err != nil {
			t.Fatal(err)
		}
		entry := publicPolicyEvent(now, 1, 1, "pool.example", true).Entry
		run, err := c.preparePublicPolicy(t.Context(), entry, owner)
		if err != nil {
			t.Fatal(err)
		}
		defer run.close()
		c.publicPolicies[entry.PublishRunId] = run
		renew := func() {
			owner.RenewedAt = time.Now()
			owner.LeaseExpiresAt = time.Now().Add(2 * time.Second)
			if err := c.setLease(owner); err != nil {
				t.Fatal(err)
			}
		}
		source, destination := netip.MustParseAddrPort("192.0.2.1:1234"), netip.MustParseAddrPort("203.0.113.1:443")
		for step := range 100 {
			if step%5 == 0 {
				renew()
			}
			wire, err := c.SignVisitorSource(entry, "visitor", source, destination)
			if err != nil {
				t.Fatalf("delegation expired with healthy 500 ms lease renewals at %v: %v", time.Since(now), err)
			}
			proof, err := tunnelv1.ReadVisitorSourceProof([]byte(wire))
			if err != nil {
				t.Fatal(err)
			}
			if err := visitortoken.VerifyVisitorSource([32]byte{1}, proof, tunnelv1.VisitorSourceBinding{
				PublicURLID: entry.PublicUrlId, PublishRunID: entry.PublishRunId, PublishRunNumber: uint64(entry.PublishRunNumber),
				VisitorID: "visitor", Source: source, Destination: destination,
			}, 1, time.Now()); err != nil {
				t.Fatal(err)
			}
			time.Sleep(100 * time.Millisecond)
			synctest.Wait()
		}
		if calls.Load() < 8 {
			t.Fatal("short delegations were not refreshed", calls.Load())
		}
		failed.Store(true)
		before := calls.Load()
		expires := time.Unix(run.source.Load().authority.ValidUntil, 0)
		for step := range 40 {
			if step%5 == 0 {
				renew()
			}
			time.Sleep(100 * time.Millisecond)
			synctest.Wait()
			if !time.Now().Before(expires) {
				if _, err := c.SignVisitorSource(entry, "visitor", source, destination); !errors.Is(err, visitortoken.ErrVisitorSource) {
					t.Fatal("failed refresh retained expired signing authority", err)
				}
				if _, ok := c.installedPublicPolicy(entry, c.Lease(), time.Now()); ok {
					t.Fatal("expired delegation remained installed for serving")
				}
			}
		}
		if retries := calls.Load() - before; retries < 1 || retries > 4 {
			t.Fatal("failed refresh did not retain bounded retries", retries)
		}
	})
}

func testForwardingSourceSigner(entry ingressv1.IngressRoutingTableEntry, visitorID string, source, destination netip.AddrPort) (string, error) {
	now := time.Now()
	authority, child, err := visitortoken.IssueVisitorSourceAuthority([32]byte{1}, tunnelv1.VisitorSourceAuthority{
		PublicURLID: entry.PublicUrlId, PublishRunID: entry.PublishRunId, PublishRunNumber: uint64(entry.PublishRunNumber),
		IngressID: "fixture-ingress", IngressRunID: "fixture-process", IngressLeaseRevision: 1, VisitorPolicyRevision: 1, ValidUntil: now.Add(10 * time.Second).Unix(),
	}, now)
	if err != nil {
		return "", err
	}
	proof, err := visitortoken.SignVisitorSource(child, authority, testForwardingSourceSequence.Add(1), tunnelv1.VisitorSourceBinding{
		PublicURLID: entry.PublicUrlId, PublishRunID: entry.PublishRunId, PublishRunNumber: uint64(entry.PublishRunNumber), VisitorID: visitorID, Source: source, Destination: destination,
	}, now)
	if err != nil {
		return "", err
	}
	wire, err := proof.MarshalBinary()
	return string(wire), err
}

func TestVisitorSourceSequenceSurvivesPolicyOwnerReplacement(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		now := time.Now()
		client := publicPolicyTestClient{read: func(_ context.Context, _ string, body ingressv1.IngressVisitorPolicyRequest) (controlv1.VisitorPolicyUpdate, error) {
			return publicPolicyWire(body, "pool.example", now), nil
		}}
		c := testLeaseController(t, client)
		owner := testIngressLease(now)
		if err := c.setLease(owner); err != nil {
			t.Fatal(err)
		}
		entry := publicPolicyEvent(now, 1, 1, "pool.example", true).Entry
		source, destination := netip.MustParseAddrPort("192.0.2.1:1234"), netip.MustParseAddrPort("203.0.113.1:443")
		var previous tunnelv1.VisitorSourceProof
		for replacement := range 2 {
			run, err := c.preparePublicPolicy(t.Context(), entry, owner)
			if err != nil {
				t.Fatal(err)
			}
			c.publicPolicies[entry.PublishRunId] = run
			proofs := make(chan tunnelv1.VisitorSourceProof, 100)
			var workers sync.WaitGroup
			for range 100 {
				workers.Go(func() {
					wire, err := c.SignVisitorSource(entry, "visitor", source, destination)
					if err != nil {
						t.Error(err)
						return
					}
					proof, err := tunnelv1.ReadVisitorSourceProof([]byte(wire))
					if err != nil {
						t.Error(err)
						return
					}
					proofs <- proof
				})
			}
			workers.Wait()
			close(proofs)
			seen := make(map[uint64]bool)
			for proof := range proofs {
				if proof.Sequence <= uint64(replacement*100) || seen[proof.Sequence] {
					t.Fatal("policy replacement or concurrent signing reset a sequence", proof.Sequence)
				}
				seen[proof.Sequence] = true
				if replacement > 0 && string(previous.Authority.MAC) != string(proof.Authority.MAC) {
					t.Fatal("fixture did not reuse the same delegation across owner replacement")
				}
				if err := visitortoken.VerifyVisitorSource([32]byte{1}, proof, tunnelv1.VisitorSourceBinding{
					PublicURLID: entry.PublicUrlId, PublishRunID: entry.PublishRunId, PublishRunNumber: uint64(entry.PublishRunNumber), VisitorID: "visitor", Source: source, Destination: destination,
				}, 1, now); err != nil {
					t.Fatal(err)
				}
				previous = proof
			}
			if len(seen) != 100 {
				t.Fatal("signing lost concurrent visitors", len(seen))
			}
			run.close()
			entry.PolicyRevision++
		}
		if _, err := c.SignVisitorSource(entry, "visitor", source, destination); !errors.Is(err, visitortoken.ErrVisitorSource) {
			t.Fatal("retired policy owner retained signing authority", err)
		}
	})
}

func TestVisitorSourcePreparationRejectsMissingOrMismatchedDelegation(t *testing.T) {
	for _, mutate := range []func(*controlv1.VisitorPolicyUpdate){
		func(update *controlv1.VisitorPolicyUpdate) { update.VisitorSourceKey = nil },
		func(update *controlv1.VisitorPolicyUpdate) { update.VisitorSourceKey = new(make([]byte, 32)) },
		func(update *controlv1.VisitorPolicyUpdate) { update.VisitorSourceAuthority = nil },
		func(update *controlv1.VisitorPolicyUpdate) { update.Policy.VisitorPolicyRevision++ },
		func(update *controlv1.VisitorPolicyUpdate) {
			update.Policy.ValidUntil = update.Policy.ObservedAt.Add(time.Second)
		},
		func(update *controlv1.VisitorPolicyUpdate) {
			authority, err := tunnelv1.ReadVisitorSourceAuthority(*update.VisitorSourceAuthority)
			if err != nil {
				t.Fatal(err)
			}
			authority.IngressRunID = "restarted-process"
			wire, err := authority.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			update.VisitorSourceAuthority = &wire
		},
	} {
		client := publicPolicyTestClient{read: func(_ context.Context, _ string, body ingressv1.IngressVisitorPolicyRequest) (controlv1.VisitorPolicyUpdate, error) {
			update := publicPolicyWire(body, "pool.example", time.Now())
			mutate(&update)
			return update, nil
		}}
		c := testLeaseController(t, client)
		now := time.Now()
		run, err := c.preparePublicPolicy(t.Context(), publicPolicyEvent(now, 1, 1, "pool.example", true).Entry, testIngressLease(now))
		if run != nil {
			run.close()
			t.Fatal("invalid source delegation installed a serving owner")
		}
		if !errors.Is(err, visitortoken.ErrVisitorSource) {
			t.Fatal("invalid source delegation lost its classification", err)
		}
	}
}

func TestVisitorSourceMissingSignerOrProofNeverOpensRelay(t *testing.T) {
	for _, signer := range []func(string, netip.AddrPort, netip.AddrPort) (string, error){
		nil,
		func(string, netip.AddrPort, netip.AddrPort) (string, error) { return "", nil },
		func(string, netip.AddrPort, netip.AddrPort) (string, error) { return "", visitortoken.ErrVisitorSource },
	} {
		backend := newTLSBackend(t)
		config := publicURLConfig(backend)
		lookup := config.Lookup
		config.Lookup = func(host string) (PublicURL, LookupReason) {
			route, reason := lookup(host)
			route.AttestSource = signer
			return route, reason
		}
		_, address := startIngress(t, config)
		if err := ingressClient(t, address, "route.example", "").Handshake(); err == nil {
			t.Fatal("unsigned metadata completed visitor TLS")
		}
		if backend.opens.Load() != 0 {
			t.Fatal("missing source evidence opened a relay stream")
		}
	}
}
