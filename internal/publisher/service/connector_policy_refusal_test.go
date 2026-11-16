package service

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestConnectorCurrentPolicyRefusalBeforeStopRemainsAdmissionLocal(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	f := newOpeningRefusalFixture(t, ctx, config.ProtocolTCP)
	b, p := f.bound, f.peer(t, ctx, 0, "P")
	entry := f.entry(t, p, 0, "P")
	view, _, _ := b.prepared.policy.Current()
	permission, err := visitortoken.VerifyConnectorPeerSession(entry, nil, p.bindingSnapshot().expected(), view, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	entered, released := make(chan struct{}), make(chan struct{})
	release := sync.OnceFunc(func() { close(released) })
	guard, err := b.prepared.policy.BindConnector(permission, netip.MustParseAddr(entry.SourceIP), int64(entry.MetadataRevision), func() {
		close(entered)
		<-released
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { release(); guard.Close() }()
	if err := guard.AllowRenewal(); err != nil {
		t.Fatal(err)
	}
	sibling := f.peer(t, ctx, 1, "S")
	siblingEntry := f.entry(t, sibling, 1, "S")
	siblingPermission, err := visitortoken.VerifyConnectorPeerSession(siblingEntry, nil, sibling.bindingSnapshot().expected(), view, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	siblingGuard, err := b.prepared.policy.BindConnector(siblingPermission, netip.MustParseAddr(siblingEntry.SourceIP), int64(siblingEntry.MetadataRevision), func() {
		t.Error("revocation stopped the independent workload")
	})
	if err != nil {
		t.Fatal(err)
	}
	defer siblingGuard.Close()
	if err := siblingGuard.AllowRenewal(); err != nil {
		t.Fatal(err)
	}
	a := &connectorAdmission{peer: p, ctx: t.Context(), caller: t.Context(), guard: guard, state: readyConnectorAdmission{}}
	if _, err := a.CheckUse(t.Context()); err != nil {
		t.Fatal("fixture admission was not current", err)
	}
	policy := f.control.policy
	policy.VisitorPolicyRevision = 3
	policy.ObservedAt = time.Now()
	policy.ValidUntil = policy.ObservedAt.Add(visitortoken.PolicyLifetime)
	digest, err := visitortoken.KeyDigest(f.subjects[1].key.Public())
	if err != nil {
		t.Fatal(err)
	}
	policy.WorkloadLeases = []controlv1.VisitorWorkloadLease{{SessionId: f.subjects[1].id, KeySha256: digest, ExpiresAt: f.until}}
	update, err := visitorlease.Decode(controlv1.VisitorPolicyUpdate{Policy: policy, SnapshotRequired: true})
	if err != nil {
		t.Fatal(err)
	}
	applied := make(chan error, 1)
	go func() { applied <- b.prepared.policy.Apply(b.prepared.policy.Begin(), update) }()
	join := sync.OnceValue(func() error { release(); return <-applied })
	defer func() {
		if err := join(); err != nil {
			t.Error("join policy installation", err)
		}
	}()
	select {
	case <-entered:
	case err := <-applied:
		applied <- err
		t.Fatal("policy installation did not reach its stop callback", err)
	case <-ctx.Done():
		t.Fatal("policy installation did not reach its stop callback", ctx.Err())
	}
	_, refusal := a.CheckUse(t.Context())
	_, siblingErr := siblingGuard.Current()
	if err := join(); err != nil {
		t.Fatal(err)
	}
	if siblingErr != nil {
		t.Fatal("current policy refused the independent workload", siblingErr)
	}
	if !errors.Is(refusal, visitortoken.ErrPolicy) || !connectorAdmissionRoutineError(refusal) {
		t.Fatal("authenticated policy refusal killed the publisher before its stop callback", refusal)
	}
	independent := errors.New("independent physical cleanup failed")
	for _, err := range []error{
		visitortoken.ErrPolicy,
		errors.Join(refusal, visitortoken.ErrPolicy),
		errors.Join(refusal, independent, context.Canceled),
		&muxsession.QUICTransportCloseError{Err: refusal},
	} {
		if connectorAdmissionRoutineError(err) {
			t.Fatal("admission refusal hid a stale policy or independent cleanup failure", err)
		}
	}
	if !connectorAdmissionRoutineError(fmt.Errorf("tls close: %w", errors.Join(refusal, context.Canceled))) {
		t.Fatal("wrapped admission refusal lost its original scope")
	}
}
