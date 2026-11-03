package service

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestConnectorRenewalSupersededProofDoesNotRetireCurrentGuard(t *testing.T) {
	b, p, _, opening, control := connectorPeerFixture(t, "127.0.0.1:1")
	apply := func(revision int64, duration time.Duration, enabled bool) {
		t.Helper()
		request := b.prepared.policy.Begin()
		policy := control.policy
		policy.VisitorPolicyRevision, policy.Enabled = revision, enabled
		policy.ObservedAt = time.Now()
		policy.ValidUntil = policy.ObservedAt.Add(duration)
		update, err := visitorlease.Decode(controlv1.VisitorPolicyUpdate{Policy: policy, SnapshotRequired: true})
		if err != nil {
			t.Fatal(err)
		}
		if err := b.prepared.policy.Apply(request, update); err != nil {
			t.Fatal(err)
		}
	}
	apply(1, 500*time.Millisecond, true)
	entry := opening("S")
	view, _, _ := b.prepared.policy.Current()
	original, err := visitortoken.VerifyConnectorPeerSession(entry, nil, p.bindingSnapshot().expected(), view, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var stopped atomic.Bool
	guard, err := b.prepared.policy.BindConnector(original, netip.MustParseAddr(entry.SourceIP), int64(entry.MetadataRevision), func() { stopped.Store(true) })
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Close()
	if err := guard.AllowRenewal(); err != nil {
		t.Fatal(err)
	}
	a := &connectorAdmission{peer: p, ctx: t.Context(), caller: t.Context(), admitted: true, ready: true, guard: guard}
	apply(2, visitortoken.PolicyLifetime, true)
	before, err := a.CheckUse(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, boundary := range []string{"signature", "metadata", "subject", "expired proof", "changed session"} {
		t.Run(boundary, func(t *testing.T) {
			invalid := entry
			switch boundary {
			case "signature":
				invalid.Permission.Signature = base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
			case "metadata":
				invalid.MetadataRevision++
			case "subject":
				invalid.Subject.DeviceID = "vdev_" + string(bytes.Repeat([]byte{'Z'}, 22))
			case "expired proof", "changed session":
				facts, issuedAt := original.Facts(), time.Now()
				if boundary == "expired proof" {
					facts.ExpiresAt = issuedAt.Add(-time.Second)
					issuedAt = issuedAt.Add(-5 * time.Second)
				} else {
					subject := facts.Subject.(visitortoken.Device)
					subject.SessionID = "cs_" + string(bytes.Repeat([]byte{'Z'}, 22))
					facts.Subject = subject
				}
				token, err := visitortoken.Sign(control.policy.Issuer, "fixture", ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32)), facts, issuedAt)
				if err != nil {
					t.Fatal(err)
				}
				invalid.Permission.Token = token.Reveal()
				message, err := tunnelv1.ConnectorPeerProofMessage(invalid, nil)
				if err != nil {
					t.Fatal(err)
				}
				invalid.Permission.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32)), message))
			}
			if err := a.renewPermission(invalid, original); err == nil {
				t.Fatal("superseded proof bypassed binding verification")
			}
		})
	}
	// control minted this authentic same-subject proof before an independent
	// policy snapshot advanced. ignoring it may retain, but never extend, the
	// still-current guard while the connector obtains the next revision.
	if err := a.renewPermission(entry, original); err != nil {
		t.Fatal("superseded in-flight proof would close the live stream", err)
	}
	if after, err := a.CheckUse(t.Context()); err != nil || after.After(before) || stopped.Load() {
		t.Fatal("superseded proof changed the original guard fence", err)
	}
	apply(2, visitortoken.PolicyLifetime, true)
	if err := a.renewPermission(entry, original); err != nil {
		t.Fatal(err)
	}
	if after, err := a.CheckUse(t.Context()); err != nil || after.After(before) {
		t.Fatal("repeated stale proof or policy refresh extended the original deadline", err)
	}
	<-time.After(time.Until(before.Add(time.Millisecond)))
	if err := a.renewPermission(entry, original); err == nil {
		t.Fatal("stale proof revived an expired guard")
	}
}

func TestConnectorRenewalWaitsForBackgroundRevisionWithinOriginalGuard(t *testing.T) {
	for _, advance := range []bool{false, true} {
		t.Run(map[bool]string{false: "outage", true: "current snapshot"}[advance], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			target, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close()
			targetDone := make(chan struct{})
			go func() {
				defer close(targetDone)
				conn, err := target.Accept()
				if err == nil {
					defer conn.Close()
					_, _ = io.Copy(conn, conn)
				}
			}()
			b, p, verification, opening, control := connectorPeerFixture(t, target.Addr().String())
			entry := opening("R")
			client, server := connectorInnerPair(t, ctx, verification)
			served := make(chan error, 1)
			go func() { served <- serveConnectorInner(ctx, p, server) }()
			connectorControl(t, ctx, client)
			defer func() { p.Close(); <-served; <-targetDone }()
			raw, err := client.OpenStream(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tunnelv1.WriteConnectorPeerVisitorOpening(raw, entry, nil); err != nil {
				t.Fatal(err)
			}
			secured := connectorVisitorTLS(raw, verification, entry.VisitorConnectionID)
			defer secured.Close()
			_ = secured.SetDeadline(time.Now().Add(time.Second))
			if _, err := secured.Write([]byte("ready")); err != nil {
				t.Fatal(err)
			}
			var data [5]byte
			if _, err := io.ReadFull(secured, data[:]); err != nil || string(data[:]) != "ready" {
				t.Fatal(err)
			}
			b.mu.Lock()
			var a *connectorAdmission
			for current := range p.streams {
				a = current
			}
			b.mu.Unlock()
			if a == nil {
				t.Fatal("real forwarding did not retain admission")
			}
			view, _, _ := b.prepared.policy.Current()
			original, err := visitortoken.VerifyConnectorPeerSession(entry, nil, p.bindingSnapshot().expected(), view, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			facts := original.Facts()
			facts.VisitorPolicyRevision++
			token, err := visitortoken.Sign(control.policy.Issuer, "fixture", ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32)), facts, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			entry.Permission.Token = token.Reveal()
			message, err := tunnelv1.ConnectorPeerProofMessage(entry, nil)
			if err != nil {
				t.Fatal(err)
			}
			entry.Permission.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32)), message))
			apply := func(revision int64, duration time.Duration) {
				t.Helper()
				r := b.prepared.policy.Begin()
				policy := control.policy
				policy.VisitorPolicyRevision = revision
				policy.ObservedAt = time.Now()
				policy.ValidUntil = policy.ObservedAt.Add(duration)
				update, err := visitorlease.Decode(controlv1.VisitorPolicyUpdate{Policy: policy, SnapshotRequired: true})
				if err != nil {
					t.Fatal(err)
				}
				if err := b.prepared.policy.Apply(r, update); err != nil {
					t.Fatal(err)
				}
			}
			apply(1, 300*time.Millisecond)
			before, err := a.CheckUse(ctx)
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- a.renewPermission(entry, original) }()
			select {
			case err := <-done:
				t.Fatal("future signed revision did not wait for canonical policy", err)
			case <-time.After(30 * time.Millisecond):
			}
			if until, err := a.CheckUse(ctx); err != nil || until.After(before) {
				t.Fatal("unobserved revision extended the original guard", err)
			}
			if advance {
				apply(2, visitortoken.PolicyLifetime)
			}
			select {
			case err := <-done:
				if advance && err != nil || !advance && err == nil {
					t.Fatal("renewal ignored the background snapshot or original deadline", err)
				}
			case <-time.After(time.Second):
				t.Fatal("revision wait exceeded its original guard")
			}
			if !advance {
				apply(2, visitortoken.PolicyLifetime)
				if _, err := a.CheckUse(ctx); err == nil {
					t.Fatal("late policy revived an expired admission")
				}
			}
		})
	}
}
