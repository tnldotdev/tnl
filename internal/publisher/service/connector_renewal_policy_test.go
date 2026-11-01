package service

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

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
			go func() { served <- p.Serve(ctx, server) }()
			defer func() { p.Close(); <-served; <-targetDone }()
			raw, err := client.OpenStream(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tunnelv1.WriteConnectorPeerVisitorOpening(raw, entry, nil); err != nil {
				t.Fatal(err)
			}
			secured := tls.Client(tunnel.NewConnectorRequestWriter(raw), verification)
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
