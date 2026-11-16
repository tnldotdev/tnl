package state

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestIntegrationGuestAuthorityBoundsPreparationPolicyAndPermissions(t *testing.T) {
	for _, bound := range []string{"ready", "credential", "publisher"} {
		t.Run(bound, func(t *testing.T) {
			age := time.Duration(0)
			if bound == "credential" {
				age = GuestLifetime - 5*time.Second
			}
			f, guest := guestAuthorityFixture(t, false, age)
			if bound == "ready" {
				if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.guest_trials SET used_ready_ns=$2 WHERE id=$1`, guest.ID, int64(GuestReadyAllowance-6*time.Second)); err != nil {
					t.Fatal(err)
				}
			}
			scope := visitorscope.Scope{Kind: visitorscope.Service, ID: f.service.ID}
			raw := bytes.Repeat([]byte{5}, 32)
			share, err := f.database.CreateGuestShare(t.Context(), guestCredentialForTest(guest), f.service.ID, "policy-share", "", sha256.Sum256(raw), guest.ExpiresAt, f.now)
			if err != nil {
				t.Fatal(err)
			}
			source := ShareTokenSource{ShareID: share.ID, Secret: base64.RawURLEncoding.EncodeToString(raw)}
			observations := 1
			if bound == "ready" {
				observations = 3
			}
			for observation := range observations {
				at := f.now.Add(time.Duration(observation) * 4 * time.Second)
				if observation > 0 {
					if _, err := f.heartbeat(at); err != nil {
						t.Fatal(err)
					}
				}
				policy, err := f.database.ReadPublisherVisitorPolicy(f.ctx, scope, f.run.RunID, f.run.RunNumber, f.run.Token, 0, at)
				if err != nil || policy.Policy.ConnectionDeadline == nil || policy.Policy.ConnectionDeadline.After(guest.ExpiresAt) {
					t.Fatalf("preparation policy bound=%+v, %v", policy.Policy, err)
				}
				if _, err := f.database.IssueVisitorToken(t.Context(), testVisitorIssuer, scope, source, at); !errors.Is(err, ErrVisitorPermission) {
					t.Fatalf("preparation granted visitor permission: %v", err)
				}
				before := f.stored(t)
				if before.ActiveReadyAt.Valid || before.ReadyDeadline.Valid || before.ServingUntil.Valid {
					t.Fatalf("observation charged READY: %+v", before)
				}
			}
			f.now = f.now.Add(time.Duration(observations-1) * 4 * time.Second)
			f.ready(t, f.now)
			ready := f.stored(t)
			horizon := ready.ServingUntil.Time
			ingress, err := f.database.RegisterIngress(t.Context(), IngressRegistration{
				IngressID: "guest-policy", IngressRunID: mustOpaqueID(t, opaqueid.IngressRunPrefix), IngressPoolID: PrimaryIngressPoolID,
				HTTPS: true, ProtocolVersion: tunnelv1.Version, ConnectionCapacity: 32,
			}, f.now, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			for _, at := range []time.Time{f.now.Add(time.Second), horizon.Add(-time.Second)} {
				policy, err := f.database.ReadPublisherVisitorPolicy(f.ctx, scope, f.run.RunID, f.run.RunNumber, f.run.Token, 0, at)
				if err != nil || policy.Policy.ConnectionDeadline == nil || !policy.Policy.ConnectionDeadline.Equal(horizon) ||
					!policy.Policy.ValidUntil.Equal(minTime(policy.Policy.ObservedAt.Add(f.database.servingTolerance()), horizon)) {
					t.Fatalf("fixed policy horizon=%+v, %v", policy.Policy, err)
				}
				wire, err := json.Marshal(policy)
				if err != nil {
					t.Fatal(err)
				}
				if err = json.Unmarshal(wire, &policy); err != nil {
					t.Fatal(err)
				}
				decoded, err := visitorlease.Decode(policy)
				if err != nil || !decoded.BoundConnections {
					t.Fatalf("service wire lost hard connection bound: %v", err)
				}
				issued, err := f.database.IssueVisitorToken(t.Context(), testVisitorIssuer, scope, source, at)
				if err != nil || issued.Permission.ExpiresAt.After(horizon) {
					t.Fatalf("visitor permission exceeded horizon: %+v, %v", issued.Permission, err)
				}
				admission, err := readIngressServiceRun(t.Context(), f.database, ingress.IngressLeaseIdentity, f.service.ID, f.run.RunID, at)
				if err != nil || admission.ValidUntil.After(horizon) || admission.Anonymous || admission.RunID != f.run.RunID ||
					admission.Traffic.TotalUploadBytes != 0 || admission.Traffic.TotalDownloadBytes != 0 || admission.Traffic.TotalConnections != 0 {
					t.Fatalf("ordinary ingress horizon/budgets=%+v, %v", admission, err)
				}
			}
			before := f.stored(t)
			for _, at := range []time.Time{horizon, horizon.Add(time.Second)} {
				if _, err := f.database.ReadPublisherVisitorPolicy(f.ctx, scope, f.run.RunID, f.run.RunNumber, f.run.Token, 0, at); err == nil {
					t.Fatal("expired run returned policy")
				}
				if _, err := f.database.IssueVisitorToken(t.Context(), testVisitorIssuer, scope, source, at); !errors.Is(err, ErrVisitorPermission) {
					t.Fatalf("expired run issued token: %v", err)
				}
				if _, err := readIngressServiceRun(t.Context(), f.database, ingress.IngressLeaseIdentity, f.service.ID, f.run.RunID, at); err == nil {
					t.Fatal("expired run admitted ingress visitor")
				}
			}
			if after := f.stored(t); !reflect.DeepEqual(before, after) {
				t.Fatal("denials changed trial authority")
			}
			if _, err := f.heartbeat(horizon); err == nil {
				t.Fatal("expired publisher lease revived")
			}
			if err := f.database.CloseServiceRun(f.ctx, f.service.ID, f.run.RunID, f.run.Token, horizon.Add(time.Hour)); err != nil {
				t.Fatal(err)
			}
			want := min(int64(GuestReadyAllowance), before.UsedReadyNs+int64(horizon.Sub(before.ActiveReadyAt.Time)))
			if after := f.stored(t); after.UsedReadyNs != want {
				t.Fatalf("settlement exceeded issued authority: %+v, want %d", after, want)
			}
		})
	}
}

func TestIntegrationGuestAuthorityOrdinaryPolicyUnchanged(t *testing.T) {
	f := newServicePublicationFixture(t)
	if err := f.database.PrepareVisitorSigningKeys(t.Context(), testVisitorIssuer, f.now); err != nil {
		t.Fatal(err)
	}
	policy, err := f.database.ReadPublisherVisitorPolicy(t.Context(), visitorscope.Scope{Kind: visitorscope.Service, ID: f.service.ID},
		f.run.RunID, f.run.RunNumber, f.run.Token, 0, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if !policy.Policy.Enabled || policy.Policy.ConnectionDeadline != nil || !policy.Policy.ValidUntil.Equal(minTime(policy.Policy.ObservedAt.Add(f.database.servingTolerance()), f.run.ServingUntil)) {
		t.Fatalf("ordinary policy changed: %+v", policy.Policy)
	}
	renewed, err := f.database.HeartbeatServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, f.now.Add(time.Second),
		ServiceRunHealth{Healthy: true, StreamCapacity: 64})
	if err != nil || !renewed.ExpiresAt.Equal(f.now.Add(46*time.Second)) {
		t.Fatalf("ordinary publisher lease changed: %v, %v", renewed.ExpiresAt, err)
	}
}
