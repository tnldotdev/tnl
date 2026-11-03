package state

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestIntegrationWorkloadRenewalOverlapsObservation(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "workload_renewal_observation")
	ctx := t.Context()
	r := appliedProjectRequest(t, d, now)
	r.Configuration = workloadConfiguration()
	applied, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	exchange, key := workloadExchange(t, r, now)
	session, err := d.ExchangeWorkload(ctx, exchange, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.PrepareVisitorSigningKeys(ctx, testVisitorIssuer, now); err != nil {
		t.Fatal(err)
	}
	service := applied.Services[0].ServiceID
	scope := visitorscope.Scope{Kind: visitorscope.Service, ID: service}
	// the request captures its clock before a renewal commits, but establishes
	// its database snapshot afterward. no scheduler or real lease wait is needed.
	observed := now.Add(31 * time.Second)
	readPolicy := func(t *testing.T, after int64, at time.Time) controlv1.VisitorPolicyUpdate {
		t.Helper()
		tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		update, err := d.readVisitorPolicy(ctx, tx, scope, after, at)
		if err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		return update
	}
	lease, err := visitorlease.New(scope, func() time.Time { return observed })
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	apply := func(t *testing.T, wire controlv1.VisitorPolicyUpdate) {
		t.Helper()
		update, err := visitorlease.Decode(wire)
		if err != nil {
			t.Fatal(err)
		}
		if err := lease.Apply(lease.Begin(), update); err != nil {
			t.Fatal(err)
		}
	}
	apply(t, readPolicy(t, 0, observed))
	view, _, _ := lease.Current()
	issued, err := d.IssueVisitorToken(ctx, testVisitorIssuer, scope, WorkloadTokenSource{Credential: session.Credential}, observed)
	if err != nil {
		t.Fatal(err)
	}
	entry := tunnelv1.ConnectorPeerVisitorEntry{ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.ConnectorPeerVisitorStream,
		PairID: mustOpaqueID(t, "cpp_"), DeliveryID: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 16)), DeliveryGeneration: 1,
		ServiceID: service, ServiceRunID: mustOpaqueID(t, opaqueid.ServiceRunPrefix), RunNumber: 1, Subject: session.Subject,
		SourceIP: "192.0.2.1", VisitorConnectionID: mustOpaqueID(t, opaqueid.VisitorConnectionPrefix), MetadataRevision: uint64(view.MetadataRevision),
		Permission: tunnelv1.ConnectorVisitorPermission{Token: issued.Token.Reveal(), PublicKey: base64.RawURLEncoding.EncodeToString(exchange.PublicKey), Signature: base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))}}
	message, err := tunnelv1.ConnectorPeerProofMessage(entry, nil)
	if err != nil {
		t.Fatal(err)
	}
	entry.Permission.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, message))
	expected := entry.Session()
	expected.ExpiresAt = session.LeaseExpiresAt
	permission, err := visitortoken.VerifyConnectorPeerSession(entry, nil, expected, view, observed)
	if err != nil {
		t.Fatal(err)
	}
	var stopped atomic.Int32
	guard, err := lease.BindConnector(permission, netip.MustParseAddr(entry.SourceIP), int64(entry.MetadataRevision), func() { stopped.Add(1) })
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Close()
	if err := guard.AllowRenewal(); err != nil {
		t.Fatal(err)
	}
	renewed, err := d.RenewWorkloadSession(ctx, session.ID, session.Credential, observed.Add(time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	t.Run("publisher policy", func(t *testing.T) {
		update := readPolicy(t, view.VisitorPolicyRevision, observed)
		apply(t, update)
		if _, err := guard.Current(); err != nil || stopped.Load() != 0 {
			t.Error("concurrent renewal canceled the retained connector stream guard", err)
		}
		if len(update.Policy.WorkloadLeases) != 1 || update.Policy.WorkloadLeases[0].SessionId != session.ID {
			t.Fatal("concurrent renewal disappeared from a successful policy observation")
		}
		if update.Policy.WorkloadLeases[0].ExpiresAt.After(observed.Add(WorkloadLease)) {
			t.Fatal("policy observation borrowed time after its request clock")
		}
	})
	t.Run("visitor permission", func(t *testing.T) {
		issued, err := d.IssueVisitorToken(ctx, testVisitorIssuer, scope, WorkloadTokenSource{Credential: session.Credential}, observed)
		if err != nil {
			t.Fatal("concurrent renewal rejected visitor permission", err)
		}
		if issued.Permission.ExpiresAt.After(observed.Add(WorkloadLease)) {
			t.Fatal("permission escaped its observation budget")
		}
	})
	t.Run("credential and session", func(t *testing.T) {
		if _, err := d.ListWorkloadServices(ctx, session.Credential, observed); err != nil {
			t.Error("concurrent renewal invalidated the workload credential", err)
		}
		replayed, err := d.RenewWorkloadSession(ctx, session.ID, session.Credential, observed)
		if err != nil {
			t.Fatal("older in-flight renewal rejected current session", err)
		}
		if !replayed.LeaseExpiresAt.Equal(renewed.LeaseExpiresAt) || !replayed.ExpiresAt.Equal(session.ExpiresAt) {
			t.Fatal("older in-flight renewal moved the current deadline")
		}
	})
	t.Run("creation and expiry fences", func(t *testing.T) {
		for _, at := range []time.Time{now.Add(-time.Millisecond), renewed.LeaseExpiresAt, session.ExpiresAt} {
			if _, err := d.ListWorkloadServices(ctx, session.Credential, at); !errors.Is(err, ErrWorkloadDenied) {
				t.Error("invalid lifetime accepted a workload credential", err)
			}
		}
	})
	t.Run("revocation", func(t *testing.T) {
		if err := d.RevokeWorkloadSession(ctx, session.ID, session.Credential, observed.Add(2*time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		if _, err := d.IssueVisitorToken(ctx, testVisitorIssuer, scope, WorkloadTokenSource{Credential: session.Credential}, observed); !errors.Is(err, ErrWorkloadDenied) {
			t.Fatal("in-flight request ignored committed revocation", err)
		}
		apply(t, readPolicy(t, 0, observed))
		if _, err := guard.Current(); err == nil || stopped.Load() != 1 {
			t.Fatal("committed revocation did not stop the retained connector stream guard", err)
		}
	})
}
