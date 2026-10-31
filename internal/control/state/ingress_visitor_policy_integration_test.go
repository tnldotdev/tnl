package state

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestIntegrationIngressVisitorPolicyBindsExactRunProjectionAndProcess(t *testing.T) {
	f, _ := finalVisitorRun(t, "http")
	d := f.database
	if err := d.PrepareVisitorSigningKeys(t.Context(), testVisitorIssuer, f.now); err != nil {
		t.Fatal(err)
	}
	owner := registerServingIngress(t, *f, "policy-ingress", f.now)
	scope := visitorscope.Scope{Kind: visitorscope.PublicURL, ID: f.setup.PublicURLID}
	var revision int64
	if err := d.pool.QueryRow(t.Context(), `SELECT policy_revision FROM control.public_urls WHERE id=$1`, scope.ID).Scan(&revision); err != nil {
		t.Fatal(err)
	}
	update, err := d.ReadIngressVisitorPolicy(t.Context(), owner, scope, f.setup.PublishRunID, int64(f.setup.PublishRunNumber), revision, 0, f.now)
	if err != nil || update.Policy.Resource.Id != scope.ID || update.Policy.Hostname != f.request.CertificateIdentifiers[0] || !update.Policy.ValidUntil.Equal(f.now.Add(10*time.Second)) {
		t.Fatal("ingress did not prepare the scoped current policy", err)
	}
	publisher, err := d.ReadPublisherVisitorPolicy(t.Context(), scope, f.setup.PublishRunID, int64(f.setup.PublishRunNumber), string(f.setup.PublishRunToken), 0, f.now)
	if err != nil || publisher.VisitorSourceKey == nil || len(*publisher.VisitorSourceKey) != 32 || publisher.VisitorSourceAuthority != nil ||
		update.VisitorSourceKey == nil || len(*update.VisitorSourceKey) != 32 || update.VisitorSourceAuthority == nil || bytes.Equal(*publisher.VisitorSourceKey, *update.VisitorSourceKey) {
		t.Fatal("preparation did not separate the publisher master from ingress delegation", err)
	}
	authority, err := tunnelv1.ReadVisitorSourceAuthority(*update.VisitorSourceAuthority)
	if err != nil || authority.IngressID != owner.IngressID || authority.IngressRunID != owner.IngressRunID || authority.IngressLeaseRevision != owner.IngressLeaseRevision ||
		authority.VisitorPolicyRevision != update.Policy.VisitorPolicyRevision || authority.ValidUntil != update.Policy.ValidUntil.Unix() {
		t.Fatal("control lost process, policy or deadline binding", err)
	}
	binding := tunnelv1.VisitorSourceBinding{PublicURLID: scope.ID, PublishRunID: f.setup.PublishRunID, PublishRunNumber: f.setup.PublishRunNumber,
		VisitorID: "visitor", Source: netip.MustParseAddrPort("192.0.2.1:1234"), Destination: netip.MustParseAddrPort("203.0.113.1:443")}
	proof, err := visitortoken.SignVisitorSource([32]byte(*update.VisitorSourceKey), authority, 1, binding, f.now)
	if err != nil || visitortoken.VerifyVisitorSource([32]byte(*publisher.VisitorSourceKey), proof, binding, update.Policy.VisitorPolicyRevision, f.now) != nil {
		t.Fatal("control-issued delegation did not authenticate source at the publisher", err)
	}
	second := registerServingIngress(t, *f, "second-policy-ingress", f.now)
	other, err := d.ReadIngressVisitorPolicy(t.Context(), second, scope, f.setup.PublishRunID, int64(f.setup.PublishRunNumber), revision, 0, f.now)
	if err != nil || other.VisitorSourceKey == nil || bytes.Equal(*update.VisitorSourceKey, *other.VisitorSourceKey) {
		t.Fatal("two ingress processes received the same delegated key", err)
	}
	short := f.now.Add(3 * time.Second)
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.ingress_leases SET lease_expires_at=$2 WHERE ingress_id=$1`, second.IngressID, short); err != nil {
		t.Fatal(err)
	}
	bounded, err := d.ReadIngressVisitorPolicy(t.Context(), second, scope, f.setup.PublishRunID, int64(f.setup.PublishRunNumber), revision, 0, f.now)
	if err != nil || bounded.VisitorSourceAuthority == nil {
		t.Fatal(err)
	}
	shortAuthority, err := tunnelv1.ReadVisitorSourceAuthority(*bounded.VisitorSourceAuthority)
	if err != nil || shortAuthority.ValidUntil != short.Unix() {
		t.Fatal("delegation extended its process lease", err)
	}
	for _, test := range []struct {
		name     string
		run      string
		number   int64
		revision int64
	}{
		{"run", "different-run", int64(f.setup.PublishRunNumber), revision},
		{"number", f.setup.PublishRunID, int64(f.setup.PublishRunNumber) + 1, revision},
		{"projection policy", f.setup.PublishRunID, int64(f.setup.PublishRunNumber), revision + 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := d.ReadIngressVisitorPolicy(t.Context(), owner, scope, test.run, test.number, test.revision, 0, f.now); !errors.Is(err, ErrVisitorPolicy) {
				t.Fatal("wrong run/projection received permission state", err)
			}
		})
	}
	stale := owner
	stale.IngressLeaseRevision++
	if _, err := d.ReadIngressVisitorPolicy(t.Context(), stale, scope, f.setup.PublishRunID, int64(f.setup.PublishRunNumber), revision, 0, f.now); !errors.Is(err, ErrIngressLeaseStale) {
		t.Fatal("stale process prepared policy", err)
	}
	if err := d.ClosePublishRun(t.Context(), f.setup.PublishRunID, f.setup.PublishRunToken, f.now); err != nil {
		t.Fatal(err)
	}
	if _, err := d.ReadIngressVisitorPolicy(t.Context(), owner, scope, f.setup.PublishRunID, int64(f.setup.PublishRunNumber), revision, 0, f.now); !errors.Is(err, ErrVisitorPolicy) {
		t.Fatal("closed run prepared policy", err)
	}
}

func TestIntegrationIngressVisitorPolicyDoesNotWaitForRenewalRow(t *testing.T) {
	f, _ := finalVisitorRun(t, "http")
	d := f.database
	if err := d.PrepareVisitorSigningKeys(t.Context(), testVisitorIssuer, f.now); err != nil {
		t.Fatal(err)
	}
	owner := registerServingIngress(t, *f, "policy-row-lock", f.now)
	var revision int64
	if err := d.pool.QueryRow(t.Context(), `SELECT policy_revision FROM control.public_urls WHERE id=$1`, f.setup.PublicURLID).Scan(&revision); err != nil {
		t.Fatal(err)
	}
	held, err := d.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer held.Rollback(t.Context())
	if _, err := held.Exec(t.Context(), `SELECT ingress_id FROM control.ingress_leases WHERE ingress_id=$1 FOR UPDATE`, owner.IngressID); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	scope := visitorscope.Scope{Kind: visitorscope.PublicURL, ID: f.setup.PublicURLID}
	if _, err := d.ReadIngressVisitorPolicy(ctx, owner, scope, f.setup.PublishRunID, int64(f.setup.PublishRunNumber), revision, 0, f.now); err != nil {
		t.Fatal("read-only policy preparation waited behind process renewal", err)
	}
}
