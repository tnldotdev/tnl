package controlstate

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisheridentity"
)

func TestIntegrationPublisherRuntimeResourceAvailability(t *testing.T) {
	for _, test := range []struct{ name, kind, mutation string }{
		{"suspended-url", "saved_url", `UPDATE control.public_urls SET lifecycle_state='suspended',suspended_at=$2 WHERE id=$1`},
		{"deleted-url", "saved_url", `UPDATE control.public_urls SET lifecycle_state='deleted',deleted_at=$2,request_digest_ciphertext=NULL,request_digest_storage_key_id=NULL WHERE id=$1`},
		{"released-url-domain", "saved_url", `UPDATE control.domains SET state='released',released_at=$2 WHERE id=(SELECT domain_id FROM control.public_urls WHERE id=$1)`},
		{"disabled-service", "private_service", `UPDATE control.private_services SET enabled=false WHERE id=$1`},
		{"deleted-service", "private_service", `UPDATE control.private_services SET deleted_at=$2 WHERE id=$1`},
		{"released-service-domain", "private_service", `UPDATE control.domains SET state='released',released_at=$2 WHERE id=(SELECT domain_id FROM control.private_services WHERE id=$1)`},
		{"released-namespace-domain", "namespace", `UPDATE control.domains SET state='released',released_at=$2 WHERE id=$1`},
	} {
		t.Run(test.name, func(t *testing.T) {
			d, now := newControlStateIntegrationDatabase(t, "runtime_scope")
			r := oidcRouteRequest(t, d, now)
			scope := PublisherScope{TeamID: r.TeamID, Kind: test.kind}
			var resource string
			switch test.kind {
			case "saved_url":
				u := createTestPublicURL(t, d, r, now)
				scope.PublicURLID, resource = u.ID, u.ID
			case "private_service":
				s, err := d.CreatePrivateService(t.Context(), r.TeamID, r.ActingIdentityID, "runtime-service", "runtime-service", now)
				if err != nil {
					t.Fatal(err)
				}
				scope.PrivateServiceID, resource = s.ID, s.ID
				if _, err := d.pool.Exec(t.Context(), `UPDATE control.private_services SET domain_id=$2 WHERE id=$1`, s.ID, r.DomainID); err != nil {
					t.Fatal(err)
				}
			case "namespace":
				scope.DomainID, resource = r.DomainID, r.DomainID
			}
			e := publisherEnrollment(t, d, r, scope, now)
			public, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			p, err := d.RedeemPublisherEnrollment(t.Context(), e.Key, public, now)
			if err != nil {
				t.Fatal(err)
			}
			request := func(action string, epoch int64) PublisherRuntimeRequest {
				proof, err := publisheridentity.Sign(p.ID, p.KeyID, publisheridentity.RuntimeScope(p.GrantID, action, strings.Repeat("a", 32), epoch), "https://control.example/v1/publisher-runtime", key, now)
				if err != nil {
					t.Fatal(err)
				}
				return PublisherRuntimeRequest{PublisherIdentityID: p.ID, ScopeID: p.GrantID, ProcessRunID: strings.Repeat("a", 32), Action: action, Assertion: proof, Audience: "https://control.example/v1/publisher-runtime", SourceIP: "8.8.8.8", ExpectedEpoch: epoch, Now: now}
			}
			if _, err := d.PublisherRuntime(t.Context(), request("start", 0)); err != nil {
				t.Fatal(err)
			}
			q := controlstatedb.New(d.pool)
			before, err := publisherRuntimeStatus(t.Context(), q, p.ID, now)
			if err != nil || before == nil || !before.Active {
				t.Fatal("runtime did not start", err)
			}
			args := []any{resource}
			if strings.Contains(test.mutation, "$2") {
				args = append(args, now)
			}
			if _, err := d.pool.Exec(t.Context(), test.mutation, args...); err != nil {
				t.Fatal(err)
			}
			active, err := q.PublisherRuntimeActive(t.Context(), controlstatedb.PublisherRuntimeActiveParams{PublisherIdentityID: p.ID, ProcessRunID: before.ProcessRunID, Epoch: before.Epoch, Now: timestamptz(now)})
			if err != nil || active {
				t.Fatal("unavailable scope still active", err)
			}
			after, err := publisherRuntimeStatus(t.Context(), q, p.ID, now)
			if err != nil {
				t.Fatal(err)
			}
			before.Active = false
			if !reflect.DeepEqual(before, after) {
				t.Fatal("scope loss changed historical evidence")
			}
			if _, err := d.PublisherRuntime(t.Context(), request("renew", 1)); !errors.Is(err, ErrPublisherIdentity) {
				t.Fatal("unavailable scope renewed", err)
			}
		})
	}
}

func TestIntegrationPublisherRuntimeGroupUsesEnrolledKey(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "runtime_group_key")
	r := appliedProjectRequest(t, d, now)
	r.Configuration = ProjectConfiguration{Publishers: map[string]ProjectPublisherGroup{"remote": {}}, Services: map[string]ProjectServiceConfiguration{"api": {Publisher: "remote", Target: "api.internal:3000"}}}
	if _, err := d.ApplyProjectConfiguration(t.Context(), r); err != nil {
		t.Fatal(err)
	}
	e, err := d.IssuePublisherGroupEnrollment(t.Context(), r.TeamID, r.ProjectKey, "remote", r.ActorID, 1, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	replica := enrollAppliedGroup(t, d, r, e, now)
	m := replica.member
	request := func(action, run, kid string, epoch int64, key ed25519.PrivateKey) PublisherRuntimeRequest {
		proof, err := publisheridentity.Sign(m.PublisherIdentityID, kid, publisheridentity.RuntimeScope(m.GroupID, action, run, epoch), "https://control.example/v1/publisher-runtime", key, now)
		if err != nil {
			t.Fatal(err)
		}
		return PublisherRuntimeRequest{PublisherIdentityID: m.PublisherIdentityID, ScopeID: m.GroupID, ProcessRunID: run, Action: action, Assertion: proof, Audience: "https://control.example/v1/publisher-runtime", SourceIP: "8.8.8.8", ExpectedEpoch: epoch, Now: now}
	}
	run := strings.Repeat("b", 32)
	if _, err := d.PublisherRuntime(t.Context(), request("start", run, m.KeyID, 0, replica.private)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.team_memberships SET manual_suspended_at=$2 WHERE team_id=$1 AND identity_id=$3`, r.TeamID, now, r.ActorID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.PublisherRuntime(t.Context(), request("renew", run, m.KeyID, 1, replica.private)); err != nil {
		t.Fatal("creator suspension rejected team-owned runtime", err)
	}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kid, err := opaqueid.New(opaqueid.PublisherIdentityKeyPrefix)
	if err != nil {
		t.Fatal(err)
	}
	q := controlstatedb.New(d.pool)
	if _, err := q.RetirePublisherKey(t.Context(), controlstatedb.RetirePublisherKeyParams{ID: m.KeyID, Now: timestamptz(now)}); err != nil {
		t.Fatal(err)
	}
	if err := q.InsertPublisherKey(t.Context(), controlstatedb.InsertPublisherKeyParams{ID: kid, PublisherIdentityID: m.PublisherIdentityID, PublicKey: public, Revision: 2, CreatedAt: timestamptz(now)}); err != nil {
		t.Fatal(err)
	}
	before, err := q.GetPublisherRuntime(t.Context(), m.PublisherIdentityID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.PublisherRuntime(t.Context(), request("start", strings.Repeat("c", 32), kid, 1, key)); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatal("non-enrolled group key acquired runtime authority", err)
	}
	after, err := q.GetPublisherRuntime(t.Context(), m.PublisherIdentityID)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("rejected group key changed runtime", err)
	}
}
