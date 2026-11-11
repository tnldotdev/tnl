package state

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationDurableVisitorProjectionIsBoundedWithoutTruncation(t *testing.T) {
	for _, kind := range []string{"share", "service"} {
		t.Run(kind, func(t *testing.T) {
			d, now := newControlStateIntegrationDatabase(t, "durable_bounds_"+kind)
			r := oidcRouteRequest(t, d, now)
			scope := visitorscope.Scope{Kind: visitorscope.PublicURL}
			if kind == "share" {
				scope.ID = createTestPublicURL(t, d, r, now).ID
			} else {
				service, err := d.CreateServiceAt(t.Context(), r.TeamID, r.ActingIdentityID, "bounds", "bounds", ServicePlacement{}, now, ServiceMetadata{Protocol: "http"})
				if err != nil {
					t.Fatal(err)
				}
				scope.Kind, scope.ID = visitorscope.Service, service.ID
			}
			insert := func(first, last int) {
				t.Helper()
				var err error
				if kind == "share" {
					_, err = d.pool.Exec(t.Context(), `WITH inserted AS (
				INSERT INTO control.shares(id,team_id,scope,created_by_identity_id,idempotency_key,request_digest,secret_digest,created_at,expires_at)
				SELECT 'shr_'||lpad(n::text,22,'0'),$1,'url',$2,'bound-'||n,$3,$3,$4,$4::timestamptz+interval '7 days' FROM generate_series($6::int,$7::int) n RETURNING id,team_id
				) INSERT INTO control.share_public_urls(share_id,team_id,public_url_id) SELECT id,team_id,$5 FROM inserted`, r.TeamID, r.ActingIdentityID, bytes.Repeat([]byte{9}, 32), now, scope.ID, first, last)
				} else {
					_, err = d.pool.Exec(t.Context(), `INSERT INTO control.service_http_grants(id,service_id,kind,secret_digest,created_by_identity_id,expires_at)
				SELECT 'shg_'||lpad(n::text,22,'0'),$1,'token',sha256(convert_to(n::text,'UTF8')),$2,$3::timestamptz+interval '7 days' FROM generate_series($4::int,$5::int) n`, scope.ID, r.ActingIdentityID, now, first, last)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			insert(1, 256)
			if err := d.PrepareVisitorSigningKeys(t.Context(), testVisitorIssuer, now); err != nil {
				t.Fatal(err)
			}
			body, err := durablePolicyAt(t, d, scope, now)
			if err != nil || len(body.Policy.ShareVerifiers)+len(body.Policy.GrantVerifiers) != 256 {
				t.Fatal("maximum projection truncated", err)
			}
			if _, err := visitorlease.Decode(body); err != nil {
				t.Fatal(err)
			}
			if kind == "service" {
				if _, err := d.CreateServiceHTTPGrant(t.Context(), scope.ID, r.ActingIdentityID, controlv1.CreateVisitorCredentialRequest{Resource: controlv1.VisitorResourceScope{Kind: "service", Id: scope.ID}, Kind: "token", ExpiresAt: now.Add(time.Hour)}, now); !errors.Is(err, ErrServiceAccess) {
					t.Fatal("creation exceeded verifier budget", err)
				}
			}
			insert(257, 257)
			if _, err := durablePolicyAt(t, d, scope, now); !errors.Is(err, ErrVisitorPolicy) {
				t.Fatal("overflow did not fail closed", err)
			}
		})
	}
}
