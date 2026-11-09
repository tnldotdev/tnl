package state

import (
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationVisitorServiceGrantRetainsAdvertisedLifetimeAcrossSessionAndPolicyChanges(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "durable_service_grant")
	request := oidcRouteRequest(t, d, now)
	session := newOIDCSession(t, d, now)
	principal := ControlPrincipal{IdentityID: session.Identity.Identity.ID, SessionID: session.SessionID}
	ctx := WithControlPrincipal(t.Context(), principal)
	service, err := d.CreateServiceAt(ctx, request.TeamID, principal.IdentityID, "durable", "durable", ServicePlacement{}, now, ServiceMetadata{Protocol: "http"})
	if err != nil {
		t.Fatal(err)
	}
	scope := visitorscope.Scope{Kind: visitorscope.Service, ID: service.ID}
	input := controlv1.CreateVisitorCredentialRequest{Resource: controlv1.VisitorResourceScope{Kind: "service", Id: service.ID}, Kind: "token", ExpiresAt: now.Add(7 * 24 * time.Hour)}
	credential, err := d.CreateServiceHTTPGrant(ctx, service.ID, principal.IdentityID, input, now)
	if err != nil {
		t.Fatal(err)
	}
	if !credential.Permission.ExpiresAt.Equal(input.ExpiresAt) {
		t.Fatal("creation shortened the advertised lifetime")
	}
	token := visitortoken.Token(credential.Permission.VisitorToken)
	read := func(at time.Time, want bool) visitortoken.View {
		t.Helper()
		if err := d.PrepareVisitorSigningKeys(t.Context(), testVisitorIssuer, at); err != nil {
			t.Fatal(err)
		}
		body, err := sharePolicyAt(t, d, scope, at)
		if err != nil {
			t.Fatal(err)
		}
		update, err := visitorlease.Decode(body)
		if err != nil {
			t.Fatal(err)
		}
		_, verifyErr := visitortoken.VerifyBearer(token, update.View, at)
		_, sourceErr := d.IssueVisitorToken(t.Context(), testVisitorIssuer, scope, GrantTokenSource{Credential: token.Reveal()}, at)
		if want && (verifyErr != nil || sourceErr != nil) {
			t.Fatal("durable credential required replacement", verifyErr, sourceErr)
		}
		if !want && (!errors.Is(verifyErr, visitortoken.ErrToken) || !errors.Is(sourceErr, ErrVisitorPermission)) {
			t.Fatal("projection and browser exchange authority diverged", verifyErr, sourceErr)
		}
		return update.View
	}
	first := read(now, true)
	verified, err := visitortoken.VerifyBearer(token, first, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.RevokeControlSession(ctx, principal, now); err != nil {
		t.Fatal(err)
	}
	if _, err := d.CreateServiceHTTPGrant(t.Context(), service.ID, principal.IdentityID, input, now); err != nil {
		t.Fatal(err)
	}
	current := read(now.Add(6*24*time.Hour), true)
	if err := visitortoken.CheckCurrent(verified, current, now.Add(6*24*time.Hour)); err != nil {
		t.Fatal("unrelated policy or sign-in revocation canceled delegated service permission", err)
	}
	if err := d.RevokeServiceHTTPGrant(t.Context(), service.ID, principal.IdentityID, credential.GrantId, now); err != nil {
		t.Fatal(err)
	}
	read(now, false)
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.service_http_grants SET revoked_at=NULL WHERE id=$1`, credential.GrantId); err != nil {
		t.Fatal(err)
	}
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.visitor_grants SET revoked_at=$2 WHERE service_id=$1`, service.ID, now); err != nil {
		t.Fatal(err)
	}
	read(now, false)
}

func TestIntegrationVisitorServiceGrantCreationAndProjectionAreBounded(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "service_grant_bounds")
	r := oidcRouteRequest(t, d, now)
	service, err := d.CreateServiceAt(t.Context(), r.TeamID, r.ActingIdentityID, "bounds", "bounds", ServicePlacement{}, now, ServiceMetadata{Protocol: "http"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.pool.Exec(t.Context(), `INSERT INTO control.service_http_grants(id,service_id,kind,secret_digest,created_by_identity_id,expires_at)
	    SELECT 'shg_'||lpad(n::text,22,'0'),$1,'token',sha256(convert_to(n::text,'UTF8')),$2,$3::timestamptz+interval '7 days' FROM generate_series(1,256) n`, service.ID, r.ActingIdentityID, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.PrepareVisitorSigningKeys(t.Context(), testVisitorIssuer, now); err != nil {
		t.Fatal(err)
	}
	scope := visitorscope.Scope{Kind: visitorscope.Service, ID: service.ID}
	body, err := sharePolicyAt(t, d, scope, now)
	if err != nil || len(body.Policy.GrantVerifiers) != 256 {
		t.Fatal("maximum service verifiers were truncated", err)
	}
	if _, err := visitorlease.Decode(body); err != nil {
		t.Fatal(err)
	}
	if _, err := d.CreateServiceHTTPGrant(t.Context(), service.ID, r.ActingIdentityID, controlv1.CreateVisitorCredentialRequest{Resource: controlv1.VisitorResourceScope{Kind: "service", Id: service.ID}, Kind: "token", ExpiresAt: now.Add(time.Hour)}, now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("creation exceeded the projection bound", err)
	}
	_, err = d.pool.Exec(t.Context(), `INSERT INTO control.service_http_grants(id,service_id,kind,secret_digest,created_by_identity_id,expires_at)
	    SELECT 'shg_'||lpad('257',22,'0'),$1,'token',sha256(convert_to('257','UTF8')),$2,$3::timestamptz+interval '7 days'`, service.ID, r.ActingIdentityID, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sharePolicyAt(t, d, scope, now); !errors.Is(err, ErrVisitorPolicy) {
		t.Fatal("projection overflow did not fail closed", err)
	}
}
