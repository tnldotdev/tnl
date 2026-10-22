package controlapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/oidcauth"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

const serviceOwnerSub = "11111111-1111-4111-8111-111111111111"
const serviceRecipientSub = "22222222-2222-4222-8222-222222222222"

func (f *companyHTTPFixture) serviceToken(sub, method, target string, raw []byte, changes map[string]any) string {
	f.t.Helper()
	f.sequence++
	claims := map[string]any{"iss": f.issuer.URL, "sub": sub, "aud": "tnl-control", "name": "Service user", "nonce": controlstate.ServiceActorNonce(method, target, raw), "iat": f.now.Unix(), "exp": f.now.Add(5 * time.Minute).Unix(), "jti": fmt.Sprintf("service-%d", f.sequence), "email": "recipient@example.test", "email_verified": true, "roles": []string{"owner", "admin"}}
	for k, v := range changes {
		claims[k] = v
	}
	return f.signer.Token(f.t, "key-1", claims)
}

func (f *companyHTTPFixture) serviceCall(method, target, sub string, body any, changes map[string]any) *httptest.ResponseRecorder {
	f.t.Helper()
	var raw []byte
	if body != nil {
		raw = f.encode(body)
	}
	return f.serviceRaw(method, target, companyWebsiteSecret, f.serviceToken(sub, method, target, raw, changes), raw)
}

func (f *companyHTTPFixture) serviceRaw(method, target, bearer, actor string, raw []byte) *httptest.ResponseRecorder {
	return f.serviceRawKey(method, target, bearer, actor, raw, fmt.Sprintf("operation-%d", f.sequence))
}

func (f *companyHTTPFixture) serviceRawKey(method, target, bearer, actor string, raw []byte, key string) *httptest.ResponseRecorder {
	f.t.Helper()
	r := httptest.NewRequest(method, target, bytes.NewReader(raw))
	r.Header.Set("Authorization", "Bearer "+bearer)
	if actor != "" {
		r.Header.Set("X-Tnl-Actor-Token", actor)
	}
	r.Header.Set("Content-Type", "application/json")
	if method == "POST" {
		r.Header.Set("Idempotency-Key", key)
	}
	w := httptest.NewRecorder()
	f.mux.ServeHTTP(w, r)
	return w
}

func serviceResult(t *testing.T, w *httptest.ResponseRecorder, status int, out any) {
	t.Helper()
	if w.Code != status {
		t.Fatalf("service operation returned HTTP %d; want %d", w.Code, status)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("service response is cacheable")
	}
	if out != nil {
		if err := json.Unmarshal(w.Body.Bytes(), out); err != nil {
			t.Fatal("invalid service response", err)
		}
	}
}

func serviceProblem(t *testing.T, w *httptest.ResponseRecorder, status int, code authorityv1.ProblemCode) {
	t.Helper()
	var problem authorityv1.Problem
	serviceResult(t, w, status, &problem)
	if problem.Code != code {
		t.Fatalf("problem code %s; want %s", problem.Code, code)
	}
}

func serviceFixture(t *testing.T) (*companyHTTPFixture, authorityv1.ControlSessionResponse, authorityv1.ControlSessionResponse, controlstate.Team, controlstate.PrivateServiceRecord) {
	t.Helper()
	f := newCompanyHTTPFixture(t, "service_actor")
	owner, recipient := f.basic(serviceOwnerSub), f.basic(serviceRecipientSub)
	team, err := f.d.CreateTeam(t.Context(), controlstate.CreateTeamRequest{IdentityID: owner.Identity.Identity.Id, DisplayName: "service-team", MemberSlug: "owner", IdempotencyKey: "team", RequestDigest: sha256.Sum256([]byte("team"))}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	service, err := f.d.CreatePrivateService(t.Context(), team.ID, owner.Identity.Identity.Id, "api", "service", f.now, controlstate.PrivateServiceMetadata{Protocol: "http"})
	if err != nil {
		t.Fatal(err)
	}
	return f, owner, recipient, team, service
}

func TestIntegrationServiceActorRequestBindingAndCurrentManager(t *testing.T) {
	f, owner, recipient, team, service := serviceFixture(t)
	target := "/v1/service/teams/" + team.ID + "/private-services"
	base := "/v1/service/private-services/" + service.ID
	if _, err := f.sql.Exec(t.Context(), `INSERT INTO control.local_project_services(team_id,project_key,source_fingerprint,service,worktree_key,private_service_id,created_by_identity_id) VALUES($1,'project-key',$2,'api','checkout-key',$3,$4)`, team.ID, strings.Repeat("a", 64), service.ID, owner.Identity.Identity.Id); err != nil {
		t.Fatal(err)
	}
	// use actual generated HTTP operations as well as raw substitution probes.
	client, err := authorityv1.NewClientWithResponses(f.server.URL, authorityv1.WithHTTPClient(f.server.Client()), authorityv1.WithRequestEditorFn(func(_ context.Context, r *http.Request) error {
		r.Header.Set("Authorization", "Bearer "+companyWebsiteSecret)
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	assertion := f.serviceToken(serviceOwnerSub, "GET", target, nil, nil)
	response, err := client.ListWebsitePrivateServicesWithResponse(t.Context(), team.ID, &authorityv1.ListWebsitePrivateServicesParams{XTnlActorToken: assertion})
	if err != nil || response.JSON200 == nil || len(response.JSON200.Services) != 1 || response.JSON200.Services[0].Id != service.ID {
		t.Fatal("generated signed inventory failed", err)
	}
	if source := response.JSON200.Services[0].Source; source == nil || source.ProjectKey != "project-key" || source.WorktreeKey != "checkout-key" || source.Service != "api" || source.SourceFingerprint != strings.Repeat("a", 64) {
		t.Fatal("inventory lost source context")
	}
	serviceProblem(t, f.serviceRaw("GET", target, companyWebsiteSecret, assertion, nil), 401, authorityv1.Unauthenticated)
	for _, path := range []string{target, base, base + "/grants", base + "/invitations", base + "/http-grants", base + "/grants?cursor=psgr_0000000000000000000100", base + "/invitations?cursor=psivt_0000000000000000000100"} {
		// generated required-header parsing may reject before the handler.
		if w := f.serviceRaw("GET", path, companyWebsiteSecret, "", nil); w.Code < 400 {
			t.Fatal("website credential alone authorized service access")
		}
		serviceProblem(t, f.serviceCall("GET", path, serviceRecipientSub, nil, nil), 403, authorityv1.ManagerRequired)
		serviceResult(t, f.serviceCall("GET", path, serviceOwnerSub, nil, nil), 200, nil)
	}
	for name, changes := range map[string]map[string]any{
		"issuer": {"iss": "https://wrong.example"}, "audience": {"aud": "another-client"},
		"nonce": {"nonce": "unbound"}, "company purpose": {"nonce": controlstate.CompanyActorNonce("GET", target, nil)},
		"missing JTI": {"jti": ""}, "old assertion": {"iat": f.now.Add(-6 * time.Minute).Unix()},
		"long lifetime": {"exp": f.now.Add(6 * time.Minute).Unix()},
	} {
		t.Run(name, func(t *testing.T) {
			serviceProblem(t, f.serviceCall("GET", target, serviceOwnerSub, nil, changes), 401, authorityv1.Unauthenticated)
		})
	}
	serviceProblem(t, f.serviceRaw("GET", base, companyWebsiteSecret, f.serviceToken(serviceOwnerSub, "GET", target, nil, nil), nil), 401, authorityv1.Unauthenticated)
	serviceProblem(t, f.serviceRaw("DELETE", base+"/grants/psg_0123456789ABCDEFGHIJKL", companyWebsiteSecret, f.serviceToken(serviceOwnerSub, "GET", base+"/grants/psg_0123456789ABCDEFGHIJKL", nil, nil), nil), 401, authorityv1.Unauthenticated)
	serviceProblem(t, f.serviceRaw("GET", target+"?cursor="+service.ID, companyWebsiteSecret, f.serviceToken(serviceOwnerSub, "GET", target, nil, nil), nil), 401, authorityv1.Unauthenticated)
	body := f.encode(controlv1.CreatePrivateServiceInvitationRequest{Email: "recipient@example.test", ExpiresAt: f.now.Add(time.Hour)})
	for _, op := range []struct {
		method, target string
		raw            []byte
	}{
		{"POST", base + "/invitations", body},
		{"POST", base + "/http-grants", f.encode(controlv1.CreateManagedHTTPGrantRequest{Kind: "token", ExpiresAt: f.now.Add(time.Hour)})},
		{"POST", "/v1/service/private-service-invitations/preview", f.encode(authorityv1.PrivateServiceInvitationCredential{Secret: strings.Repeat("A", 64)})},
		{"POST", "/v1/service/private-service-invitations/accept", f.encode(authorityv1.PrivateServiceInvitationCredential{Secret: strings.Repeat("A", 64)})},
		{"DELETE", base + "/grants/psg_0123456789ABCDEFGHIJKL", nil},
		{"DELETE", base + "/invitations/psi_0123456789ABCDEFGHIJKL", nil},
		{"DELETE", base + "/http-grants/mhg_0123456789ABCDEFGHIJKL", nil},
	} {
		if w := f.serviceRaw(op.method, op.target, companyWebsiteSecret, "", op.raw); w.Code < 400 {
			t.Fatal("website credential alone mutated service access")
		}
	}
	serviceProblem(t, f.serviceRaw("POST", base+"/invitations", companyWebsiteSecret, f.serviceToken(serviceOwnerSub, "POST", base+"/invitations", body, nil), append(body, ' ')), 401, authorityv1.Unauthenticated)
	jti := map[string]any{"jti": "one-operation-only"}
	serviceResult(t, f.serviceCall("GET", base, serviceOwnerSub, nil, jti), 200, nil)
	serviceProblem(t, f.serviceCall("GET", base+"/grants", serviceOwnerSub, nil, jti), 401, authorityv1.Unauthenticated)
	// no service assertion authenticates the existing public URL control API.
	public, err := NewHandler(Config{}, f.d, f.d, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/v1/public-urls", nil)
	r.Header.Set("Authorization", "Bearer "+companyWebsiteSecret)
	r.Header.Set("X-Tnl-Actor-Token", f.serviceToken(serviceOwnerSub, "GET", "/v1/public-urls", nil, nil))
	w := httptest.NewRecorder()
	public.ServeHTTP(w, r)
	if w.Code < 400 {
		t.Fatal("service proof authenticated public URL operation")
	}
	serviceProblem(t, f.serviceCall("GET", "/v1/service/private-services/purl_0123456789ABCDEFGHIJKL", serviceOwnerSub, nil, nil), 403, authorityv1.Forbidden)
	// page state and issuer-signed role strings are not management permission.
	var member string
	if err = f.sql.QueryRow(t.Context(), `SELECT id FROM control.team_memberships WHERE team_id=$1 AND identity_id=$2`, team.ID, owner.Identity.Identity.Id).Scan(&member); err != nil {
		t.Fatal(err)
	}
	stalePageToken := f.serviceToken(serviceOwnerSub, "GET", target, nil, nil)
	if _, err = f.sql.Exec(t.Context(), `UPDATE control.team_memberships SET role='member' WHERE id=$1`, member); err != nil {
		t.Fatal(err)
	}
	serviceProblem(t, f.serviceRaw("GET", target, companyWebsiteSecret, stalePageToken, nil), 403, authorityv1.ManagerRequired)
	serviceProblem(t, f.serviceCall("POST", base+"/invitations", serviceOwnerSub, controlv1.CreatePrivateServiceInvitationRequest{Email: "recipient@example.test", ExpiresAt: f.now.Add(time.Hour)}, nil), 403, authorityv1.ManagerRequired)
	serviceProblem(t, f.serviceCall("GET", "/v1/service/teams/"+recipient.Identity.PersonalTeamId+"/private-services", serviceOwnerSub, nil, nil), 403, authorityv1.ManagerRequired)
	if _, err = f.sql.Exec(t.Context(), `UPDATE control.identities SET disabled_at=CURRENT_TIMESTAMP WHERE id=$1`, owner.Identity.Identity.Id); err != nil {
		t.Fatal(err)
	}
	serviceProblem(t, f.serviceCall("GET", base, serviceOwnerSub, nil, nil), 401, authorityv1.Unauthenticated)
}

func TestIntegrationServiceActorInvitationAndManagedHTTPLifecycle(t *testing.T) {
	f, owner, recipient, team, service := serviceFixture(t)
	base := "/v1/service/private-services/" + service.ID
	deadline := f.now.Add(time.Hour).Truncate(time.Microsecond)
	create := controlv1.CreatePrivateServiceInvitationRequest{Email: "recipient@example.test", ExpiresAt: deadline}
	var invitation controlv1.PrivateServiceInvitation
	serviceResult(t, f.serviceCall("POST", base+"/invitations", serviceOwnerSub, create, nil), 201, &invitation)
	if invitation.Secret == nil {
		t.Fatal("creation omitted invitation secret")
	}
	credential := authorityv1.PrivateServiceInvitationCredential{Secret: *invitation.Secret}
	preview, accept := "/v1/service/private-service-invitations/preview", "/v1/service/private-service-invitations/accept"
	// acceptance derives current email from the issuer, not this stored snapshot.
	if _, err := f.sql.Exec(t.Context(), `UPDATE control.identities SET normalized_email='stale@example.test',email_verified=false WHERE id=$1`, recipient.Identity.Identity.Id); err != nil {
		t.Fatal(err)
	}
	for _, op := range []string{preview, accept} {
		serviceProblem(t, f.serviceCall("POST", op, serviceRecipientSub, credential, map[string]any{"email": "other@example.test"}), 403, authorityv1.Forbidden)
		serviceProblem(t, f.serviceCall("POST", op, serviceRecipientSub, credential, map[string]any{"email_verified": false}), 403, authorityv1.VerifiedEmailRequired)
		bad := authorityv1.PrivateServiceInvitationCredential{Secret: strings.Split(credential.Secret, ".")[0] + "." + strings.Repeat("A", 43)}
		w := f.serviceCall("POST", op, serviceRecipientSub, bad, nil)
		serviceProblem(t, w, 403, authorityv1.Forbidden)
		if strings.Contains(w.Body.String(), service.ID) || strings.Contains(w.Body.String(), "recipient@example.test") {
			t.Fatal("invalid secret leaked invitation metadata")
		}
	}
	var projected authorityv1.PrivateServiceInvitationPreview
	serviceResult(t, f.serviceCall("POST", preview, serviceRecipientSub, credential, nil), 200, &projected)
	if projected.PrivateServiceId != service.ID || projected.TeamId != team.ID || !projected.ExpiresAt.Equal(deadline) || projected.Name != service.Name {
		t.Fatal("preview changed service or deadline")
	}
	var pending bool
	if err := f.sql.QueryRow(t.Context(), `SELECT accepted_at IS NULL FROM control.private_service_invitations WHERE id=$1`, invitation.Id).Scan(&pending); err != nil || !pending {
		t.Fatal("preview accepted invitation", err)
	}
	var grant controlv1.PrivateServiceGrant
	serviceResult(t, f.serviceCall("POST", accept, serviceRecipientSub, credential, nil), 200, &grant)
	if grant.PrivateServiceId != service.ID || grant.IdentityId == nil || *grant.IdentityId != recipient.Identity.Identity.Id || grant.Kind != "identity" || grant.ExpiresAt == nil || !grant.ExpiresAt.Equal(deadline) {
		t.Fatal("acceptance changed exact grant scope or deadline")
	}
	var members int
	if err := f.sql.QueryRow(t.Context(), `SELECT count(*) FROM control.team_memberships WHERE team_id=$1 AND identity_id=$2`, team.ID, recipient.Identity.Identity.Id).Scan(&members); err != nil || members != 0 {
		t.Fatal("acceptance created membership", err)
	}
	listed := f.serviceCall("GET", base+"/invitations", serviceOwnerSub, nil, nil)
	serviceResult(t, listed, 200, nil)
	if strings.Contains(listed.Body.String(), *invitation.Secret) || strings.Contains(listed.Body.String(), `"secret"`) {
		t.Fatal("list exposed invitation secret")
	}
	serviceProblem(t, f.serviceCall("POST", accept, serviceRecipientSub, credential, nil), 403, authorityv1.Forbidden)
	serviceResult(t, f.serviceCall("DELETE", base+"/invitations/"+invitation.Id, serviceOwnerSub, nil, nil), 204, nil)
	grants, _, err := f.d.ListPrivateServiceGrants(t.Context(), service.ID, owner.Identity.Identity.Id, "")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, g := range grants {
		if g.ID == grant.Id {
			found = g.RevokedAt != nil
		}
	}
	if !found {
		t.Fatal("invitation revoke did not revoke the existing accepted grant")
	}
	var httpGrant controlv1.ManagedHTTPGrant
	serviceResult(t, f.serviceCall("POST", base+"/http-grants", serviceOwnerSub, controlv1.CreateManagedHTTPGrantRequest{Kind: "token", ExpiresAt: deadline}, nil), 201, &httpGrant)
	var summaries []controlv1.ManagedHTTPGrantSummary
	listed = f.serviceCall("GET", base+"/http-grants", serviceOwnerSub, nil, nil)
	serviceResult(t, listed, 200, &summaries)
	if len(summaries) != 1 || summaries[0].Id != httpGrant.Id || summaries[0].Subject.Kind != "managed_service" || summaries[0].Subject.Id != service.ID || strings.Contains(listed.Body.String(), httpGrant.Secret) || strings.Contains(listed.Body.String(), `"secret"`) {
		t.Fatal("HTTP inventory lost exact owned ID or exposed secret")
	}
	native, err := NewHandler(Config{}, f.d, f.d, nil)
	if err != nil {
		t.Fatal(err)
	}
	nativeServer := httptest.NewServer(native)
	t.Cleanup(nativeServer.Close)
	nativeClient, err := controlv1.NewClientWithResponses(nativeServer.URL, controlv1.WithRequestEditorFn(func(_ context.Context, r *http.Request) error {
		r.Header.Set("Authorization", "Bearer "+owner.AccessToken)
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	nativeList, err := nativeClient.ListManagedHTTPGrantsWithResponse(t.Context(), service.ID)
	if err != nil || nativeList.JSON200 == nil || len(*nativeList.JSON200) != 1 || (*nativeList.JSON200)[0].Id != httpGrant.Id || bytes.Contains(nativeList.Body, []byte(httpGrant.Secret)) {
		t.Fatal("native HTTP grant inventory did not expose the owned secretless ID", err)
	}
	other, err := f.d.CreatePrivateService(t.Context(), team.ID, owner.Identity.Identity.Id, "other", "other", f.now)
	if err != nil {
		t.Fatal(err)
	}
	serviceProblem(t, f.serviceCall("DELETE", "/v1/service/private-services/"+other.ID+"/http-grants/"+httpGrant.Id, serviceOwnerSub, nil, nil), 403, authorityv1.Forbidden)
	serviceProblem(t, f.serviceCall("DELETE", base+"/grants/"+httpGrant.Id, serviceOwnerSub, nil, nil), 403, authorityv1.Forbidden)
	serviceResult(t, f.serviceCall("DELETE", base+"/http-grants/"+httpGrant.Id, serviceOwnerSub, nil, nil), 204, nil)
	serviceResult(t, f.serviceCall("GET", base+"/http-grants", serviceOwnerSub, nil, nil), 200, &summaries)
	if summaries[0].RevokedAt == nil {
		t.Fatal("HTTP revocation disappeared from inventory")
	}
	// the bridge cannot turn management permission alone into visit access.
	if _, err = f.sql.Exec(t.Context(), `UPDATE control.private_service_grants SET revoked_at=$2 WHERE private_service_id=$1`, service.ID, f.now); err != nil {
		t.Fatal(err)
	}
	if w := f.serviceCall("POST", base+"/http-grants", serviceOwnerSub, controlv1.CreateManagedHTTPGrantRequest{Kind: "share", ExpiresAt: deadline}, nil); w.Code < 400 {
		t.Fatal("manager without current visit access issued HTTP credential")
	}
	// direct grant revocation uses the same stored grant and exact service ID.
	direct, err := f.d.CreatePrivateServiceGrant(t.Context(), other.ID, owner.Identity.Identity.Id, "direct", "identity", recipient.Identity.Identity.Id, &deadline, f.now)
	if err != nil {
		t.Fatal(err)
	}
	serviceProblem(t, f.serviceCall("DELETE", base+"/grants/"+direct.ID, serviceOwnerSub, nil, nil), 403, authorityv1.Forbidden)
	serviceResult(t, f.serviceCall("DELETE", "/v1/service/private-services/"+other.ID+"/grants/"+direct.ID, serviceOwnerSub, nil, nil), 204, nil)
	// expired invitation metadata is indistinguishable from an invalid secret.
	serviceResult(t, f.serviceCall("POST", base+"/invitations", serviceOwnerSub, create, nil), 201, &invitation)
	if _, err = f.sql.Exec(t.Context(), `UPDATE control.private_service_invitations SET created_at=$2::timestamptz-interval '2 hours',expires_at=$2::timestamptz-interval '1 hour' WHERE id=$1`, invitation.Id, f.now); err != nil {
		t.Fatal(err)
	}
	for _, op := range []string{preview, accept} {
		serviceProblem(t, f.serviceCall("POST", op, serviceRecipientSub, authorityv1.PrivateServiceInvitationCredential{Secret: *invitation.Secret}, nil), 403, authorityv1.Forbidden)
	}
}

func TestIntegrationServiceActorCurrentCompanySource(t *testing.T) {
	f, owner, _, team, service := serviceFixture(t)
	connections := "/v1/service/teams/" + team.ID + "/identity-connections"
	var setup controlstate.IdentityConnectionSetup
	serviceResult(t, f.ownerCall("POST", connections, serviceOwnerSub, nil, authorityv1.CreateIdentityConnectionRequest{Admission: "approval", SourceId: "source-one"}), 201, &setup)
	if err := f.d.ProvisionCompanyEligibility(t.Context(), setup.SetupToken, controlstate.ProvisionCompanyEligibilityRequest{TeamID: team.ID, IdentityConnectionID: setup.ID, ConnectionRevision: setup.Revision, IdentityID: owner.Identity.Identity.Id, Subject: "directory-owner", Revision: 1, Eligible: true, ValidUntil: f.now.Add(4 * time.Hour)}, f.now); err != nil {
		t.Fatal(err)
	}
	var active controlstate.IdentityConnectionSecret
	serviceResult(t, f.ownerCall("POST", connections+"/"+setup.ID+"/activate", serviceOwnerSub, f.proof(setup.IdentityConnection, "directory-owner"), map[string]any{"setup_token": setup.SetupToken, "expected_revision": setup.Revision}), 200, &active)
	target := "/v1/service/teams/" + team.ID + "/private-services"
	base := "/v1/service/private-services/" + service.ID
	proofs := f.proof(active.IdentityConnection, "directory-owner")
	valid := map[string]any{"tnl_team_contexts": proofs}
	for _, path := range []string{target, base, base + "/grants", base + "/invitations", base + "/http-grants", base + "/grants?cursor=psgr_0000000000000000000100", base + "/invitations?cursor=psivt_0000000000000000000100"} {
		serviceProblem(t, f.serviceCall("GET", path, serviceOwnerSub, nil, nil), 403, authorityv1.SourceSignInRequired)
		serviceResult(t, f.serviceCall("GET", path, serviceOwnerSub, nil, valid), 200, nil)
	}
	for name, change := range map[string]func(*oidcauth.TeamContext){
		"wrong source":  func(c *oidcauth.TeamContext) { c.SourceID = "source-two" },
		"old revision":  func(c *oidcauth.TeamContext) { c.ConnectionRevision++ },
		"wrong subject": func(c *oidcauth.TeamContext) { c.Subject = "someone-else" },
		"stale event":   func(c *oidcauth.TeamContext) { c.AuthenticatedAt = f.now.Add(-2 * time.Hour).Unix() },
		"wrong team":    func(c *oidcauth.TeamContext) { c.TeamID = owner.Identity.PersonalTeamId },
	} {
		t.Run(name, func(t *testing.T) {
			bad := append([]oidcauth.TeamContext(nil), proofs...)
			change(&bad[0])
			serviceProblem(t, f.serviceCall("GET", target, serviceOwnerSub, nil, map[string]any{"tnl_team_contexts": bad}), 403, authorityv1.SourceSignInRequired)
		})
	}
	// signed service management does not mint a session to back HTTP credentials.
	serviceProblem(t, f.serviceCall("POST", base+"/http-grants", serviceOwnerSub, controlv1.CreateManagedHTTPGrantRequest{Kind: "token", ExpiresAt: f.now.Add(time.Hour)}, valid), 403, authorityv1.SourceSignInRequired)
	invitationBody := f.encode(controlv1.CreatePrivateServiceInvitationRequest{Email: "recipient@example.test", ExpiresAt: f.now.Add(time.Hour)})
	retryInvitation := func() *httptest.ResponseRecorder {
		token := f.serviceToken(serviceOwnerSub, "POST", base+"/invitations", invitationBody, valid)
		return f.serviceRawKey("POST", base+"/invitations", companyWebsiteSecret, token, invitationBody, "source-bound-retry")
	}
	serviceResult(t, retryInvitation(), 201, nil)
	serviceResult(t, retryInvitation(), 200, nil)
	pageProof := f.serviceToken(serviceOwnerSub, "GET", target, nil, valid)
	if _, err := f.sql.Exec(t.Context(), `UPDATE control.company_eligibility SET eligible=false WHERE identity_connection_id=$1`, active.ID); err != nil {
		t.Fatal(err)
	}
	serviceProblem(t, f.serviceRaw("GET", target, companyWebsiteSecret, pageProof, nil), 403, authorityv1.SourceSignInRequired)
	serviceProblem(t, retryInvitation(), 403, authorityv1.SourceSignInRequired)
	if _, err := f.sql.Exec(t.Context(), `UPDATE control.company_eligibility SET eligible=true WHERE identity_connection_id=$1`, active.ID); err != nil {
		t.Fatal(err)
	}
	serviceResult(t, f.serviceCall("GET", target, serviceOwnerSub, nil, valid), 200, nil)
	serviceResult(t, retryInvitation(), 200, nil)
	if _, err := f.sql.Exec(t.Context(), `UPDATE control.identity_connections SET state='retired',revision=revision+1 WHERE id=$1`, active.ID); err != nil {
		t.Fatal(err)
	}
	serviceProblem(t, f.serviceCall("GET", target, serviceOwnerSub, nil, valid), 403, authorityv1.SourceSignInRequired)
	serviceProblem(t, retryInvitation(), 403, authorityv1.SourceSignInRequired)
	// company configuration recovery remains separate from service authority.
	serviceResult(t, f.ownerCall("GET", connections, serviceOwnerSub, nil, nil), 200, nil)
}

func TestIntegrationServiceActorAccessPagination(t *testing.T) {
	f, owner, recipient, team, service := serviceFixture(t)
	ctx := t.Context()
	base := "/v1/service/private-services/" + service.ID
	// mixed-case IDs must follow bytewise cursor order, independently of database
	// locale. live access must remain discoverable beyond revoked history without
	// adding management or membership to its visitor.
	for _, query := range []string{
		`INSERT INTO control.private_service_grants(id,private_service_id,team_id,kind,identity_id,created_by_identity_id,idempotency_key,request_digest,created_at,expires_at,revoked_at)
		 SELECT 'psgr_'||(CASE WHEN n%2=0 THEN 'A' ELSE 'a' END)||lpad(n::text,21,'0'),$1,$2,'identity',$4,$3,'page-grant/'||n,sha256(convert_to('grant/'||n,'UTF8')),$5::timestamptz-interval '2 hours',
		 CASE WHEN n BETWEEN 121 AND 140 THEN $5::timestamptz-interval '1 hour' ELSE $5::timestamptz+interval '1 hour' END,
		 CASE WHEN n<=120 THEN $5::timestamptz END FROM generate_series(1,205) n`,
		`INSERT INTO control.private_service_invitations(id,private_service_id,team_id,normalized_email,token_digest,created_by_identity_id,idempotency_key,request_digest,created_at,expires_at,revoked_at)
		 SELECT 'psivt_'||(CASE WHEN n%2=0 THEN 'A' ELSE 'a' END)||lpad(n::text,21,'0'),$1,$2,'recipient@example.test',sha256(convert_to('token/'||n,'UTF8')),$3,'page-invite/'||n,sha256(convert_to('request/'||n,'UTF8')),$5::timestamptz-interval '2 hours',
		 CASE WHEN n BETWEEN 121 AND 140 THEN $5::timestamptz-interval '1 hour' ELSE $5::timestamptz+interval '1 hour' END,
		 CASE WHEN n<=120 THEN $5::timestamptz END FROM generate_series(1,205) n WHERE $4::text<>''`,
	} {
		if _, err := f.sql.Exec(ctx, query, service.ID, team.ID, owner.Identity.Identity.Id, recipient.Identity.Identity.Id, f.now); err != nil {
			t.Fatal(err)
		}
	}
	for _, kind := range []string{"grants", "invitations"} {
		t.Run(kind, func(t *testing.T) {
			target, cursor, pages, total, active := base+"/"+kind, "", 0, 0, 0
			for {
				path := target
				if cursor != "" {
					path += "?cursor=" + cursor
				}
				var next *string
				listed := f.serviceCall("GET", path, serviceOwnerSub, nil, nil)
				if kind == "grants" {
					var page controlv1.PrivateServiceGrantPage
					serviceResult(t, listed, 200, &page)
					if len(page.Grants) > 100 {
						t.Fatal("unbounded grant page")
					}
					for _, row := range page.Grants {
						if row.Id <= cursor || row.PrivateServiceId != service.ID {
							t.Fatal("grant scope or cursor overlap")
						}
						cursor = row.Id
						if row.RevokedAt == nil && (row.ExpiresAt == nil || row.ExpiresAt.After(f.now)) {
							active++
						}
					}
					total += len(page.Grants)
					next = page.NextCursor
				} else {
					var page controlv1.PrivateServiceInvitationPage
					serviceResult(t, listed, 200, &page)
					if len(page.Invitations) > 100 || strings.Contains(listed.Body.String(), `"secret"`) || strings.Contains(listed.Body.String(), "token_digest") {
						t.Fatal("unbounded or secret-bearing invitation page")
					}
					for _, row := range page.Invitations {
						if row.Id <= cursor || row.PrivateServiceId != service.ID {
							t.Fatal("invitation scope or cursor overlap")
						}
						cursor = row.Id
						if row.RevokedAt == nil && row.ExpiresAt.After(f.now) {
							active++
						}
					}
					total += len(page.Invitations)
					next = page.NextCursor
				}
				pages++
				if next == nil {
					break
				}
				if *next != cursor || pages > 3 {
					t.Fatal("nonprogressing cursor")
				}
				// the old proof cannot authorize a new page or the other list.
				assertion := f.serviceToken(serviceOwnerSub, "GET", target, nil, nil)
				serviceProblem(t, f.serviceRaw("GET", target+"?cursor="+cursor, companyWebsiteSecret, assertion, nil), 401, authorityv1.Unauthenticated)
			}
			want := 205
			if kind == "grants" {
				want++ // the creator's separate exact-service owner grant.
			}
			if total != want || pages != 3 || active < 65 {
				t.Fatalf("lost access after revoked history: total=%d pages=%d active=%d", total, pages, active)
			}
			serviceProblem(t, f.serviceCall("GET", target+"?cursor="+cursor, serviceRecipientSub, nil, nil), 403, authorityv1.ManagerRequired)
			serviceProblem(t, f.serviceCall("GET", target+"?cursor=invalid", serviceOwnerSub, nil, nil), 403, authorityv1.Forbidden)
		})
	}
	// management inventory never becomes visitor permission. revoked/expired
	// grants disappear from visitor inventory despite remaining in the audit list.
	if _, err := f.sql.Exec(ctx, `UPDATE control.private_service_grants SET revoked_at=$2 WHERE private_service_id=$1`, service.ID, f.now); err != nil {
		t.Fatal(err)
	}
	if rows, _, err := f.d.ListAvailablePrivateServices(ctx, recipient.Identity.Identity.Id, "", f.now); err != nil || len(rows) != 0 {
		t.Fatal("grant history became visitor access", err)
	}
	serviceResult(t, f.serviceCall("GET", base+"/grants", serviceOwnerSub, nil, nil), 200, nil)
	if _, err := f.sql.Exec(ctx, `UPDATE control.team_memberships SET role='member' WHERE team_id=$1 AND identity_id=$2`, team.ID, owner.Identity.Identity.Id); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{base + "/grants?cursor=psgr_0000000000000000000100", base + "/invitations?cursor=psivt_0000000000000000000100"} {
		serviceProblem(t, f.serviceCall("GET", path, serviceOwnerSub, nil, nil), 403, authorityv1.ManagerRequired)
	}
}

func TestIntegrationServiceActorInvitationLostResponse(t *testing.T) {
	f, owner, _, team, service := serviceFixture(t)
	ctx := t.Context()
	path := "/v1/service/private-services/" + service.ID + "/invitations"
	body := controlv1.CreatePrivateServiceInvitationRequest{Email: "recipient@example.test", ExpiresAt: f.now.Add(time.Hour).Truncate(time.Microsecond)}
	call := func(target, sub, key string, body controlv1.CreatePrivateServiceInvitationRequest, changes map[string]any) *httptest.ResponseRecorder {
		raw := f.encode(body)
		return f.serviceRawKey("POST", target, companyWebsiteSecret, f.serviceToken(sub, "POST", target, raw, changes), raw, key)
	}
	// discard the committed creation response, then retry with a fresh proof.
	serviceResult(t, call(path, serviceOwnerSub, "lost-response", body, nil), 201, nil)
	var originalID string
	if err := f.sql.QueryRow(ctx, `SELECT id FROM control.private_service_invitations WHERE created_by_identity_id=$1 AND idempotency_key='lost-response'`, owner.Identity.Identity.Id).Scan(&originalID); err != nil {
		t.Fatal(err)
	}
	var retry controlv1.PrivateServiceInvitation
	serviceResult(t, call(path, serviceOwnerSub, "lost-response", body, nil), 200, &retry)
	if retry.Id != originalID || retry.Secret != nil || retry.PrivateServiceId != service.ID || !retry.ExpiresAt.Equal(body.ExpiresAt) {
		t.Fatal("retry did not recover exact secretless metadata")
	}
	raw := f.encode(body)
	assertion := f.serviceToken(serviceOwnerSub, "POST", path, raw, nil)
	serviceResult(t, f.serviceRawKey("POST", path, companyWebsiteSecret, assertion, raw, "lost-response"), 200, nil)
	serviceProblem(t, f.serviceRawKey("POST", path, companyWebsiteSecret, assertion, raw, "lost-response"), 401, authorityv1.Unauthenticated)
	for _, changed := range []controlv1.CreatePrivateServiceInvitationRequest{
		{Email: "other@example.test", ExpiresAt: body.ExpiresAt},
		{Email: body.Email, ExpiresAt: body.ExpiresAt.Add(time.Minute)},
	} {
		serviceProblem(t, call(path, serviceOwnerSub, "lost-response", changed, nil), 409, authorityv1.Conflict)
	}
	other, err := f.d.CreatePrivateService(ctx, team.ID, owner.Identity.Identity.Id, "other", "other", f.now)
	if err != nil {
		t.Fatal(err)
	}
	serviceProblem(t, call("/v1/service/private-services/"+other.ID+"/invitations", serviceOwnerSub, "lost-response", body, nil), 409, authorityv1.Conflict)
	serviceProblem(t, call(path, serviceRecipientSub, "lost-response", body, nil), 403, authorityv1.ManagerRequired)
	if _, err := f.sql.Exec(ctx, `UPDATE control.team_memberships SET manual_suspended_at=$3 WHERE team_id=$1 AND identity_id=$2`, team.ID, owner.Identity.Identity.Id, f.now); err != nil {
		t.Fatal(err)
	}
	serviceProblem(t, call(path, serviceOwnerSub, "lost-response", body, nil), 403, authorityv1.ManagerRequired)
	if _, err := f.sql.Exec(ctx, `UPDATE control.team_memberships SET manual_suspended_at=NULL WHERE team_id=$1 AND identity_id=$2`, team.ID, owner.Identity.Identity.Id); err != nil {
		t.Fatal(err)
	}
	serviceResult(t, f.serviceCall("DELETE", path+"/"+originalID, serviceOwnerSub, nil, nil), 204, nil)
	serviceResult(t, call(path, serviceOwnerSub, "lost-response", body, nil), 200, &retry)
	if retry.RevokedAt == nil || retry.Secret != nil {
		t.Fatal("retry revived revoked invitation")
	}
	var reissued controlv1.PrivateServiceInvitation
	serviceResult(t, call(path, serviceOwnerSub, "replacement", body, nil), 201, &reissued)
	if reissued.Id == originalID || reissued.Secret == nil {
		t.Fatal("explicit reissue did not create a new secret")
	}
	var creations int
	if err := f.sql.QueryRow(ctx, `SELECT count(*) FROM control.private_service_invitations WHERE private_service_id=$1`, service.ID).Scan(&creations); err != nil || creations != 2 {
		t.Fatal("retry/conflict created phantom invitations", err)
	}
	if err := f.sql.QueryRow(ctx, `SELECT count(*) FROM control.service_audit_events WHERE service_id=$1 AND event_type='invitation.create'`, service.ID).Scan(&creations); err != nil || creations != 2 {
		t.Fatal("retry/conflict duplicated invitation creation audit", err)
	}
}
