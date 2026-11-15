package public

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/oidc"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func registerShareActorAPI(t *testing.T, f *companyHTTPFixture) {
	t.Helper()
	verifier, err := oidc.NewVerifier(oidc.VerifierConfig{Issuer: f.issuer.URL, ClientID: "tnl-control", HTTPClient: f.issuer.Client()})
	if err != nil {
		t.Fatal(err)
	}
	h, err := NewHandler(Config{ControlURL: "https://control.example.test", OIDCIssuer: f.issuer.URL, OIDCClientID: "tnl-control",
		OIDCVerifier: verifier, OIDCScopes: []string{"openid"}, WebServiceSecret: companyWebsiteSecret, HTTPClient: f.issuer.Client()}, DatabaseStores(f.d), f.d, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.mux.Handle("/", h)
}

func TestIntegrationCanonicalShareWebsiteActor(t *testing.T) {
	f, owner, secondOwner, team, _ := serviceFixture(t)
	ctx := t.Context()
	service := serviceActorNamedService(t, f, team.ID, owner.Identity.Identity.Id)
	registerShareActorAPI(t, f)
	body := f.encode(controlv1.CreateShareRequest{ServiceIds: []string{service.ID}, EntryServiceId: service.ID, ExpiresAt: f.now.Add(time.Hour)})
	callRaw := func(method, target, actor, key string, raw []byte) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, target, bytes.NewReader(raw))
		r.Header.Set("Authorization", "Bearer "+companyWebsiteSecret)
		r.Header.Set("X-Tnl-Actor-Token", actor)
		if key != "" {
			r.Header.Set("Idempotency-Key", key)
		}
		w := httptest.NewRecorder()
		f.mux.ServeHTTP(w, r)
		return w
	}
	call := func(method, target, subject, key string, raw []byte) *httptest.ResponseRecorder {
		return callRaw(method, target, f.token(subject, controlstate.ServiceActorNonce(method, target, raw), nil), key, raw)
	}
	var beforeGrants, beforeSessions int
	if err := f.sql.QueryRow(ctx, `SELECT (SELECT count(*) FROM control.visitor_grants WHERE service_id=$1),
		(SELECT count(*) FROM control.control_sessions)`, service.ID).Scan(&beforeGrants, &beforeSessions); err != nil {
		t.Fatal(err)
	}
	created := call("POST", "/v1/shares", serviceOwnerSub, "website-share", body)
	var creation controlv1.ShareCreation
	if created.Code != 201 || json.Unmarshal(created.Body.Bytes(), &creation) != nil || created.Header().Get("Cache-Control") != "no-store" ||
		!slices.Equal(creation.Share.ServiceIds, []string{service.ID}) || creation.Share.EntryServiceId != service.ID {
		t.Fatal("signed website could not create a canonical share", created.Code)
	}
	secret, err := base64.RawURLEncoding.DecodeString(creation.TokenSource.Secret)
	var digest []byte
	var sessionless bool
	if err != nil || len(secret) != 32 {
		t.Fatal("canonical share did not deliver a complete creation-only credential", err)
	}
	if err := f.sql.QueryRow(ctx, `SELECT secret_digest,control_session_id IS NULL FROM control.shares WHERE id=$1`,
		creation.Share.Id).Scan(&digest, &sessionless); err != nil {
		t.Fatal(err)
	}
	wantDigest := sha256.Sum256(secret)
	if !bytes.Equal(digest, wantDigest[:]) || !sessionless {
		t.Fatal("signed creation changed its durable digest or fabricated a control session")
	}
	retry := call("POST", "/v1/shares", serviceOwnerSub, "website-share", body)
	var problem controlv1.Problem
	if retry.Code != 409 || json.Unmarshal(retry.Body.Bytes(), &problem) != nil ||
		problem.Code != controlv1.CredentialDeliveryUnavailable || problem.Details == nil ||
		(*problem.Details)["resource_id"] != creation.Share.Id || strings.Contains(retry.Body.String(), creation.TokenSource.Secret) {
		t.Fatal("exact signed retry reminted a share or lost the original ID", retry.Code)
	}
	listTarget := "/v1/shares?team_id=" + team.ID
	listed := call("GET", listTarget, serviceOwnerSub, "", nil)
	var page controlv1.SharePage
	if listed.Code != 200 || json.Unmarshal(listed.Body.Bytes(), &page) != nil || len(page.Shares) != 1 || page.Shares[0].Id != creation.Share.Id ||
		strings.Contains(listed.Body.String(), creation.TokenSource.Secret) || strings.Contains(listed.Body.String(), "token_source") {
		t.Fatal("signed share list lost its canonical record or exposed its secret", listed.Code)
	}
	readTarget := "/v1/shares/" + creation.Share.Id
	if got := call("GET", readTarget, serviceOwnerSub, "", nil); got.Code != 200 || strings.Contains(got.Body.String(), creation.TokenSource.Secret) {
		t.Fatal("signed share read failed or exposed its secret", got.Code)
	}
	if got := call("GET", readTarget, serviceRecipientSub, "", nil); got.Code != 404 {
		t.Fatal("another website identity read the share", got.Code)
	}
	// changing the raw query or body invalidates the proof before state work.
	bound := f.token(serviceOwnerSub, controlstate.ServiceActorNonce("GET", listTarget, nil), nil)
	if got := f.call("GET", listTarget+"&cursor="+creation.Share.Id, companyWebsiteSecret, bound, nil); got.Code != 401 {
		t.Fatal("share assertion crossed raw query boundaries", got.Code)
	}
	bound = f.token(serviceOwnerSub, controlstate.ServiceActorNonce("POST", "/v1/shares", body), nil)
	if got := callRaw("POST", "/v1/shares", bound, "body-boundary", append(bytes.Clone(body), ' ')); got.Code != 401 {
		t.Fatal("share assertion crossed body-byte boundaries", got.Code)
	}
	// successful reads consume the issuer JTI, even when re-signed for another
	// valid request. the website secret alone is never human authority.
	signJTI := func(target, name string) string {
		return f.signer.Token(t, "key-1", map[string]any{"iss": f.issuer.URL, "aud": "tnl-control", "sub": serviceOwnerSub,
			"name": name, "nonce": controlstate.ServiceActorNonce("GET", target, nil), "jti": "one-share-operation",
			"iat": f.now.Unix(), "exp": f.now.Add(time.Minute).Unix()})
	}
	if got := f.call("GET", listTarget, companyWebsiteSecret, signJTI(listTarget, "first"), nil); got.Code != 200 {
		t.Fatal("first signed share read failed", got.Code)
	}
	if got := f.call("GET", readTarget, companyWebsiteSecret, signJTI(readTarget, "resigned"), nil); got.Code != 401 {
		t.Fatal("re-signed issuer JTI authorized another share operation", got.Code)
	}
	if got := f.call("GET", listTarget, companyWebsiteSecret, "", nil); got.Code != 401 {
		t.Fatal("website credential alone listed shares", got.Code)
	}
	if got := call("GET", "/v1/services?team_id="+team.ID, serviceOwnerSub, "", nil); got.Code != 401 {
		t.Fatal("share actor proof became general control authority", got.Code)
	}
	source, err := json.Marshal(creation.TokenSource)
	if err != nil {
		t.Fatal(err)
	}
	permissionBody := f.encode(controlv1.VisitorTokenRequest{Resource: controlv1.VisitorResourceScope{Kind: controlv1.VisitorResourceScopeKindService, Id: service.ID}, Source: source})
	issued := f.call("POST", "/v1/visitor-tokens", "", "", permissionBody)
	var permission controlv1.VisitorTokenResponse
	if issued.Code != 200 || json.Unmarshal(issued.Body.Bytes(), &permission) != nil || permission.VisitorToken == "" {
		t.Fatal("canonical signed-created share did not authorize an HTTP visitor", issued.Code)
	}
	if _, err := f.d.AuthenticateAccessToken(ctx, credentials.AccessToken(permission.VisitorToken), f.now); !errors.Is(err, controlstate.ErrControlAuthentication) {
		t.Fatal("share visitor permission authenticated a control session", err)
	}
	var afterGrants, afterSessions int
	if err := f.sql.QueryRow(ctx, `SELECT (SELECT count(*) FROM control.visitor_grants WHERE service_id=$1),
		(SELECT count(*) FROM control.control_sessions)`, service.ID).Scan(&afterGrants, &afterSessions); err != nil ||
		afterGrants != beforeGrants || afterSessions != beforeSessions {
		t.Fatal("share creation or redemption minted connector grants or control sessions", err)
	}
	revokeTarget := readTarget + "/revoke"
	revoked := call("POST", revokeTarget, serviceOwnerSub, "", nil)
	var record controlv1.Share
	if revoked.Code != 200 || json.Unmarshal(revoked.Body.Bytes(), &record) != nil || record.Id != creation.Share.Id || record.RevokedAt == nil {
		t.Fatal("signed revocation did not update the canonical share", revoked.Code)
	}
	// demotion is read from durable state, not the signed token's role claims.
	invitation, err := f.d.CreateTeamInvitation(ctx, controlstate.CreateInvitationRequest{IdentityID: owner.Identity.Identity.Id,
		TeamID: team.ID, MemberSlug: "second-owner", InitialRole: controlstate.TeamRoleOwner,
		IdempotencyKey: "share-second-owner", RetrySecret: bytes.Repeat([]byte{9}, 32), ExpiresAt: f.now.Add(time.Hour)}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.d.AcceptInvitation(ctx, secondOwner.Identity.Identity.Id, credentials.InvitationToken(invitation.Secret), f.now); err != nil {
		t.Fatal(err)
	}
	member := f.membership(owner.Identity.Identity.Id, team.ID)
	p := f.principal(secondOwner)
	if _, err := f.d.SetMembershipRole(controlstate.WithControlPrincipal(ctx, p), p.IdentityID, team.ID, member.ID, controlstate.TeamRoleMember, f.now); err != nil {
		t.Fatal(err)
	}
	for _, operation := range []struct {
		method, target, key string
		body                []byte
	}{
		{"GET", readTarget, "", nil},
		{"POST", revokeTarget, "", nil},
		{"POST", "/v1/shares", "website-share", body},
	} {
		if got := call(operation.method, operation.target, serviceOwnerSub, operation.key, operation.body); got.Code != 403 {
			t.Fatal(fmt.Sprintf("demoted issuer retained %s share authority", operation.method), got.Code)
		}
	}
}

func TestIntegrationCanonicalCompanyShareKeepsOriginalSource(t *testing.T) {
	f, owner, _, team, _ := serviceFixture(t)
	ctx := t.Context()
	service := serviceActorNamedService(t, f, team.ID, owner.Identity.Identity.Id)
	registerShareActorAPI(t, f)
	base := "/v1/service/teams/" + team.ID + "/identity-connections"
	var setup controlstate.IdentityConnectionSetup
	f.decode(f.ownerCall("POST", base, serviceOwnerSub, nil,
		authorityv1.CreateIdentityConnectionRequest{SourceId: "share-source", Admission: authorityv1.CreateConnectionApproval}), 201, &setup)
	f.decode(f.provision(setup.IdentityConnection, setup.SetupToken, serviceOwnerSub, "a/owner", 1, true, "owner"), 204, nil)
	var connection controlstate.IdentityConnectionSecret
	f.decode(f.ownerCall("POST", base+"/"+setup.ID+"/activate", serviceOwnerSub, f.proof(setup.IdentityConnection, "a/owner"), f.activationRequest(setup)), 200, &connection)
	body := f.encode(controlv1.CreateShareRequest{ServiceIds: []string{service.ID}, EntryServiceId: service.ID, ExpiresAt: f.now.Add(24 * time.Hour)})
	create := func(proofs []oidc.TeamContext) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest("POST", "/v1/shares", bytes.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+companyWebsiteSecret)
		r.Header.Set("Idempotency-Key", "company-share")
		r.Header.Set("X-Tnl-Actor-Token", f.token(serviceOwnerSub, controlstate.ServiceActorNonce("POST", "/v1/shares", body), proofs))
		w := httptest.NewRecorder()
		f.mux.ServeHTTP(w, r)
		return w
	}
	if denied := create(nil); denied.Code != 403 {
		t.Fatal("personal website sign-in bypassed the required company source", denied.Code)
	}
	proofs := f.proof(connection.IdentityConnection, "a/owner")
	proofs[0].AuthenticatedAt -= 120
	created := create(proofs)
	var share controlv1.ShareCreation
	if created.Code != 201 || json.Unmarshal(created.Body.Bytes(), &share) != nil {
		t.Fatal("current company actor could not create a canonical share", created.Code)
	}
	newerProof := f.proof(connection.IdentityConnection, "a/owner")
	if retry := create(newerProof); retry.Code != 409 || strings.Contains(retry.Body.String(), share.TokenSource.Secret) {
		t.Fatal("fresh company authentication reminted an existing share", retry.Code)
	}
	var raw []byte
	var noSession bool
	if err := f.sql.QueryRow(ctx, `SELECT issuer_company_context,control_session_id IS NULL FROM control.shares WHERE id=$1`, share.Share.Id).Scan(&raw, &noSession); err != nil {
		t.Fatal(err)
	}
	var saved oidc.TeamContext
	if err := json.Unmarshal(raw, &saved); err != nil || saved != proofs[0] || !noSession {
		t.Fatal("share lost its original company proof or fabricated a control session", err)
	}
	source, err := json.Marshal(share.TokenSource)
	if err != nil {
		t.Fatal(err)
	}
	visitorBody := f.encode(controlv1.VisitorTokenRequest{Resource: controlv1.VisitorResourceScope{
		Kind: controlv1.VisitorResourceScopeKindService, Id: service.ID}, Source: source})
	visit := func(want int) {
		t.Helper()
		if response := f.call("POST", "/v1/visitor-tokens", "", "", visitorBody); response.Code != want {
			t.Fatal("share visitor permission changed its current source boundary", response.Code, want)
		}
	}
	visit(200)
	deadline := time.Unix(proofs[0].AuthenticatedAt, 0).Add(controlstate.CompanyAuthenticationLifetime)
	credential := controlstate.ShareTokenSource{ShareID: share.Share.Id, Secret: share.TokenSource.Secret}
	if _, err := f.d.IssueVisitorToken(ctx, "https://control.example.test",
		visitorscope.Scope{Kind: visitorscope.Service, ID: service.ID}, credential, deadline.Add(time.Second)); !errors.Is(err, controlstate.ErrVisitorPermission) {
		t.Fatal("fresh retry extended the original company authentication deadline", err)
	}
	f.decode(f.provision(connection.IdentityConnection, connection.ProvisioningToken, serviceOwnerSub, "a/owner", 2, false, "owner"), 204, nil)
	visit(403)
	f.decode(f.provision(connection.IdentityConnection, connection.ProvisioningToken, serviceOwnerSub, "a/owner", 3, true, "owner"), 204, nil)
	var replacementSetup controlstate.IdentityConnectionSetup
	f.decode(f.ownerCall("POST", base, serviceOwnerSub, f.proof(connection.IdentityConnection, "a/owner"),
		authorityv1.CreateIdentityConnectionRequest{SourceId: "replacement-share-source", Admission: authorityv1.CreateConnectionApproval,
			ReplaceId: &connection.ID, ExpectedRevision: &connection.Revision}), 201, &replacementSetup)
	f.decode(f.provision(replacementSetup.IdentityConnection, replacementSetup.SetupToken, serviceOwnerSub, "b/owner", 1, true, "owner"), 204, nil)
	var replacement controlstate.IdentityConnectionSecret
	bothSources := append(f.proof(connection.IdentityConnection, "a/owner"), f.proof(replacementSetup.IdentityConnection, "b/owner")...)
	f.decode(f.ownerCall("POST", base+"/"+replacementSetup.ID+"/activate", serviceOwnerSub, bothSources, f.activationRequest(replacementSetup)), 200, &replacement)
	readPath := "/v1/shares/" + share.Share.Id
	currentOwner := f.token(serviceOwnerSub, controlstate.ServiceActorNonce("GET", readPath, nil), f.proof(replacement.IdentityConnection, "b/owner"))
	if response := f.call("GET", readPath, companyWebsiteSecret, currentOwner, nil); response.Code != 200 {
		t.Fatal("replacement source did not retain current share management", response.Code)
	}
	visit(403)
}
