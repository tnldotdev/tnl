package state

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
)

func prepareVisitorTokenKeys(t *testing.T, d *Database, now time.Time) {
	t.Helper()
	if err := d.PrepareVisitorSigningKeys(t.Context(), testVisitorIssuer, now); err != nil {
		t.Fatal(err)
	}
}

func TestIntegrationVisitorTokenIssuanceUsesCurrentScopeAndParentDeadlines(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "visitor_token_issuance")
	prepareVisitorTokenKeys(t, d, now)
	request := oidcRouteRequest(t, d, now)
	u := createTestPublicURL(t, d, request, now)
	session := newOIDCSession(t, d, now)
	principal := ControlPrincipal{IdentityID: session.Identity.Identity.ID, SessionID: session.SessionID}
	ctx := WithControlPrincipal(t.Context(), principal)
	scope := visitorscope.Scope{Kind: visitorscope.PublicURL, ID: u.ID}
	issued, err := d.IssueVisitorToken(ctx, testVisitorIssuer, scope, BrowserTokenSource{}, now)
	if err != nil {
		t.Fatal(err)
	}
	keys := stateTestVisitorKeys(t, d, now)
	verified, err := visitortoken.VerifyBearer(issued.Token, stateTestVisitorView(issued.Permission, keys, now), now)
	if err != nil || verified.Scope != scope || verified.Subject != (visitortoken.Browser{IdentityID: principal.IdentityID, SessionID: principal.SessionID}) || !verified.ExpiresAt.Equal(now.Add(5*time.Minute).Truncate(time.Second)) {
		t.Fatal("incorrect scoped visitor permission", err)
	}
	if _, err := d.IssueVisitorToken(t.Context(), testVisitorIssuer, scope, BrowserTokenSource{}, now); !errors.Is(err, ErrVisitorPermission) {
		t.Fatal("unverified identity minted visitor permission", err)
	}
	if _, err := d.IssueVisitorToken(ctx, testVisitorIssuer, visitorscope.Scope{Kind: visitorscope.Service, ID: u.ID}, BrowserTokenSource{}, now); err == nil {
		t.Fatal("public URL ID became a service permission")
	}
	parentDeadline := now.Add(2 * time.Second)
	if _, err := d.pool.Exec(ctx, `UPDATE control.control_sessions SET access_expires_at=$2 WHERE id=$1`, session.SessionID, parentDeadline); err != nil {
		t.Fatal(err)
	}
	short, err := d.IssueVisitorToken(ctx, testVisitorIssuer, scope, BrowserTokenSource{}, now)
	if err != nil || !short.Permission.ExpiresAt.Equal(parentDeadline.Truncate(time.Second)) {
		t.Fatal("permission outlived its parent session", err)
	}
	if _, err := d.pool.Exec(ctx, `UPDATE control.public_urls SET access_mode='anonymous' WHERE id=$1`, u.ID); err != nil {
		t.Fatal(err)
	}
	if err := d.RevokeControlSession(ctx, principal, now); err != nil {
		t.Fatal(err)
	}
	if _, err := d.IssueVisitorToken(ctx, testVisitorIssuer, scope, BrowserTokenSource{}, now); !errors.Is(err, ErrVisitorPermission) {
		t.Fatal("revoked credential fell back to anonymous", err)
	}
	if _, err := d.IssueVisitorToken(ctx, testVisitorIssuer, scope, BrowserSessionTokenSource{Secret: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))}, now); !errors.Is(err, ErrVisitorPermission) {
		t.Fatal("unknown browser sign-in fell back to anonymous", err)
	}
}

func TestIntegrationConcurrentVisitorTokenIssuanceRetriesSerialization(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "visitor_token_concurrent")
	prepareVisitorTokenKeys(t, d, now)
	request := oidcRouteRequest(t, d, now)
	url := createTestPublicURL(t, d, request, now)
	session := newOIDCSession(t, d, now)
	ctx := WithControlPrincipal(t.Context(), ControlPrincipal{IdentityID: session.Identity.Identity.ID, SessionID: session.SessionID})
	scope := visitorscope.Scope{Kind: visitorscope.PublicURL, ID: url.ID}
	start := make(chan struct{})
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			<-start
			issued, err := d.IssueVisitorToken(ctx, testVisitorIssuer, scope, BrowserTokenSource{}, now)
			if err != nil || issued.Token == "" {
				t.Errorf("concurrent visitor token issuance failed: %v", err)
			}
		})
	}
	close(start)
	workers.Wait()
}

func TestIntegrationConcurrentVisitorGrantAndCertificatePreparation(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "visitor_grant_certificate_concurrent")
	prepareVisitorTokenKeys(t, d, now)
	request := oidcRouteRequest(t, d, now)
	session := newOIDCSession(t, d, now)
	principal := ControlPrincipal{IdentityID: session.Identity.Identity.ID, SessionID: session.SessionID}
	ctx := WithControlPrincipal(t.Context(), principal)
	service, err := d.CreateServiceAt(ctx, request.TeamID, principal.IdentityID, "concurrent", "concurrent", ServicePlacement{}, now, ServiceMetadata{Protocol: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, 32))
	device, err := d.EnrollVisitorDevice(ctx, principal.IdentityID, key.Public().(ed25519.PublicKey), now)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	scope := visitorscope.Scope{Kind: visitorscope.Service, ID: service.ID}
	start := make(chan struct{})
	var workers sync.WaitGroup
	for range 4 {
		workers.Go(func() {
			<-start
			issued, err := d.CreateVisitorGrantCredentials(ctx, testVisitorIssuer, scope, "token", now.Add(time.Hour), now)
			if err != nil || issued.Token == "" {
				t.Errorf("concurrent grant preparation failed: %v", err)
			}
		})
		workers.Go(func() {
			<-start
			issued, err := d.IssueVisitorClientCertificate(ctx, testVisitorIssuer, scope, DeviceTokenSource{DeviceID: device.ID}, csr, now)
			if err != nil || issued.CertificatePEM == "" {
				t.Errorf("concurrent certificate preparation failed: %v", err)
			}
		})
	}
	close(start)
	workers.Wait()
}

func TestIntegrationVisitorTokenShareUsesCapturedScopeExpiryAndCurrentIssuer(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "visitor_token_share")
	prepareVisitorTokenKeys(t, d, now)
	request := oidcRouteRequest(t, d, now)
	u := createTestPublicURL(t, d, request, now)
	otherRequest := request
	otherRequest.IdempotencyKey, otherRequest.CanonicalHostname = "other", "other."+request.CanonicalHostname
	otherRequest.RequestDigest = sha256.Sum256([]byte("other"))
	other := createTestPublicURL(t, d, otherRequest, now)
	secret := bytes.Repeat([]byte{7}, 32)
	fingerprint := sha256.Sum256(secret)
	deadline := now.Add(3 * time.Second)
	share, err := d.CreateShare(t.Context(), CreateShareRequest{TeamID: u.TeamID, ActingIdentityID: request.ActingIdentityID, IdempotencyKey: "token-share", SecretFingerprint: fingerprint, ExpiresAt: deadline, PolicyRevision: 1, PublicURLs: []AuthorizedSharePublicURL{{PublicURLID: u.ID, ExpectedMutationRevision: u.MutationRevision}}}, now)
	if err != nil {
		t.Fatal(err)
	}
	source := ShareTokenSource{ShareID: share.ID, Secret: base64.RawURLEncoding.EncodeToString(secret)}
	scope := visitorscope.Scope{Kind: visitorscope.PublicURL, ID: u.ID}
	issued, err := d.IssueVisitorToken(t.Context(), testVisitorIssuer, scope, source, now)
	if err != nil || issued.Permission.Subject != (visitortoken.Share{ShareID: share.ID}) || !issued.Permission.ExpiresAt.Equal(deadline.Truncate(time.Second)) {
		t.Fatal("share permission scope or expiry changed", err)
	}
	if _, err := d.IssueVisitorToken(t.Context(), testVisitorIssuer, visitorscope.Scope{Kind: visitorscope.PublicURL, ID: other.ID}, source, now); !errors.Is(err, ErrVisitorPermission) {
		t.Fatal("share expanded to a later public URL", err)
	}
	if _, err := d.IssueVisitorToken(t.Context(), testVisitorIssuer, scope, source, deadline); err == nil {
		t.Fatal("expired share issued permission")
	}
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.identities SET disabled_at=$2 WHERE id=$1`, request.ActingIdentityID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := d.IssueVisitorToken(t.Context(), testVisitorIssuer, scope, source, now); !errors.Is(err, ErrVisitorPermission) {
		t.Fatal("share issuer lost authority but still issued permission", err)
	}
}

func TestIntegrationVisitorTokenNativeAndExplicitCredentialsNeedOneScopedGrantModel(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "visitor_token_native")
	prepareVisitorTokenKeys(t, d, now)
	request := oidcRouteRequest(t, d, now)
	session := newOIDCSession(t, d, now)
	principal := ControlPrincipal{IdentityID: session.Identity.Identity.ID, SessionID: session.SessionID}
	ctx := WithControlPrincipal(t.Context(), principal)
	service, err := d.CreateServiceAt(ctx, request.TeamID, principal.IdentityID, "native", "native", ServicePlacement{}, now, ServiceMetadata{Protocol: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, 32))
	device, err := d.EnrollVisitorDevice(ctx, principal.IdentityID, key.Public().(ed25519.PublicKey), now)
	if err != nil {
		t.Fatal(err)
	}
	scope := visitorscope.Scope{Kind: visitorscope.Service, ID: service.ID}
	issued, err := d.IssueVisitorToken(ctx, testVisitorIssuer, scope, DeviceTokenSource{DeviceID: device.ID}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := issued.Permission.Subject.(visitortoken.Device); !ok {
		t.Fatal("device permission lost proof binding")
	}
	var runs int
	if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM control.service_runs WHERE service_id=$1`, service.ID).Scan(&runs); err != nil || runs != 0 {
		t.Fatal("permission issuance depended on selecting a run", err)
	}
	expires := now.Add(48 * time.Hour)
	credentials, err := d.CreateVisitorGrantCredentials(ctx, testVisitorIssuer, scope, "token", expires, now)
	if err != nil || !credentials.Permission.ExpiresAt.Equal(expires.Truncate(time.Second)) {
		t.Fatal("explicit credential lifetime was replaced by renewable token lifetime", err)
	}
	if _, err := d.IssueVisitorToken(t.Context(), testVisitorIssuer, scope, GrantTokenSource{Credential: credentials.RefreshCredential}, now); err != nil {
		t.Fatal("authority refresh failed", err)
	}
	if _, err := visitortoken.VerifyBearer(visitortoken.Token(credentials.RefreshCredential), stateTestVisitorView(credentials.Permission, stateTestVisitorKeys(t, d, now), now), now); !errors.Is(err, visitortoken.ErrToken) {
		t.Fatal("refresh credential became an app credential", err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := d.IssueVisitorClientCertificate(ctx, testVisitorIssuer, scope, DeviceTokenSource{DeviceID: device.ID}, csr, now)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(certificate.CertificatePEM))
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	certificateToken, err := visitortoken.CertificateToken(leaf)
	if err != nil || !certificate.ExpiresAt.Equal(issued.Permission.ExpiresAt) {
		t.Fatal("certificate did not carry the scoped permission deadline", err)
	}
	currentPermission := issued.Permission
	currentPermission.VisitorPolicyRevision = policyRevision(t, d, scope)
	if _, err := visitortoken.VerifyBearer(certificateToken, stateTestVisitorView(currentPermission, stateTestVisitorKeys(t, d, now), now), now); !errors.Is(err, visitortoken.ErrBinding) {
		t.Fatal("certificate permission became bearer access", err)
	}
	if _, err := d.pool.Exec(ctx, `UPDATE control.service_client_certificates SET revoked_at=$2 WHERE service_id=$1`, service.ID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := d.IssueVisitorClientCertificate(ctx, testVisitorIssuer, scope, DeviceTokenSource{DeviceID: device.ID}, csr, now); !errors.Is(err, ErrVisitorPermission) {
		t.Fatal("certificate issuance revived a revoked CSR", err)
	}
	// keep a real public URL grant for the same identity and team. it must not
	// substitute for revoked grants on this service, even for an enrolled device.
	u := createTestPublicURL(t, d, request, now)
	if _, err := d.CreateTeamVisitorGrant(ctx, u.ID, principal.IdentityID, "scope-grant", nil, now); err != nil {
		t.Fatal(err)
	}
	if _, err := d.pool.Exec(ctx, `UPDATE control.visitor_grants SET revoked_at=$2 WHERE service_id=$1`, service.ID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := d.IssueVisitorToken(ctx, testVisitorIssuer, scope, DeviceTokenSource{DeviceID: device.ID}, now); !errors.Is(err, ErrVisitorPermission) {
		t.Fatal("device existence or public URL grant authorized a service", err)
	}
	if _, err := d.IssueVisitorToken(t.Context(), testVisitorIssuer, scope, GrantTokenSource{Credential: credentials.RefreshCredential}, now); !errors.Is(err, ErrVisitorPermission) {
		t.Fatal("refresh grant outlived issuer authority", err)
	}
}

func TestIntegrationVisitorTokenConcurrentPreparationRetriesFreshAuthorization(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "visitor_token_concurrent")
	actor := oidcRouteRequest(t, d, now)
	session := newOIDCSession(t, d, now)
	ctx := WithControlPrincipal(t.Context(), ControlPrincipal{IdentityID: session.Identity.Identity.ID, SessionID: session.SessionID})
	service, err := d.CreateServiceAt(ctx, actor.TeamID, session.Identity.Identity.ID, "native-concurrent", "native-concurrent", ServicePlacement{}, now, ServiceMetadata{Protocol: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))
	device, err := d.EnrollVisitorDevice(ctx, session.Identity.Identity.ID, key.Public().(ed25519.PublicKey), now)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.PrepareVisitorSigningKeys(ctx, testVisitorIssuer, now); err != nil {
		t.Fatal(err)
	}
	scope := visitorscope.Scope{Kind: visitorscope.Service, ID: service.ID}
	results := make(chan error, 16)
	start := make(chan struct{})
	var workers sync.WaitGroup
	for range 16 {
		workers.Go(func() {
			<-start
			issued, err := d.IssueVisitorToken(ctx, testVisitorIssuer, scope, DeviceTokenSource{DeviceID: device.ID}, now)
			if err == nil && (issued.Permission.Scope != scope || issued.Token.Reveal() == "") {
				err = errors.New("concurrent permission lost its exact scope or signature")
			}
			results <- err
		})
	}
	close(start)
	workers.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatalf("concurrent preparation failed instead of retrying a fresh authorization: %v", err)
		}
	}
}

func TestIntegrationVisitorTokenWorkloadKeepsSelectedServicesKeyAndFixedDeadline(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "visitor_token_workload")
	prepareVisitorTokenKeys(t, d, now)
	request := appliedProjectRequest(t, d, now)
	request.Configuration = workloadConfiguration()
	applied, err := d.ApplyProjectConfiguration(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	exchange, key := workloadExchange(t, request, now)
	exchange.Services = []string{"api"}
	signWorkloadRequest(&exchange, key)
	session, err := d.ExchangeWorkload(t.Context(), exchange, now)
	if err != nil {
		t.Fatal(err)
	}
	var allowed, excluded string
	for _, service := range applied.Services {
		if service.Service == "api" {
			allowed = service.ServiceID
		} else if service.Service == "db" {
			excluded = service.ServiceID
		}
	}
	scope := visitorscope.Scope{Kind: visitorscope.Service, ID: allowed}
	source := WorkloadTokenSource{Credential: session.Credential}
	issued, err := d.IssueVisitorToken(t.Context(), testVisitorIssuer, scope, source, now)
	if err != nil {
		t.Fatal(err)
	}
	parent, ok := issued.Permission.Subject.(visitortoken.Workload)
	if !ok || parent.SessionID != session.ID || issued.Permission.ExpiresAt.After(session.LeaseExpiresAt) || issued.Permission.ExpiresAt.After(session.ExpiresAt) {
		t.Fatal("workload permission changed its authority-confirmed parent")
	}
	if _, err := d.IssueVisitorToken(t.Context(), testVisitorIssuer, visitorscope.Scope{Kind: visitorscope.Service, ID: excluded}, source, now); !errors.Is(err, ErrVisitorPermission) {
		t.Fatal("workload permission widened selected services", err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := d.IssueVisitorClientCertificate(t.Context(), testVisitorIssuer, scope, source, csr, now)
	if err != nil || certificate.ExpiresAt.After(session.LeaseExpiresAt) {
		t.Fatal("workload certificate outlived current source authority", err)
	}
	_, wrong, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongCSR, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, wrong)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.IssueVisitorClientCertificate(t.Context(), testVisitorIssuer, scope, source, wrongCSR, now); !errors.Is(err, ErrVisitorPermission) {
		t.Fatal("workload certificate accepted another TLS key", err)
	}
	if _, err := d.IssueVisitorToken(t.Context(), testVisitorIssuer, scope, source, session.LeaseExpiresAt); err == nil {
		t.Fatal("expired workload lease minted permission")
	}
	if err := d.RevokeWorkloadSession(t.Context(), session.ID, session.Credential, now); err != nil {
		t.Fatal(err)
	}
	if _, err := d.IssueVisitorToken(t.Context(), testVisitorIssuer, scope, source, now); err == nil {
		t.Fatal("revoked workload minted permission")
	}
}
