package state

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestIntegrationPublicURLDeviceTokenKeepsExactScopeAndNativePossession(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "public_url_device_token")
	request := oidcRouteRequest(t, d, now)
	url := createTestPublicURL(t, d, request, now)
	session := newOIDCSession(t, d, now)
	principal := ControlPrincipal{IdentityID: session.Identity.Identity.ID, SessionID: session.SessionID}
	ctx := WithControlPrincipal(t.Context(), principal)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, ed25519.SeedSize))
	device, err := d.EnrollVisitorDevice(ctx, principal.IdentityID, key.Public().(ed25519.PublicKey), now)
	if err != nil {
		t.Fatal(err)
	}
	scope := visitorscope.Scope{Kind: visitorscope.PublicURL, ID: url.ID}
	source := DeviceTokenSource{DeviceID: device.ID}
	issued, err := d.IssueVisitorToken(ctx, testVisitorIssuer, scope, source, now)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := visitortoken.KeyDigest(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	subject := visitortoken.Device{IdentityID: principal.IdentityID, SessionID: principal.SessionID, DeviceID: device.ID, KeySHA256: digest}
	if issued.ServiceTrustRevision != 0 || issued.Permission.Scope != scope || issued.Permission.Subject != subject ||
		issued.Permission.Hostname != url.CanonicalHostname || issued.Permission.Port != uint16(url.Port) ||
		issued.Permission.ExpiresAt.After(session.AccessExpiresAt) {
		t.Fatal("native token changed the saved resource, endpoint, source, or deadline")
	}
	keys := stateTestVisitorKeys(t, d, now)
	view := stateTestVisitorView(issued.Permission, keys, now)
	view.MetadataRevision = 1
	if got, err := visitortoken.VerifyBearer(issued.Token, view, now); !errors.Is(err, visitortoken.ErrBinding) || got.Valid() {
		t.Fatal("native possession-bound permission became browser bearer access", err)
	}
	if _, err := d.AuthenticateAccessToken(ctx, credentials.AccessToken(issued.Token.Reveal()), now); !errors.Is(err, ErrControlAuthentication) {
		t.Fatal("native visitor permission became a control session", err)
	}
	// a token is resource permission, not proof that a connector pair or run
	// exists. use checked-session test facts only to exercise its native proof.
	entry := tunnelv1.ConnectorPeerVisitorEntry{
		ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.ConnectorPeerVisitorStream,
		PairID: "cpp_1234567890123456789012", DeliveryID: "AQEBAQEBAQEBAQEBAQEBAQ", DeliveryGeneration: 1,
		PublicURLID: url.ID, PublishRunID: "pr_1234567890123456789012", PublishRunNumber: 1,
		Subject:  VisitorSubject{Kind: tunnelv1.VisitorHumanDevice, IdentityID: principal.IdentityID, DeviceID: device.ID},
		SourceIP: "192.0.2.1", VisitorConnectionID: "vc_1234567890123456789012", MetadataRevision: 1,
		Permission: tunnelv1.ConnectorVisitorPermission{Token: issued.Token.Reveal(),
			PublicKey: base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey)),
			Signature: base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))},
	}
	initial := []byte("exact TLS initial bytes")
	message, err := tunnelv1.ConnectorPeerProofMessage(entry, initial)
	if err != nil {
		t.Fatal(err)
	}
	entry.Permission.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, message))
	expected := entry.Session()
	expected.ExpiresAt = now.Add(time.Minute)
	verified, err := visitortoken.VerifyConnectorPeerSession(entry, initial, expected, view, now)
	if err != nil || !verified.Valid() || verified.Facts().Subject != subject {
		t.Fatal("issued native permission failed its exact public URL proof", err)
	}
	if got, err := visitortoken.VerifyConnectorPeerSession(entry, []byte("changed"), expected, view, now); !errors.Is(err, visitortoken.ErrBinding) || got.Valid() {
		t.Fatal("native opening did not bind the application bytes", err)
	}
	other := view
	other.Port++
	if got, err := visitortoken.VerifyConnectorPeerSession(entry, initial, expected, other, now); !errors.Is(err, visitortoken.ErrToken) || got.Valid() {
		t.Fatal("saved endpoint port became a wildcard", err)
	}
	var runs int
	if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM control.publish_runs WHERE public_url_id=$1`, url.ID).Scan(&runs); err != nil || runs != 0 {
		t.Fatal("native token issuance created or selected a publish run", err)
	}
	parentUntil := now.Add(2 * time.Second)
	if _, err := d.pool.Exec(ctx, `UPDATE control.control_sessions SET access_expires_at=$2 WHERE id=$1`, principal.SessionID, parentUntil); err != nil {
		t.Fatal(err)
	}
	short, err := d.IssueVisitorToken(ctx, testVisitorIssuer, scope, source, now)
	if err != nil || !short.Permission.ExpiresAt.Equal(parentUntil.Truncate(time.Second)) {
		t.Fatal("native public URL permission outlived its parent session", err)
	}
	if _, err := d.pool.Exec(ctx, `UPDATE control.public_urls SET access_mode='anonymous' WHERE id=$1`, url.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.IssueVisitorToken(t.Context(), testVisitorIssuer, scope, source, now); !errors.Is(err, ErrVisitorPermission) {
		t.Fatal("device enrollment substituted for a current authenticated session", err)
	}
	if _, err := d.IssueVisitorToken(ctx, testVisitorIssuer, scope, DeviceTokenSource{DeviceID: "vdev_1234567890123456789012"}, now); !errors.Is(err, ErrVisitorPermission) {
		t.Fatal("unknown device fell back to anonymous access", err)
	}
	if _, err := d.IssueVisitorToken(ctx, testVisitorIssuer, scope, source, parentUntil); !errors.Is(err, ErrVisitorPermission) {
		t.Fatal("expired native source fell back to anonymous access", err)
	}
	if err := d.RevokeVisitorDevice(ctx, principal.IdentityID, device.ID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := d.IssueVisitorToken(ctx, testVisitorIssuer, scope, source, now); !errors.Is(err, ErrVisitorPermission) {
		t.Fatal("revoked native device fell back to anonymous access", err)
	}
}

func TestIntegrationPublicURLDeviceTokenUsesOnlyCurrentIncludedPreviewAccess(t *testing.T) {
	d, now, owner, team := newAuthorityTeam(t)
	members, err := d.ListTeamMemberships(t.Context(), owner, team.ID)
	if err != nil || len(members) != 1 {
		t.Fatal("missing owner membership", err)
	}
	domains, err := d.ListTeamDomains(t.Context(), owner, team.ID)
	if err != nil || len(domains) == 0 {
		t.Fatal("missing team domain", err)
	}
	request := CreatePublicURLRequest{TeamID: team.ID, DomainID: domains[0].ID, MembershipID: members[0].ID,
		ActingIdentityID: owner, PublicURLScope: PublicURLScopeMember, Purpose: PublicURLPurposeApp,
		IdempotencyKey: "native-preview", RequestDigest: sha256.Sum256([]byte("native-preview")),
		CanonicalHostname: "preview." + members[0].ManagedLabel + "." + domains[0].CanonicalDomain,
		Target:            "http://127.0.0.1:3000", DNSState: PublicURLDNSUnmanaged}
	url := createTestPublicURL(t, d, request, now)
	request.IdempotencyKey, request.RequestDigest = "excluded-preview", sha256.Sum256([]byte("excluded-preview"))
	request.CanonicalHostname = "excluded." + members[0].ManagedLabel + "." + domains[0].CanonicalDomain
	excluded := createTestPublicURL(t, d, request, now)
	session, err := d.CreateOIDCControlSession(t.Context(), "tunnels.example.test",
		OIDCIdentity{Issuer: "https://identity.fixture.test", Subject: "native-preview-visitor", DisplayName: "native visitor",
			AssertionDigest: sha256.Sum256([]byte("native-preview-visitor")), AssertionExpiry: now.Add(time.Hour)},
		time.Hour, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	person := session.Identity.Identity.ID
	invitation, err := d.CreateTeamInvitation(t.Context(), authorityInvitationRequest(owner, team.ID, "native", now), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.AcceptInvitation(t.Context(), person, credentials.InvitationToken(invitation.Secret), now); err != nil {
		t.Fatal(err)
	}
	service, err := d.CreateServiceAt(t.Context(), team.ID, owner, "native-grant", "native-grant", ServicePlacement{}, now, ServiceMetadata{Protocol: "http"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.CreateServiceGrant(t.Context(), service.ID, owner, "native-visitor", "identity", person, nil, now); err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))
	device, err := d.EnrollVisitorDevice(t.Context(), person, key.Public().(ed25519.PublicKey), now)
	if err != nil {
		t.Fatal(err)
	}
	ctx := WithControlPrincipal(t.Context(), ControlPrincipal{IdentityID: person, SessionID: session.SessionID})
	scope := visitorscope.Scope{Kind: visitorscope.PublicURL, ID: url.ID}
	source := DeviceTokenSource{DeviceID: device.ID}
	ownerMember, err := controlstatedb.New(d.pool).GetActivePublishRunMembership(t.Context(),
		controlstatedb.GetActivePublishRunMembershipParams{TeamID: team.ID, IdentityID: owner})
	if err != nil {
		t.Fatal(err)
	}
	preview, err := d.CreatePreview(t.Context(), team.ID, owner, "native-preview", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.AddPreviewPublicURL(t.Context(), AddPreviewPublicURLRequest{
		PreviewID: preview.ID, PublicURLID: url.ID, TeamID: team.ID, IdentityID: owner,
		PolicyRevision: uint64(ownerMember.PolicyRevision), ExpectedMutationRevision: url.MutationRevision,
	}, now); err != nil {
		t.Fatal(err)
	}
	source.PreviewID = preview.ID
	if _, err := d.IssueVisitorToken(ctx, testVisitorIssuer, scope, source, now); !errors.Is(err, ErrVisitorPermission) {
		t.Fatal("membership, a service grant, or a preview ID implied public URL access", err)
	}
	access := SetPreviewTeamAccessRequest{PreviewID: preview.ID, TeamID: team.ID, IdentityID: owner,
		PolicyRevision: uint64(ownerMember.PolicyRevision), Enabled: true,
		PublicURLs: []AuthorizedSharePublicURL{{PublicURLID: url.ID, ExpectedMutationRevision: url.MutationRevision}}}
	if _, err := d.SetPreviewTeamAccess(t.Context(), access, now); err != nil {
		t.Fatal(err)
	}
	issued, err := d.IssueVisitorToken(ctx, testVisitorIssuer, scope, source, now)
	if err != nil || issued.Permission.Scope != scope {
		t.Fatal("current included preview access did not authorize native permission", err)
	}
	current := issued.Permission.VisitorPolicyRevision
	if _, err := d.IssueVisitorToken(ctx, testVisitorIssuer, visitorscope.Scope{Kind: visitorscope.Service, ID: service.ID}, source, now); !errors.Is(err, ErrVisitorPermission) {
		t.Fatal("public URL preview selection was silently accepted as a service source", err)
	}
	for _, input := range []struct {
		scope  visitorscope.Scope
		source DeviceTokenSource
	}{
		{scope, DeviceTokenSource{DeviceID: device.ID}},
		{scope, DeviceTokenSource{DeviceID: device.ID, PreviewID: "pv_1234567890123456789012"}},
		{visitorscope.Scope{Kind: visitorscope.PublicURL, ID: excluded.ID}, source},
	} {
		if _, err := d.IssueVisitorToken(ctx, testVisitorIssuer, input.scope, input.source, now); !errors.Is(err, ErrVisitorPermission) {
			t.Fatal("preview access expanded beyond the selected included public URL", err)
		}
	}
	access.Enabled, access.PublicURLs, access.PolicyRevision = false, nil, 0
	if _, err := d.SetPreviewTeamAccess(t.Context(), access, now); err != nil {
		t.Fatal(err)
	}
	if _, err := d.IssueVisitorToken(ctx, testVisitorIssuer, scope, source, now); !errors.Is(err, ErrVisitorPermission) {
		t.Fatal("revoked preview team access still issued native permission", err)
	}
	if revision := policyRevision(t, d, scope); revision <= current {
		t.Fatal("revoking preview access did not invalidate prepared visitor permission")
	}
}
