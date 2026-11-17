package state

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/oidc"
	"github.com/tnldotdev/tnl/internal/security/credentials"
)

func TestIntegrationShareHandoffRevocationRequiresCurrentOwner(t *testing.T) {
	for _, change := range []string{"foreign owner", "removed membership", "replaced membership", "company eligibility"} {
		t.Run(change, func(t *testing.T) {
			f := newServiceManagementFixture(t)
			d, ctx := f.d, t.Context()
			if _, err := d.SetMembershipRole(ctx, f.owner, f.team, f.member.ID, TeamRoleAdmin, f.now); err != nil {
				t.Fatal(err)
			}
			apiOwner := f.member.IdentityID
			if change == "foreign owner" {
				apiOwner = f.owner
			}
			placement := ServicePlacement{}
			create := func(key string) ServiceRecord {
				t.Helper()
				service, err := d.CreateServiceAt(ctx, f.team, apiOwner, "api", key, placement,
					f.now, ServiceMetadata{Protocol: "http"}, &ProjectServiceConfiguration{Target: "localhost:3000"})
				if err != nil {
					t.Fatal(err)
				}
				return service
			}
			api := create("api")
			placement = ServicePlacement{DomainID: api.DomainID, Hostname: api.Endpoint.Hostname, Reserve: true}
			preview, err := d.CreatePreview(ctx, f.team, f.member.IdentityID, "handoff", f.now)
			if err != nil {
				t.Fatal(err)
			}
			for _, service := range []ServiceRecord{f.local, api} {
				if _, err := d.AddPreviewService(ctx, AddPreviewServiceRequest{PreviewID: preview.ID, ServiceID: service.ID,
					TeamID: f.team, IdentityID: f.member.IdentityID}, f.now); err != nil {
					t.Fatal(err)
				}
			}
			request := SetPreviewTeamAccessRequest{PreviewID: preview.ID, TeamID: f.team, IdentityID: f.member.IdentityID, Enabled: true}
			if _, err := d.SetPreviewTeamAccess(ctx, request, f.now); err != nil {
				t.Fatal(err)
			}
			share, err := d.CreateShare(ctx, CreateShareRequest{PreviewID: preview.ID, TeamID: f.team,
				ActingIdentityID: f.member.IdentityID, IdempotencyKey: "handoff", SecretFingerprint: sha256.Sum256([]byte("handoff")),
				ServiceIDs: []string{f.local.ID, api.ID}, EntryServiceID: f.local.ID, ExpiresAt: f.now.Add(time.Hour)}, f.now)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := d.SetMembershipRole(ctx, f.owner, f.team, f.member.ID, TeamRoleMember, f.now); err != nil {
				t.Fatal(err)
			}
			if err := d.DeleteService(ctx, api.ID, apiOwner, ServiceDeleteConditions{Unconditional: true}, f.now); err != nil {
				t.Fatal(err)
			}
			replacement := create("replacement")
			if replacement.ID == api.ID || replacement.Endpoint.Hostname != api.Endpoint.Hostname {
				t.Fatal("fixture did not replace the exact endpoint")
			}
			var receipts int
			if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM control.service_endpoints WHERE service_id=$1`, api.ID).Scan(&receipts); err != nil || receipts != 0 {
				t.Fatal("fixture retained the predecessor endpoint", receipts, err)
			}

			actor := func(string) context.Context { return ctx }
			want := ErrServiceAccess
			switch change {
			case "foreign owner":
				// even a replacement claim naming the actor cannot authorize
				// revocation for the foreign-owned service captured by the share.
				if _, err := d.pool.Exec(ctx, `UPDATE control.service_namespace_claims SET membership_id=$2 WHERE namespace=$1`,
					replacement.Endpoint.Hostname, f.member.ID); err != nil {
					t.Fatal(err)
				}
			case "removed membership", "replaced membership":
				if err := d.RemoveMembership(ctx, f.owner, f.team, f.member.ID, f.now); err != nil {
					t.Fatal(err)
				}
				if change == "replaced membership" {
					invitation, err := d.CreateTeamInvitation(ctx, authorityInvitationRequest(f.owner, f.team, "replacement-member", f.now), f.now)
					if err != nil {
						t.Fatal(err)
					}
					member, err := d.AcceptInvitation(ctx, f.member.IdentityID, credentials.InvitationToken(invitation.Secret), f.now)
					if err != nil || member.ID == f.member.ID {
						t.Fatal("fixture did not replace the membership", err)
					}
				}
			case "company eligibility":
				if _, err := d.pool.Exec(ctx, `UPDATE control.identities SET issuer='https://company.example',subject=id WHERE id=$1`, f.member.IdentityID); err != nil {
					t.Fatal(err)
				}
				owner := companyTestPrincipal(t, d, newOIDCSession(t, d, f.now), f.now)
				connection := companyTestConnection(t, d, f.team, owner, "approval", f.now)
				companyTestEligibility(t, d, connection, f.member.IdentityID, 1, true, f.now)
				actor = func(nonce string) context.Context {
					proof := managementActorProof(t, d, f.member.IdentityID, nonce, f.now)
					proof.TeamContexts = []oidc.TeamContext{{TeamID: f.team, IdentityConnectionID: connection.ID,
						ConnectionRevision: connection.Revision, SourceID: connection.SourceID,
						Subject: "directory/" + f.member.IdentityID, AuthenticatedAt: f.now.Unix()}}
					return WithServiceActorProof(ctx, proof, proof.Nonce)
				}
				if _, err := d.GetService(actor("eligible"), f.local.ID, f.member.IdentityID); err != nil {
					t.Fatal("eligible company owner could not manage its surviving service", err)
				}
				companyTestEligibility(t, d, connection, f.member.IdentityID, 2, false, f.now)
				want = ErrServiceSourceSignInRequired
			}
			request.Enabled = false
			if _, err := d.SetPreviewTeamAccess(actor("disable"), request, f.now); !errors.Is(err, want) {
				t.Fatal("retained ownership bypassed current team access authority", err)
			}
			if _, err := d.RevokeShare(actor("revoke"), share.ID, f.member.IdentityID, f.now); !errors.Is(err, want) {
				t.Fatal("retained ownership bypassed current share authority", err)
			}
			savedPreview, err := d.GetPreview(ctx, preview.ID)
			if err != nil || !savedPreview.TeamAccessEnabled {
				t.Fatal("denied revocation changed team access", err)
			}
			savedShare, err := d.GetShare(ctx, share.ID)
			if err != nil || savedShare.RevokedAt != nil {
				t.Fatal("denied revocation changed the share", err)
			}
		})
	}
}
