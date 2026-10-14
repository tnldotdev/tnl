package controlstate

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
	"time"
)

func TestIntegrationNamedShareNeedsVerifiedRecipientWithoutTeamMembership(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "named_visitor_share")
	request := builtinRouteRequest(t, database, now)
	url := createTestPublicURL(t, database, request, now)
	unshared := request
	unshared.IdempotencyKey = "unshared-app"
	unshared.RequestDigest = sha256.Sum256([]byte(unshared.IdempotencyKey))
	unshared.CanonicalHostname = "other." + url.CanonicalHostname
	createTestPublicURL(t, database, unshared, now)
	recipient, err := database.EnsureServiceIdentity(t.Context(), "tunnels.example.test", OIDCIdentity{
		Issuer: "https://account.example", Subject: "named-reviewer", DisplayName: "Named reviewer",
		NormalizedEmail: "reviewer@example.test", EmailVerified: true,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	_, cookie, _ := newBrowserReviewer(t, database, "", url.ID, recipient.Identity.ID, now)
	before, err := database.BrowserAuthorization(t.Context(), url.ID, cookie, now)
	if err != nil || before.VisitAllowed {
		t.Fatalf("uninvited outsider = %+v, %v", before, err)
	}
	secret := bytes.Repeat([]byte{9}, 32)
	fingerprint := sha256.Sum256(secret)
	invitation, err := database.CreateVisitorShareInvitation(t.Context(), CreateVisitorShareInvitationRequest{
		TeamID: request.TeamID, PublicURLID: url.ID, ActingIdentityID: request.ActingIdentityID,
		IdempotencyKey: "named-invitation", Email: "Reviewer@Example.Test", TokenDigest: fingerprint,
		PolicyRevision: uint64(url.PolicyRevision), ExpectedMutationRevision: url.MutationRevision,
		ExpiresAt: now.Add(time.Hour),
	}, now)
	if err != nil || invitation.Email != "reviewer@example.test" || invitation.AcceptedAt != nil {
		t.Fatalf("pending invitation = %+v, %v", invitation, err)
	}
	if page, err := database.ListAvailablePublicURLs(t.Context(), recipient.Identity.ID, "", "", now); err != nil || len(page.PublicURLs) != 0 {
		t.Fatalf("pending invite leaked inventory = %+v, %v", page, err)
	}
	token := invitation.ID + "." + base64.RawURLEncoding.EncodeToString(secret)
	if _, err := database.AcceptVisitorShareInvitation(t.Context(), token, request.ActingIdentityID, now); !errors.Is(err, ErrShareNotFound) {
		t.Fatalf("wrong identity accepted invitation: %v", err)
	}
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.identities SET email_verified = false WHERE id = $1`, recipient.Identity.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.AcceptVisitorShareInvitation(t.Context(), token, recipient.Identity.ID, now); !errors.Is(err, ErrShareNotFound) {
		t.Fatalf("unverified email accepted invitation: %v", err)
	}
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.identities SET email_verified = true WHERE id = $1`, recipient.Identity.ID); err != nil {
		t.Fatal(err)
	}
	accepted, err := database.AcceptVisitorShareInvitation(t.Context(), token, recipient.Identity.ID, now)
	if err != nil || accepted.AcceptedIdentityID != recipient.Identity.ID || accepted.AcceptedAt == nil {
		t.Fatalf("accepted invitation = %+v, %v", accepted, err)
	}
	if _, err := database.AcceptVisitorShareInvitation(t.Context(), token, recipient.Identity.ID, now); !errors.Is(err, ErrShareNotFound) {
		t.Fatalf("used invitation secret accepted twice: %v", err)
	}
	context, err := database.IdentityContext(t.Context(), recipient.Identity.ID)
	if err != nil || len(context.Memberships) != 1 || context.Memberships[0].TeamID != recipient.PersonalTeamID {
		t.Fatalf("recipient gained owner team membership = %+v, %v", context, err)
	}
	page, err := database.ListAvailablePublicURLs(t.Context(), recipient.Identity.ID, "", "", now)
	if err != nil || len(page.PublicURLs) != 1 || page.PublicURLs[0].ID != url.ID || page.PublicURLs[0].VisitorAccess != "invite" {
		t.Fatalf("accepted invite inventory = %+v, %v", page, err)
	}
	access, err := database.BrowserAuthorization(t.Context(), url.ID, cookie, now)
	if err != nil || !access.VisitAllowed {
		t.Fatalf("accepted invite browser access = %+v, %v", access, err)
	}
	revoked, err := database.RevokeVisitorShareInvitation(t.Context(), invitation.ID, request.TeamID, request.ActingIdentityID, now.Add(time.Minute))
	if err != nil || revoked.RevokedAt == nil {
		t.Fatalf("revoke accepted invite = %+v, %v", revoked, err)
	}
	access, err = database.BrowserAuthorization(t.Context(), url.ID, cookie, now.Add(time.Minute))
	if err != nil || access.VisitAllowed {
		t.Fatalf("revoked invite browser access = %+v, %v", access, err)
	}
	page, err = database.ListAvailablePublicURLs(t.Context(), recipient.Identity.ID, "", "", now.Add(time.Minute))
	if err != nil || len(page.PublicURLs) != 0 {
		t.Fatalf("revoked invite still visible = %+v, %v", page, err)
	}
}

func TestIntegrationNamedInvitationExpiryAndRevocation(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "named_invitation_expiry")
	request := builtinRouteRequest(t, database, now)
	url := createTestPublicURL(t, database, request, now)
	recipient, err := database.EnsureServiceIdentity(t.Context(), "tunnels.example.test", OIDCIdentity{
		Issuer: "https://account.example", Subject: "expiry-reviewer", DisplayName: "Expiry reviewer",
		NormalizedEmail: "expiry@example.test", EmailVerified: true,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	secret := bytes.Repeat([]byte{7}, 32)
	fingerprint := sha256.Sum256(secret)
	create := CreateVisitorShareInvitationRequest{
		TeamID: request.TeamID, PublicURLID: url.ID, ActingIdentityID: request.ActingIdentityID,
		IdempotencyKey: "short-named-invite", Email: "expiry@example.test", TokenDigest: fingerprint,
		PolicyRevision: uint64(url.PolicyRevision), ExpectedMutationRevision: url.MutationRevision,
		ExpiresAt: now.Add(time.Minute),
	}
	invitation, err := database.CreateVisitorShareInvitation(t.Context(), create, now)
	if err != nil {
		t.Fatal(err)
	}
	token := invitation.ID + "." + base64.RawURLEncoding.EncodeToString(secret)
	if _, err := database.AcceptVisitorShareInvitation(t.Context(), token, recipient.Identity.ID, now.Add(2*time.Minute)); !errors.Is(err, ErrShareNotFound) {
		t.Fatalf("expired invite accepted: %v", err)
	}
	other := create
	other.IdempotencyKey = "other-named-invite"
	other.ExpiresAt = now.Add(time.Hour)
	otherInvite, err := database.CreateVisitorShareInvitation(t.Context(), other, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.RevokeVisitorShareInvitation(t.Context(), otherInvite.ID, request.TeamID, request.ActingIdentityID, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	otherToken := otherInvite.ID + "." + base64.RawURLEncoding.EncodeToString(secret)
	if _, err := database.AcceptVisitorShareInvitation(t.Context(), otherToken, recipient.Identity.ID, now.Add(2*time.Second)); !errors.Is(err, ErrShareNotFound) {
		t.Fatalf("revoked pending invite accepted: %v", err)
	}
	if _, err := database.CreateVisitorShareInvitation(t.Context(), other, now); !errors.Is(err, ErrShareIdempotency) {
		t.Fatalf("revoked invite revived on retry: %v", err)
	}
}
