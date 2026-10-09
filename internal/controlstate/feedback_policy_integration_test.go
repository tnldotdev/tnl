package controlstate

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
)

func feedbackPolicyShare(t *testing.T, f publishRunFixture, preview Preview) FeedbackActor {
	t.Helper()
	if err := f.database.EnableShareAccess(t.Context(), f.authentication(), preview.ID); err != nil {
		t.Fatal(err)
	}
	share, err := f.database.CreateShare(t.Context(), CreateShareRequest{
		PreviewID: preview.ID, TeamID: f.request.TeamID, ActingIdentityID: f.request.ActingIdentityID,
		IdempotencyKey: "policy-share", SecretFingerprint: sha256.Sum256([]byte(strings.Repeat("s", 32))), ExpiresAt: f.now.Add(time.Hour),
		PolicyRevision: 1, PublicURLs: []AuthorizedSharePublicURL{{PublicURLID: f.setup.PublicURLID, ExpectedMutationRevision: 2}},
	}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	cookie := []byte(strings.Repeat("c", 32))
	digest := sha256.Sum256(cookie)
	if _, err := controlstatedb.New(f.database.pool).InsertShareCookie(t.Context(), controlstatedb.InsertShareCookieParams{
		TokenDigest: digest[:], PublicURLID: f.setup.PublicURLID, CreatedAt: timestamptz(f.now), ShareID: share.ID,
	}); err != nil {
		t.Fatal(err)
	}
	return FeedbackActor{Kind: "reviewer", ShareID: share.ID, CookieSecret: cookie}
}

func TestIntegrationFeedbackPolicyAllReviewerActions(t *testing.T) {
	for _, kind := range []string{"anonymous IP", "anonymous share", "member", "nonmember IP", "nonmember share", "nonmember denied", "revoked session", "revoked share", "forged identity"} {
		t.Run(kind, func(t *testing.T) {
			f := newPublishRunFixture(t)
			preview := browserFeedbackPreview(t, f)
			actor := FeedbackActor{Kind: "reviewer", AllowedIP: true}
			switch kind {
			case "anonymous share", "revoked share":
				actor = feedbackPolicyShare(t, f, preview)
			case "member":
				if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.teams SET kind = 'organization' WHERE id = $1`, f.request.TeamID); err != nil {
					t.Fatal(err)
				}
				member := addAuthorityMember(t, f.database, f.now, f.request.ActingIdentityID, f.request.TeamID, "policy-member", TeamRoleMember)
				actor, _, _ = newBrowserReviewer(t, f.database, preview.ID, f.setup.PublicURLID, member.IdentityID, f.now)
				setBrowserTeamGrant(t, f, preview, true)
			case "nonmember IP", "nonmember share", "nonmember denied", "revoked session":
				const identityID = "feedback-external-reviewer"
				insertAuthorityIdentity(t, f.database, identityID, "", false, f.now)
				var session ControlSession
				actor, _, session = newBrowserReviewer(t, f.database, preview.ID, f.setup.PublicURLID, identityID, f.now)
				actor.AllowedIP = kind == "nonmember IP" || kind == "revoked session"
				if kind == "nonmember share" {
					share := feedbackPolicyShare(t, f, preview)
					actor.ShareID, actor.CookieSecret = share.ShareID, share.CookieSecret
				}
				if kind == "revoked session" {
					if err := f.database.RevokeControlSession(t.Context(), ControlPrincipal{SessionID: session.SessionID, IdentityID: identityID}, f.now); err != nil {
						t.Fatal(err)
					}
				}
			case "forged identity":
				actor.IdentityID, actor.DisplayName = f.request.ActingIdentityID, "forged"
			}
			if kind == "revoked share" {
				if _, err := f.database.RevokeShare(t.Context(), actor.ShareID, f.request.ActingIdentityID, f.now); err != nil {
					t.Fatal(err)
				}
			}
			denied := kind == "nonmember denied" || kind == "revoked session" || kind == "revoked share" || kind == "forged identity"
			team, err := f.database.GetTeam(t.Context(), f.request.ActingIdentityID, f.request.TeamID)
			if err != nil {
				t.Fatal(err)
			}
			implementer := FeedbackActor{Kind: "implementer", IdentityID: f.request.ActingIdentityID, PolicyRevision: uint64(team.PolicyRevision), ExpectedMutationRevision: 2}
			// create before changing policy: the same run and thread stay live.
			thread, err := f.database.CreateFeedback(t.Context(), f.authentication(), browserFeedbackReport(t, preview.ID, FeedbackActor{Kind: "reviewer", AllowedIP: true}, "initial"), f.now)
			if err != nil {
				t.Fatal(err)
			}
			for index, required := range []bool{false, true, false} {
				policy, err := f.database.SetTeamFeedbackPolicy(t.Context(), f.request.ActingIdentityID, f.request.TeamID, required, f.now)
				if err != nil || policy.RequireSignIn != required {
					t.Fatalf("set policy = %+v, %v", policy, err)
				}
				var want error
				if denied {
					want = ErrFeedbackAccess
				} else if required && actor.IdentityID == "" {
					want = ErrFeedbackSignInRequired
				}
				access, err := f.database.ReviewerFeedbackAccess(t.Context(), f.authentication(), preview.ID, actor, f.now)
				if denied {
					if !errors.Is(err, ErrFeedbackAccess) {
						t.Fatalf("denied metadata = %+v, %v", access, err)
					}
				} else if err != nil || access.RequireSignIn != required {
					t.Fatalf("live metadata = %+v, %v", access, err)
				}
				if _, _, err := f.database.ReviewerFeedbackScope(t.Context(), f.authentication(), preview.ID, actor, f.now); (denied && !errors.Is(err, ErrFeedbackAccess)) || (!denied && err != nil) {
					t.Fatalf("policy changed read access: %v", err)
				}
				created, err := f.database.CreateFeedback(t.Context(), f.authentication(), browserFeedbackReport(t, preview.ID, actor, fmt.Sprintf("report-%d", index)), f.now)
				if !errors.Is(err, want) {
					t.Fatalf("report required=%t: %v, want %v", required, err, want)
				}
				if err == nil && (created.AuthorVerified != (actor.IdentityID != "") || created.AuthorIdentityID != actor.IdentityID || actor.IdentityID != "" && created.AuthorDisplayName == "untrusted report name") {
					t.Fatalf("unverified attribution: %+v", created)
				}
				for _, action := range []FeedbackEventType{FeedbackReply, FeedbackThreadResolved, FeedbackThreadReopened} {
					if action == FeedbackThreadReopened {
						if _, err := f.database.AppendFeedback(t.Context(), AppendFeedbackRequest{FeedbackID: thread.ID, Type: FeedbackThreadResolved, Actor: implementer, IdempotencyKey: fmt.Sprintf("prepare-resolve-%d", index)}, f.now); err != nil && !errors.Is(err, ErrFeedbackState) {
							t.Fatal(err)
						}
					}
					event, err := f.database.AppendFeedback(t.Context(), AppendFeedbackRequest{FeedbackID: thread.ID, Type: action, Text: "More detail", Actor: actor, IdempotencyKey: fmt.Sprintf("%s-%d", action, index)}, f.now)
					if !errors.Is(err, want) {
						t.Fatalf("%s required=%t: %v, want %v", action, required, err, want)
					}
					if err == nil && event.AuthorVerified != (actor.IdentityID != "") {
						t.Fatalf("event attribution = %+v", event)
					}
				}
				if _, err := f.database.AppendFeedback(t.Context(), AppendFeedbackRequest{FeedbackID: thread.ID, Type: FeedbackThreadReopened, Actor: implementer, IdempotencyKey: fmt.Sprintf("cleanup-reopen-%d", index)}, f.now); err != nil && !errors.Is(err, ErrFeedbackState) {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestIntegrationFeedbackPolicyPermissionsAndMetadataScope(t *testing.T) {
	f := newPublishRunFixture(t)
	preview := browserFeedbackPreview(t, f)
	if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.teams SET kind = 'organization' WHERE id = $1`, f.request.TeamID); err != nil {
		t.Fatal(err)
	}
	member := addAuthorityMember(t, f.database, f.now, f.request.ActingIdentityID, f.request.TeamID, "policy-member", TeamRoleMember)
	admin := addAuthorityMember(t, f.database, f.now, f.request.ActingIdentityID, f.request.TeamID, "policy-admin", TeamRoleAdmin)
	insertAuthorityIdentity(t, f.database, "policy-nonmember", "", false, f.now)
	for _, identity := range []string{f.request.ActingIdentityID, admin.IdentityID, member.IdentityID, "policy-nonmember"} {
		policy, err := f.database.GetTeamFeedbackPolicy(t.Context(), identity, f.request.TeamID)
		if identity == "policy-nonmember" {
			if !errors.Is(err, ErrTeamNotFound) {
				t.Fatalf("nonmember read = %v", err)
			}
		} else if err != nil || policy.RequireSignIn {
			t.Fatalf("default policy = %+v, %v", policy, err)
		}
	}
	for _, test := range []struct {
		identity string
		want     error
	}{{member.IdentityID, ErrAuthorityAccess}, {"policy-nonmember", ErrTeamNotFound}, {admin.IdentityID, nil}, {f.request.ActingIdentityID, nil}} {
		if _, err := f.database.SetTeamFeedbackPolicy(t.Context(), test.identity, f.request.TeamID, true, f.now); !errors.Is(err, test.want) {
			t.Fatalf("%s edit = %v, want %v", test.identity, err, test.want)
		}
	}
	if err := f.database.RemoveMembership(t.Context(), f.request.ActingIdentityID, f.request.TeamID, member.ID, f.now); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.GetTeamFeedbackPolicy(t.Context(), member.IdentityID, f.request.TeamID); !errors.Is(err, ErrTeamNotFound) {
		t.Fatalf("removed membership read = %v", err)
	}
	actor := FeedbackActor{Kind: "reviewer", AllowedIP: true}
	for _, change := range []string{"preview", "URL", "run number"} {
		auth, previewID := f.authentication(), preview.ID
		switch change {
		case "preview":
			previewID = "pv_0123456789abcdefghijkl"
		case "URL":
			auth.PublicURLID = "url_other"
		case "run number":
			auth.PublishRunNumber++
		}
		if _, err := f.database.ReviewerFeedbackAccess(t.Context(), auth, previewID, actor, f.now); !errors.Is(err, ErrFeedbackAccess) {
			t.Fatalf("cross-%s metadata = %v", change, err)
		}
	}
}

func TestIntegrationFeedbackPolicySerializesReviewerWritesByTeam(t *testing.T) {
	for _, action := range []string{"report", "reply", "resolve", "reopen"} {
		t.Run(action, func(t *testing.T) {
			f := newPublishRunFixture(t)
			preview := browserFeedbackPreview(t, f)
			actor := FeedbackActor{Kind: "reviewer", AllowedIP: true}
			thread, err := f.database.CreateFeedback(t.Context(), f.authentication(), browserFeedbackReport(t, preview.ID, actor, "initial"), f.now)
			if err != nil {
				t.Fatal(err)
			}
			if action == "reopen" {
				if _, err := f.database.AppendFeedback(t.Context(), AppendFeedbackRequest{FeedbackID: thread.ID, Type: FeedbackThreadResolved, Actor: actor, IdempotencyKey: "initial-resolve"}, f.now); err != nil {
					t.Fatal(err)
				}
			}
			seedControlPublicURL(t, f.database, f.now, "other_feedback_policy")
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			mutation, err := f.database.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, mutation)
			queries := controlstatedb.New(mutation)
			if _, err := queries.LockLocalTeamForMutation(ctx, f.request.TeamID); err != nil {
				t.Fatal(err)
			}
			workers := newIntegrationWorkers(t, cancel)
			defer workers.stop()
			done := make(chan error, 1)
			report := browserFeedbackReport(t, preview.ID, actor, "queued")
			workers.Go(func() {
				var err error
				if action == "report" {
					_, err = f.database.CreateFeedback(ctx, f.authentication(), report, f.now)
				} else {
					eventType := map[string]FeedbackEventType{"reply": FeedbackReply, "resolve": FeedbackThreadResolved, "reopen": FeedbackThreadReopened}[action]
					_, err = f.database.AppendFeedback(ctx, AppendFeedbackRequest{FeedbackID: thread.ID, Type: eventType, Text: "Queued", Actor: actor, IdempotencyKey: "queued"}, f.now)
				}
				done <- err
			})
			waitForPostgresBlock(t, ctx, f.database, int32(mutation.Conn().PgConn().PID()), done)
			if _, err := f.database.SetTeamFeedbackPolicy(ctx, "identity_other_feedback_policy", "team_other_feedback_policy", true, f.now); err != nil {
				t.Fatalf("unrelated policy blocked: %v", err)
			}
			// the queued writer must not hold the public URL or thread locks.
			if _, err := queries.LockPublicURLForRun(ctx, f.setup.PublicURLID); err != nil {
				t.Fatal(err)
			}
			if _, err := queries.LockFeedbackThread(ctx, thread.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := queries.SetTeamFeedbackPolicy(ctx, controlstatedb.SetTeamFeedbackPolicyParams{TeamID: f.request.TeamID, RequireSignIn: true, UpdatedAt: timestamp(f.now)}); err != nil {
				t.Fatal(err)
			}
			if err := mutation.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err := awaitIntegrationResult(t, ctx, done); !errors.Is(err, ErrFeedbackSignInRequired) {
				t.Fatalf("queued %s ignored live policy: %v", action, err)
			}
		})
	}
}

func TestIntegrationFeedbackPolicyAppliesToReadyRunAndRetries(t *testing.T) {
	f := newPublishRunFixture(t)
	preview := browserFeedbackPreview(t, f)
	readyTestSession(t, f)
	actor := FeedbackActor{Kind: "reviewer", AllowedIP: true}
	report := browserFeedbackReport(t, preview.ID, actor, "initial")
	thread, err := f.database.CreateFeedback(t.Context(), f.authentication(), report, f.now)
	if err != nil {
		t.Fatal(err)
	}
	reply := AppendFeedbackRequest{FeedbackID: thread.ID, Type: FeedbackReply, Text: "More detail", Actor: actor, IdempotencyKey: "initial-reply"}
	if _, err := f.database.AppendFeedback(t.Context(), reply, f.now); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.SetTeamFeedbackPolicy(t.Context(), f.request.ActingIdentityID, f.request.TeamID, true, f.now); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.CreateFeedback(t.Context(), f.authentication(), report, f.now); !errors.Is(err, ErrFeedbackSignInRequired) {
		t.Fatalf("anonymous report retry bypassed policy: %v", err)
	}
	if _, err := f.database.AppendFeedback(t.Context(), reply, f.now); !errors.Is(err, ErrFeedbackSignInRequired) {
		t.Fatalf("anonymous reply retry bypassed policy: %v", err)
	}
	if access, err := f.database.ReviewerFeedbackAccess(t.Context(), f.authentication(), preview.ID, actor, f.now); err != nil || !access.RequireSignIn {
		t.Fatalf("ready run metadata=%+v, %v", access, err)
	}
	implementer := FeedbackActor{Kind: "implementer", IdentityID: f.request.ActingIdentityID, PolicyRevision: 1, ExpectedMutationRevision: 2}
	if _, err := f.database.AppendFeedback(t.Context(), AppendFeedbackRequest{FeedbackID: thread.ID, Type: FeedbackUpdate, Text: "Fixed", SourceState: feedbackTestSource(t), Actor: implementer, IdempotencyKey: "update"}, f.now); err != nil {
		t.Fatalf("authenticated implementer update=%v", err)
	}
	if setup, err := f.database.HeartbeatPublishRun(t.Context(), f.authentication(), f.now, time.Minute, time.Minute); err != nil || setup.State != PublishRunReady || setup.PolicyRevision != f.setup.PolicyRevision {
		t.Fatalf("policy changed ready publish run: %+v, %v", setup, err)
	}
}

func TestIntegrationFeedbackPolicyMutationWaitsForReviewerGuard(t *testing.T) {
	f := newPublishRunFixture(t)
	seedControlPublicURL(t, f.database, f.now, "other_policy_writer")
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	reviewer, err := f.database.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, reviewer)
	if err := controlstatedb.New(reviewer).LockReviewerTeam(ctx, f.request.TeamID); err != nil {
		t.Fatal(err)
	}
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	done := make(chan error, 1)
	workers.Go(func() {
		_, err := f.database.SetTeamFeedbackPolicy(ctx, f.request.ActingIdentityID, f.request.TeamID, true, f.now)
		done <- err
	})
	waitForPostgresBlock(t, ctx, f.database, int32(reviewer.Conn().PgConn().PID()), done)
	if _, err := f.database.SetTeamFeedbackPolicy(ctx, "identity_other_policy_writer", "team_other_policy_writer", true, f.now); err != nil {
		t.Fatalf("unrelated mutation blocked: %v", err)
	}
	if err := reviewer.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := awaitIntegrationResult(t, ctx, done); err != nil {
		t.Fatal(err)
	}
	if policy, err := f.database.GetTeamFeedbackPolicy(ctx, f.request.ActingIdentityID, f.request.TeamID); err != nil || !policy.RequireSignIn {
		t.Fatalf("queued policy=%+v, %v", policy, err)
	}
}

func TestIntegrationFeedbackPolicyGuestDefaultAndMissingTeam(t *testing.T) {
	f := newPublishRunFixture(t)
	guest, err := NewGuestTrialCredential(netip.MustParseAddr("192.0.2.7"))
	if err != nil {
		t.Fatal(err)
	}
	domainID, err := f.database.CreateGuestTrial(t.Context(), guest, "guest-policy.example.test", f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.AllocateGuestDemoNumber(t.Context(), guest.ID, f.now); err != nil {
		t.Fatal(err)
	}
	secret, err := f.database.EnsureGuestPrincipal(t.Context(), guest.ID, f.now)
	if err != nil {
		t.Fatal(err)
	}
	publicURL, err := f.database.CreatePublicURL(t.Context(), CreatePublicURLRequest{
		GuestID: guest.ID, TeamID: guest.TeamID, DomainID: domainID, MembershipID: guest.MembershipID, ActingIdentityID: guest.ID,
		IdempotencyKey: "guest-policy", RequestDigest: sha256.Sum256([]byte("guest-policy")), CanonicalHostname: "demo-1." + guest.NamespaceLabel + ".guest-policy.example.test",
		Target: "http://127.0.0.1:3000", PublicURLScope: PublicURLScopeMember, Purpose: PublicURLPurposeDemo, AllowedIPPrefixes: []string{"192.0.2.7/32"},
		DNSState: PublicURLDNSUnmanaged, PolicyRevision: 1, Ephemeral: true,
	}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	setup, err := f.database.CreatePublishRun(t.Context(), PublishRunRequest{
		GuestID: guest.ID, PublicURLID: publicURL.ID, TeamID: guest.TeamID, ActingIdentityID: guest.ID, MembershipID: guest.MembershipID,
		RetrySecret: secret[:], IdempotencyKey: "guest-policy", RequestDigest: sha256.Sum256([]byte("guest-policy-run")), PolicyRevision: 1, ExpectedMutationRevision: publicURL.MutationRevision,
		CertificateCacheKey: "guest-policy", CertificateScope: "public-url", CertificateIdentifiers: []string{publicURL.CanonicalHostname}, CertificateChallenge: "tls-alpn-01",
	}, f.now, time.Minute, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	auth := PublishRunAuthentication{PublishRunID: setup.PublishRunID, PublicURLID: setup.PublicURLID, PublishRunNumber: setup.PublishRunNumber, PublishRunToken: setup.PublishRunToken}
	preview, err := f.database.CreatePublishRunPreview(t.Context(), auth, f.now)
	if err != nil {
		t.Fatal(err)
	}
	actor := FeedbackActor{Kind: "reviewer", AllowedIP: true}
	thread, err := f.database.CreateFeedback(t.Context(), auth, browserFeedbackReport(t, preview.ID, actor, "guest-report"), f.now)
	if err != nil {
		t.Fatalf("guest report policy=%v", err)
	}
	if _, err := f.database.AppendFeedback(t.Context(), AppendFeedbackRequest{FeedbackID: thread.ID, Type: FeedbackReply, Text: "More detail", Actor: actor, IdempotencyKey: "guest-reply"}, f.now); err != nil {
		t.Fatal(err)
	}
	if access, err := f.database.ReviewerFeedbackAccess(t.Context(), auth, preview.ID, actor, f.now); err != nil || access.RequireSignIn {
		t.Fatalf("guest metadata=%+v, %v", access, err)
	}
	if err := requireFeedbackIdentity(t.Context(), controlstatedb.New(f.database.pool), "missing-team", actor); !errors.Is(err, ErrFeedbackAccess) {
		t.Fatalf("missing team policy=%v", err)
	}
}
