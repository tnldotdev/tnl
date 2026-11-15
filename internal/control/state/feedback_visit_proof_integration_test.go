package state

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func feedbackProofRequest(t *testing.T, preview string, actor FeedbackActor, key string) CreateFeedbackRequest {
	t.Helper()
	return CreateFeedbackRequest{PreviewID: preview, Service: "web", PagePath: "/", ReportText: "check the selected admission",
		Anchor: json.RawMessage(`null`), Evidence: json.RawMessage(`{"schema_version":1,"actions":[],"failed_requests":[]}`),
		SourceAtReport: feedbackTestSource(t), IdempotencyKey: key, Actor: actor}
}

func feedbackProofGrant(t *testing.T, f serviceHTTPFixture, ctx context.Context) controlv1.VisitorCredential {
	t.Helper()
	grant, err := f.database.CreateServiceHTTPGrant(ctx, f.service.ID, f.project.ActorID,
		controlv1.CreateVisitorCredentialRequest{Kind: "token", ExpiresAt: f.now.Add(time.Hour)}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	return grant
}

// signing deliberately bypasses issuance to isolate current-authority checks
// from policy revision rejection. production feedback never issues a token.
func signFeedbackProofFacts(t *testing.T, d *Database, permission visitortoken.Permission, now time.Time) visitortoken.Token {
	t.Helper()
	permission.VisitorPolicyRevision = policyRevision(t, d, permission.Scope)
	token, err := signStateTestPermission(t.Context(), d, testVisitorIssuer, permission, now)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func feedbackBearerFacts(t *testing.T, f serviceHTTPFixture, token string) visitortoken.Permission {
	t.Helper()
	update := policyObservation(t, f.database, f.auth().Subject, 0)
	keys := stateTestVisitorKeys(t, f.database, f.now)
	permission := visitortoken.Permission{Scope: f.auth().Subject, Hostname: update.Policy.Hostname, Port: uint16(update.Policy.Port),
		VisitorPolicyRevision: update.Policy.VisitorPolicyRevision}
	verified, err := visitortoken.VerifyBearer(visitortoken.Token(token), stateTestVisitorView(permission, keys, f.now), f.now)
	if err != nil {
		t.Fatal(err)
	}
	return verified.Facts()
}

func TestIntegrationFeedbackBearerProofUsesIndependentBrowserAuthor(t *testing.T) {
	f := newServiceHTTPFixture(t)
	f.run = f.publish(t, f.service)
	preview := f.preview(t, "bearer-feedback", f.service)
	grant := feedbackProofGrant(t, f, t.Context())
	actor := FeedbackActor{Kind: "reviewer", SourceIP: "192.0.2.9",
		VisitProof: FeedbackBearerVisitProof{Token: visitortoken.Token(grant.Permission.VisitorToken)}}
	thread, err := f.database.CreateFeedback(t.Context(), f.auth(), feedbackProofRequest(t, preview.ID, actor, "token-only"), f.now)
	if err != nil || thread.AuthorVerified || thread.AuthorIdentityID != "" {
		t.Fatal("token-only feedback failed or supplied verified authorship", err)
	}
	personID, personName := mustOpaqueID(t, "ident_"), "Independent reviewer"
	insertAuthorityIdentity(t, f.database, personID, "", false, f.now)
	if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.identities SET display_name=$2 WHERE id=$1`, personID, personName); err != nil {
		t.Fatal(err)
	}
	handoff, _ := f.browser(t, preview.ID, personID)
	cookie, err := f.database.RedeemServiceBrowserHandoff(t.Context(), f.auth(), handoff.Token, f.now)
	if err != nil {
		t.Fatal(err)
	}
	actor.BrowserCookieSecret, err = base64.RawURLEncoding.Strict().DecodeString(cookie.CookieSecret)
	if err != nil {
		t.Fatal(err)
	}
	thread, err = f.database.CreateFeedback(t.Context(), f.auth(), feedbackProofRequest(t, preview.ID, actor, "independent-author"), f.now)
	if err != nil || !thread.AuthorVerified || thread.AuthorIdentityID != personID ||
		thread.AuthorDisplayName != personName {
		t.Fatal("bearer replaced the independent current browser author", err)
	}
	if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.teams SET feedback_authors='signed_in' WHERE id=$1`, f.project.TeamID); err != nil {
		t.Fatal(err)
	}
	refresh := func() {
		t.Helper()
		issued, err := f.database.IssueVisitorToken(t.Context(), testVisitorIssuer, f.auth().Subject,
			GrantTokenSource{Credential: grant.RefreshCredential}, f.now)
		if err != nil {
			t.Fatal(err)
		}
		actor.VisitProof = FeedbackBearerVisitProof{Token: issued.Token}
	}
	refresh()
	anonymous := actor
	anonymous.BrowserCookieSecret = nil
	if _, err := f.database.CreateFeedback(t.Context(), f.auth(), feedbackProofRequest(t, preview.ID, anonymous, "requires-sign-in"), f.now); !errors.Is(err, ErrVisitorSignIn) {
		t.Fatal("token became a signed-in feedback author", err)
	}
	if _, err := f.database.CreateFeedback(t.Context(), f.auth(), feedbackProofRequest(t, preview.ID, actor, "signed-in-author"), f.now); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.teams SET feedback_authors='team_members' WHERE id=$1`, f.project.TeamID); err != nil {
		t.Fatal(err)
	}
	refresh()
	if _, err := f.database.CreateFeedback(t.Context(), f.auth(), feedbackProofRequest(t, preview.ID, actor, "requires-membership"), f.now); !errors.Is(err, ErrFeedbackAccess) {
		t.Fatal("grant creator membership became browser author membership", err)
	}
}

func TestIntegrationFeedbackBearerProofRechecksGrantAuthority(t *testing.T) {
	for _, change := range []string{"revoked", "expired", "creator", "parent", "kind", "service", "bearer-expiry", "policy", "key", "refresh", "certificate"} {
		t.Run(change, func(t *testing.T) {
			f := newServiceHTTPFixture(t)
			f.run = f.publish(t, f.service)
			preview := f.preview(t, "proof-"+change, f.service)
			parent := browserTestControlSession(t, f.database, f.project.ActorID, f.now)
			principal := ControlPrincipal{IdentityID: f.project.ActorID, SessionID: parent.SessionID}
			grant := feedbackProofGrant(t, f, WithControlPrincipal(t.Context(), principal))
			permission := feedbackBearerFacts(t, f, grant.Permission.VisitorToken)
			at := f.now
			var err error
			switch change {
			case "revoked":
				_, err = f.database.pool.Exec(t.Context(), `UPDATE control.service_http_grants SET revoked_at=$2 WHERE id=$1`, grant.GrantId, f.now)
			case "expired":
				_, err = f.database.pool.Exec(t.Context(), `UPDATE control.service_http_grants SET expires_at=$2 WHERE id=$1`, grant.GrantId, f.now.Add(time.Second))
				at = f.now.Add(2 * time.Second)
			case "creator":
				_, err = f.database.pool.Exec(t.Context(), `UPDATE control.visitor_grants SET revoked_at=$2 WHERE service_id=$1`, f.service.ID, f.now)
			case "parent":
				err = f.database.RevokeControlSession(t.Context(), principal, f.now)
			case "kind":
				subject := permission.Subject.(visitortoken.Grant)
				subject.Kind = "share"
				permission.Subject = subject
			case "service":
				other := f.local(t, "other", nil)
				permission.Scope.ID, permission.Hostname = other.ID, other.Endpoint.Hostname
			case "bearer-expiry":
				permission.ExpiresAt = f.now.Add(time.Second)
				at = f.now.Add(2 * time.Second)
			case "certificate":
				key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{42}, ed25519.SeedSize))
				digest, _ := visitortoken.KeyDigest(key.Public())
				permission.Subject = visitortoken.Certificate{Serial: "abc", KeySHA256: digest,
					Source: visitortoken.Device{IdentityID: f.project.ActorID, SessionID: parent.SessionID,
						DeviceID: "vdev_" + strings.Repeat("A", 22), KeySHA256: digest}}
			}
			if err != nil {
				t.Fatal(err)
			}
			token := signFeedbackProofFacts(t, f.database, permission, f.now)
			switch change {
			case "policy":
				_, err = f.database.pool.Exec(t.Context(), `UPDATE control.visitor_policies SET revision=revision+1 WHERE resource_kind='service' AND resource_id=$1`, f.service.ID)
			case "key":
				err = f.database.RotateVisitorSigningKey(t.Context(), testVisitorIssuer, true, f.now.Add(time.Millisecond))
				at = f.now.Add(time.Second)
			case "refresh":
				token = visitortoken.Token(grant.RefreshCredential)
			}
			if err != nil {
				t.Fatal(err)
			}
			actor := FeedbackActor{Kind: "reviewer", SourceIP: "192.0.2.9", VisitAllowed: true,
				VisitProof: FeedbackBearerVisitProof{Token: token}}
			if _, err := f.database.CreateFeedback(t.Context(), f.auth(), feedbackProofRequest(t, preview.ID, actor, "denied"), at); err == nil {
				t.Fatal("invalid explicit bearer proof authorized feedback")
			}
			var count int
			if err := f.database.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.feedback_threads WHERE preview_id=$1`, preview.ID).Scan(&count); err != nil || count != 0 {
				t.Fatal("denied proof persisted feedback", err)
			}
		})
	}
}

func TestIntegrationFeedbackExplicitPermissionNeverFallsBack(t *testing.T) {
	f := newServiceHTTPFixture(t)
	f.service = f.local(t, "anonymous", &config.HTTPService{Access: &config.Access{Mode: "anonymous"}})
	f.run = f.publish(t, f.service)
	preview := f.preview(t, "no-proof-fallback", f.service)
	grant := feedbackProofGrant(t, f, t.Context())
	valid := FeedbackBearerVisitProof{Token: visitortoken.Token(grant.Permission.VisitorToken)}
	for i, actor := range []FeedbackActor{
		{VisitProof: FeedbackBearerVisitProof{}},
		{VisitProof: FeedbackBearerVisitProof{Token: "malformed-private-token"}},
		{VisitProof: FeedbackConnectorVisitProof{}},
		{VisitProof: valid, ShareID: "shr_" + strings.Repeat("A", 22), ShareSecret: bytes.Repeat([]byte{1}, 32)},
		{VisitProof: valid, CookieSecret: bytes.Repeat([]byte{1}, 32)},
		{CookieSecret: bytes.Repeat([]byte{1}, 32)},
		{ShareSecret: bytes.Repeat([]byte{1}, 32)},
		{ShareID: "shr_" + strings.Repeat("A", 22)},
		{ShareID: "shr_" + strings.Repeat("A", 22), ShareSecret: bytes.Repeat([]byte{1}, 32), CookieSecret: []byte{1}},
	} {
		actor.Kind, actor.SourceIP, actor.VisitAllowed = "reviewer", "192.0.2.9", true
		request := feedbackProofRequest(t, preview.ID, actor, string(rune('a'+i)))
		if _, err := f.database.CreateFeedback(t.Context(), f.auth(), request, f.now); err == nil {
			t.Fatal("explicit invalid permission fell back to anonymous policy")
		}
	}
}

func TestIntegrationFeedbackShareBearerRequiresCapturedService(t *testing.T) {
	f := newServiceHTTPFixture(t)
	f.run = f.publish(t, f.service)
	other := f.local(t, "other", nil)
	preview := f.preview(t, "captured-share-proof", f.service, other)
	secret := bytes.Repeat([]byte{32}, 32)
	share := f.share(t, preview.ID, "other-service-share", secret, other)
	issued, err := f.database.IssueVisitorToken(t.Context(), testVisitorIssuer,
		visitorscope.Scope{Kind: visitorscope.Service, ID: other.ID},
		ShareTokenSource{ShareID: share.ID, Secret: base64.RawURLEncoding.EncodeToString(secret)}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	// a signed current service permission still needs the actual captured
	// membership of its share, not just a valid share identifier.
	permission := issued.Permission
	permission.Scope, permission.Hostname = f.auth().Subject, f.service.Endpoint.Hostname
	actor := FeedbackActor{Kind: "reviewer", SourceIP: "192.0.2.9",
		VisitProof: FeedbackBearerVisitProof{Token: signFeedbackProofFacts(t, f.database, permission, f.now)}}
	if _, err := f.database.CreateFeedback(t.Context(), f.auth(), feedbackProofRequest(t, preview.ID, actor, "not-captured"), f.now); !errors.Is(err, ErrFeedbackAccess) {
		t.Fatal("signed share proof substituted a service outside its captured membership", err)
	}
}

func TestIntegrationFeedbackBrowserAndShareBearerRecheckCurrentParents(t *testing.T) {
	for _, kind := range []string{"browser", "share"} {
		t.Run(kind, func(t *testing.T) {
			f := newServiceHTTPFixture(t)
			f.run = f.publish(t, f.service)
			preview := f.preview(t, "current-"+kind, f.service)
			parent := browserTestControlSession(t, f.database, f.project.ActorID, f.now)
			ctx := WithControlPrincipal(t.Context(), ControlPrincipal{IdentityID: f.project.ActorID, SessionID: parent.SessionID})
			var source VisitorTokenSource = BrowserTokenSource{}
			if kind == "share" {
				secret := bytes.Repeat([]byte{12}, 32)
				share, err := f.database.CreateShare(ctx, CreateShareRequest{TeamID: f.project.TeamID, ActingIdentityID: f.project.ActorID,
					PreviewID: preview.ID, IdempotencyKey: "bearer-share", SecretFingerprint: sha256.Sum256(secret),
					ExpiresAt: f.now.Add(time.Hour), ServiceIDs: []string{f.service.ID}, EntryServiceID: f.service.ID}, f.now)
				if err != nil {
					t.Fatal(err)
				}
				source = ShareTokenSource{ShareID: share.ID, Secret: base64.RawURLEncoding.EncodeToString(secret)}
			}
			issued, err := f.database.IssueVisitorToken(ctx, testVisitorIssuer, f.auth().Subject, source, f.now)
			if err != nil {
				t.Fatal(err)
			}
			actor := FeedbackActor{Kind: "reviewer", SourceIP: "192.0.2.9", VisitProof: FeedbackBearerVisitProof{Token: issued.Token}}
			thread, err := f.database.CreateFeedback(t.Context(), f.auth(), feedbackProofRequest(t, preview.ID, actor, "current"), f.now)
			if err != nil || thread.AuthorVerified || thread.AuthorIdentityID != "" {
				t.Fatal("source bearer rejected or promoted to verified author", err)
			}
			err = f.database.RevokeControlSession(t.Context(), ControlPrincipal{IdentityID: f.project.ActorID, SessionID: parent.SessionID}, f.now)
			if err != nil {
				t.Fatal(err)
			}
			actor.VisitProof = FeedbackBearerVisitProof{Token: signFeedbackProofFacts(t, f.database, issued.Permission, f.now)}
			auth := f.auth()
			actor.ServiceRun = &auth
			if _, err := f.database.AppendFeedback(t.Context(), AppendFeedbackRequest{FeedbackID: thread.ID, Type: FeedbackReply,
				Text: "revoked", IdempotencyKey: "revoked", Actor: actor}, f.now); err == nil {
				t.Fatal("signed bearer bypassed current source authority")
			}
		})
	}
}

func TestIntegrationFeedbackConnectorProofMatchesAdmittedBinding(t *testing.T) {
	d, now, _, leases := newConnectorPairPrerequisites(t)
	f := serviceHTTPFixture{database: d, now: now, project: appliedProjectRequest(t, d, now), leases: leases}
	f.service = f.local(t, "web", nil)
	f.run = f.publish(t, f.service)
	preview := f.preview(t, "connector-feedback", f.service)
	parent := browserTestControlSession(t, d, f.project.ActorID, now)
	ctx := WithControlPrincipal(t.Context(), ControlPrincipal{IdentityID: f.project.ActorID, SessionID: parent.SessionID})
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{27}, ed25519.SeedSize))
	device, err := d.EnrollVisitorDevice(ctx, f.project.ActorID, key.Public().(ed25519.PublicKey), now)
	if err != nil {
		t.Fatal(err)
	}
	var publisher string
	if err := d.pool.QueryRow(ctx, `SELECT publisher_identity_id FROM control.service_runs WHERE id=$1`, f.run.RunID).Scan(&publisher); err != nil {
		t.Fatal(err)
	}
	request := ConnectorPeerPairRequest{ServiceID: f.service.ID, ServiceRunID: f.run.RunID, RunNumber: f.run.RunNumber,
		PublisherIdentityID: publisher, IdempotencyKey: "feedback-owner",
		Subject: VisitorSubject{Kind: tunnelv1.VisitorHumanDevice, IdentityID: f.project.ActorID, DeviceID: device.ID},
		Source:  DeviceTokenSource{DeviceID: device.ID}, Action: "create", RequestedAt: now, ExpectedRelays: testConnectorPairRelays(f.run, leases)}
	sign := func() {
		t.Helper()
		message, err := request.proof().Message()
		if err != nil {
			t.Fatal(err)
		}
		request.Signature = ed25519.Sign(key, message)
	}
	sign()
	pair, err := d.PrepareConnectorPeerPair(ctx, request, now)
	if err != nil {
		t.Fatal(err)
	}
	for slot := range pair.Relays {
		if _, err := testClaimConnectorPeerPairLeg(t, d, ctx, pair.Relays[slot].RelayLease, netip.MustParseAddr("192.0.2.10"),
			testConnectorLegProof(t, pair, slot, now, key), now); err != nil {
			t.Fatal(err)
		}
	}
	if err := d.ConfirmConnectorPeerPairPrepared(ctx, f.service.ID, f.run.RunID, pair.ID, f.run.Token,
		ConnectorPeerPairPrepared{Phase: "installed", DeliveryID: pair.DeliveryID, DeliveryGeneration: pair.DeliveryGeneration,
			BindingExpiresAt: pair.ExpiresAt, OperationID: pair.OperationID, BindingChallenge: pair.BindingChallenge}, now); err != nil {
		t.Fatal(err)
	}
	request.Action, request.PreviousPairID, request.PreviousGeneration, request.RequestedAt = "renew", pair.ID, pair.DeliveryGeneration, now.Add(time.Millisecond)
	sign()
	renewed, err := d.RenewConnectorPeerPair(ctx, testVisitorIssuer, request, request.RequestedAt)
	if err != nil {
		t.Fatal(err)
	}
	proof := FeedbackConnectorVisitProof{PairID: pair.ID, DeliveryGeneration: pair.DeliveryGeneration, PermissionToken: renewed.VisitorPermission.Token}
	actor := FeedbackActor{Kind: "reviewer", SourceIP: "192.0.2.10", VisitProof: proof}
	at := now.Add(time.Second)
	thread, err := d.CreateFeedback(ctx, f.auth(), feedbackProofRequest(t, preview.ID, actor, "connector"), at)
	if err != nil || thread.AuthorVerified || thread.AuthorIdentityID != "" {
		t.Fatal("admitted connector rejected or device became verified author", err)
	}
	for _, change := range []string{"pair", "generation", "run", "source", "subject", "key", "parent", "bearer"} {
		t.Run(change, func(t *testing.T) {
			bad, badActor, auth := proof, actor, f.auth()
			permission := renewed.VisitorPermission.Permission
			switch change {
			case "pair":
				bad.PairID = "cpp_" + strings.Repeat("Z", 22)
			case "generation":
				bad.DeliveryGeneration++
			case "run":
				auth.Number++
			case "source":
				badActor.SourceIP = "192.0.2.11"
			case "subject", "key", "parent":
				subject := permission.Subject.(visitortoken.Device)
				if change == "subject" {
					subject.DeviceID = "vdev_" + strings.Repeat("Z", 22)
				} else if change == "parent" {
					subject.SessionID = "cs_" + strings.Repeat("Z", 22)
				} else {
					subject.KeySHA256, _ = visitortoken.KeyDigest(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{99}, ed25519.SeedSize)).Public())
				}
				permission.Subject = subject
				bad.PermissionToken = signFeedbackProofFacts(t, d, permission, request.RequestedAt)
			case "bearer":
				badActor.VisitProof = FeedbackBearerVisitProof{Token: proof.PermissionToken}
			}
			if change != "bearer" {
				badActor.VisitProof = bad
			}
			if _, err := d.CreateFeedback(ctx, auth, feedbackProofRequest(t, preview.ID, badActor, "wrong-"+change), at); err == nil {
				t.Fatal("connector proof escaped its checked admitted binding")
			}
		})
	}
	if _, err := d.pool.Exec(ctx, `UPDATE control.connector_peer_pairs SET publisher_prepared_until=NULL WHERE id=$1`, pair.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.CreateFeedback(ctx, f.auth(), feedbackProofRequest(t, preview.ID, actor, "not-installed"), at); err == nil {
		t.Fatal("uninstalled connector binding authorized feedback")
	}
	if _, err := d.pool.Exec(ctx, `UPDATE control.connector_peer_pairs SET publisher_prepared_until=expires_at WHERE id=$1`, pair.ID); err != nil {
		t.Fatal(err)
	}
	if err := d.RevokeControlSession(ctx, ControlPrincipal{IdentityID: f.project.ActorID, SessionID: parent.SessionID}, at); err != nil {
		t.Fatal(err)
	}
	if _, err := d.CreateFeedback(ctx, f.auth(), feedbackProofRequest(t, preview.ID, actor, "revoked-parent"), at); err == nil {
		t.Fatal("connector permission outlived its actual parent session")
	}
}

func TestIntegrationFeedbackProofLockWaitCannotCommitExpiredAuthority(t *testing.T) {
	for _, operation := range []string{"create", "append", "scope"} {
		t.Run(operation, func(t *testing.T) {
			f := newServiceHTTPFixture(t)
			f.run = f.publish(t, f.service)
			preview := f.preview(t, "expiry-"+operation, f.service)
			grant := feedbackProofGrant(t, f, t.Context())
			permission := feedbackBearerFacts(t, f, grant.Permission.VisitorToken)
			actor := FeedbackActor{Kind: "reviewer", SourceIP: "192.0.2.9",
				VisitProof: FeedbackBearerVisitProof{Token: visitortoken.Token(grant.Permission.VisitorToken)}}
			var thread FeedbackThread
			var err error
			if operation == "append" {
				thread, err = f.database.CreateFeedback(t.Context(), f.auth(), feedbackProofRequest(t, preview.ID, actor, "original"), f.now)
				if err != nil {
					t.Fatal(err)
				}
			}
			permission.ExpiresAt = f.now.Truncate(time.Second).Add(2 * time.Second)
			actor.VisitProof = FeedbackBearerVisitProof{Token: signFeedbackProofFacts(t, f.database, permission, f.now)}
			auth := f.auth()
			actor.ServiceRun = &auth
			request := feedbackProofRequest(t, preview.ID, actor, "expired-write")
			gate, err := f.database.pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, gate)
			if operation == "scope" {
				err = lockServiceAdmission(t.Context(), gate, f.service.ID)
			} else {
				_, err = gate.Exec(t.Context(), `SELECT next_cursor FROM control.feedback_event_clock WHERE id=1 FOR UPDATE`)
			}
			if err != nil {
				t.Fatal(err)
			}
			entered := make(chan time.Time, 1)
			done, join := connectorPairWorker(t, t.Context(), func(ctx context.Context) error {
				entered <- time.Now()
				switch operation {
				case "create":
					_, err := f.database.CreateFeedback(ctx, auth, request, f.now)
					return err
				case "append":
					_, err := f.database.AppendFeedback(ctx, AppendFeedbackRequest{FeedbackID: thread.ID, Type: FeedbackReply,
						Text: "expired", IdempotencyKey: "expired-write", Actor: actor}, f.now)
					return err
				default:
					team, service, err := f.database.ReviewerFeedbackScope(ctx, auth, preview.ID, actor, f.now)
					if err != nil && (team != "" || service != "") {
						return errors.New("denied scope returned authorized identifiers")
					}
					return err
				}
			})
			defer join()
			ctx, stop := context.WithTimeout(t.Context(), 5*time.Second)
			defer stop()
			waitForPostgresBlock(t, ctx, f.database, int32(gate.Conn().PgConn().PID()), done)
			started := awaitIntegrationResult(t, ctx, entered)
			timer := time.NewTimer(max(0, time.Until(started.Add(permission.ExpiresAt.Sub(f.now)+20*time.Millisecond))))
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-ctx.Done():
				t.Fatal(context.Cause(ctx))
			}
			if err := gate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err := awaitIntegrationResult(t, ctx, done); !errors.Is(err, ErrFeedbackAccess) {
				t.Fatal("lock wait committed expired feedback authority", err)
			}
			var reports, events int
			if err := f.database.pool.QueryRow(ctx, `SELECT
			    (SELECT count(*) FROM control.feedback_threads WHERE preview_id=$1),
			    (SELECT count(*) FROM control.feedback_events event JOIN control.feedback_threads thread ON thread.id=event.feedback_id WHERE thread.preview_id=$1)`,
				preview.ID).Scan(&reports, &events); err != nil {
				t.Fatal(err)
			}
			want := 0
			if operation == "append" {
				want = 1
			}
			if reports != want || events != want {
				t.Fatal("expired operation left feedback writes", reports, events)
			}
		})
	}
}

func TestIntegrationFeedbackGuestShareBearerNeedsNoRedundantSecret(t *testing.T) {
	f, _ := guestAuthorityFixture(t, true)
	auth := ServiceHTTPRun{Subject: visitorscope.Scope{Kind: visitorscope.Service, ID: f.service.ID},
		RunID: f.run.RunID, Number: f.run.RunNumber, Token: credentials.ServiceRunToken(f.run.Token)}
	preview, err := f.database.CreateServiceRunPreview(f.ctx, auth, f.now)
	if err != nil {
		t.Fatal(err)
	}
	secret := bytes.Repeat([]byte{9}, 32)
	share, err := f.database.CreateGuestShare(f.ctx, guestCredentialForTest(f.guest), f.service.ID, "proof-share", "", sha256.Sum256(secret), f.now.Add(time.Hour), f.now)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := f.database.IssueVisitorToken(f.ctx, testVisitorIssuer, auth.Subject,
		ShareTokenSource{ShareID: share.ID, Secret: base64.RawURLEncoding.EncodeToString(secret)}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	actor := FeedbackActor{Kind: "reviewer", SourceIP: "192.0.2.9", VisitProof: FeedbackBearerVisitProof{Token: issued.Token}}
	thread, err := f.database.CreateFeedback(f.ctx, auth, feedbackProofRequest(t, preview.ID, actor, "guest-bearer"), f.now)
	if err != nil || thread.GuestID != f.guest.ID || thread.AuthorVerified {
		t.Fatal("actual guest share bearer required redundant browser credentials", err)
	}
}
