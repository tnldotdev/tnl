package state

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
)

func TestIntegrationReviewerSessionsObtainCurrentPermissionAfterAppRestart(t *testing.T) {
	f := newServiceHTTPFixture(t)
	f.run = f.publish(t, f.service)
	preview := f.preview(t, "reviewer-restart", f.service)
	reviewer := finalVisitorIdentity(t, f.database, f.now, "restart-reviewer@example.test")
	browser := feedbackBrowserSecret(t, t.Context(), f, preview.ID, reviewer)
	pending, _ := f.browser(t, preview.ID, reviewer)
	secret := bytes.Repeat([]byte{23}, 32)
	share := f.share(t, preview.ID, "restart-share", secret, f.service)
	redemption, err := f.database.RedeemShare(t.Context(), f.auth(), share.ID, secret, nil, f.now)
	if err != nil {
		t.Fatal(err)
	}
	old := f.auth()
	ownerLogin, _ := f.browser(t, "", f.project.ActorID)
	ownerBrowser, err := f.database.RedeemServiceBrowserHandoff(t.Context(), old, ownerLogin.Token, f.now)
	if err != nil {
		t.Fatal(err)
	}
	ownerSource := BrowserSessionTokenSource{Secret: ownerBrowser.CookieSecret}
	if _, err := f.database.IssueVisitorToken(t.Context(), testVisitorIssuer, old.Subject, ownerSource, f.now); err != nil {
		t.Fatal("initial browser-only permission", err)
	}
	source := ShareSessionTokenSource{ShareID: share.ID, Secret: redemption.CookieSecret}
	issued, err := f.database.IssueVisitorToken(t.Context(), testVisitorIssuer, old.Subject, source, f.now)
	if err != nil {
		t.Fatal(err)
	}
	actor := FeedbackActor{Kind: "reviewer", SourceIP: "192.0.2.9", BrowserCookieSecret: browser,
		VisitProof: FeedbackBearerVisitProof{Token: issued.Token}}
	first, err := f.database.CreateFeedback(t.Context(), old, feedbackProofRequest(t, preview.ID, actor, "before-restart"), f.now)
	if err != nil || first.AuthorIdentityID != reviewer || !first.AuthorVerified {
		t.Fatal("initial reviewer feedback lost verified authorship", err)
	}
	if err := f.database.CloseServiceRun(t.Context(), old.Subject.ID, old.RunID, old.Token.String(), f.now); err != nil {
		t.Fatal(err)
	}
	f.run = f.publish(t, f.service)
	current := f.auth()
	if current.RunID == old.RunID || current.Number <= old.Number {
		t.Fatal("app restart did not create a new run")
	}
	// one-use login tickets still belong only to their initiating run.
	if _, err := f.database.RedeemServiceBrowserHandoff(t.Context(), current, pending.Token, f.now); !errors.Is(err, ErrVisitorSignIn) {
		t.Fatal("unredeemed login ticket crossed run replacement", err)
	}
	cookie := base64.RawURLEncoding.EncodeToString(browser)
	if _, err := f.database.ServiceBrowserSession(t.Context(), old, cookie, false, f.now); err == nil {
		t.Fatal("old run regained browser authority")
	}
	identity, err := f.database.ServiceBrowserSession(t.Context(), current, cookie, false, f.now)
	if err != nil || identity.IdentityID != reviewer || identity.VisitAllowed {
		t.Fatal("installed browser identity did not survive restart independently of visit permission", err)
	}
	ownerPermission, err := f.database.IssueVisitorToken(t.Context(), testVisitorIssuer, current.Subject, ownerSource, f.now)
	if err != nil {
		t.Fatal("browser-only session could not obtain current permission", err)
	}
	if ownerPermission.Permission.ExpiresAt.After(ownerBrowser.ExpiresAt) {
		t.Fatal("restart extended the original browser session deadline")
	}
	staleSource := source
	staleSource.RunID = old.RunID
	if _, err := f.database.IssueVisitorToken(t.Context(), testVisitorIssuer, current.Subject, staleSource, f.now); !errors.Is(err, ErrVisitorPermission) {
		t.Fatal("installed share cookie revived an explicitly requested old run", err)
	}
	source.RunID = current.RunID
	fresh, err := f.database.IssueVisitorToken(t.Context(), testVisitorIssuer, current.Subject, source, f.now)
	if err != nil || fresh.Permission.Subject != (visitortoken.Share{ShareID: share.ID}) {
		t.Fatal("installed share session could not obtain current permission", err)
	}
	if fresh.Permission.ExpiresAt.After(redemption.ExpiresAt) {
		t.Fatal("restart extended the original share session deadline")
	}
	actor.VisitProof = FeedbackBearerVisitProof{Token: fresh.Token}
	second, err := f.database.CreateFeedback(t.Context(), current, feedbackProofRequest(t, preview.ID, actor, "after-restart"), f.now)
	if err != nil || second.ServiceRunID != current.RunID || second.AuthorIdentityID != reviewer || !second.AuthorVerified {
		t.Fatal("same reviewer cookies could not leave feedback after restart", err)
	}
	added := f.local(t, "added", nil)
	if _, err := f.database.AddPreviewService(t.Context(), AddPreviewServiceRequest{
		PreviewID: preview.ID, ServiceID: added.ID, TeamID: f.project.TeamID, IdentityID: f.project.ActorID,
	}, f.now); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.IssueVisitorToken(t.Context(), testVisitorIssuer, visitorscope.Scope{Kind: visitorscope.Service, ID: added.ID}, source, f.now); !errors.Is(err, ErrVisitorPermission) {
		t.Fatal("old share expanded to a newly added preview service", err)
	}
	if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.identities SET disabled_at=$2 WHERE id=$1`, f.project.ActorID, f.now); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.IssueVisitorToken(t.Context(), testVisitorIssuer, current.Subject, source, f.now); !errors.Is(err, ErrVisitorPermission) {
		t.Fatal("reviewer session outlived its share creator's authority", err)
	}
	if _, err := f.database.CreateFeedback(t.Context(), current, feedbackProofRequest(t, preview.ID, actor, "revoked-creator"), f.now); err == nil {
		t.Fatal("verified reviewer feedback outlived its share creator's authority")
	}
}
