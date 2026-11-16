package state

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/security/visitortoken"
)

func TestIntegrationShareHandoffKeepsRunCaptureOnlyUntilRedemption(t *testing.T) {
	f := newServiceHTTPFixture(t)
	f.run = f.publish(t, f.service)
	api := f
	api.service = f.local(t, "api", nil)
	if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.services SET publisher_pool=true WHERE id=$1`, api.service.ID); err != nil {
		t.Fatal(err)
	}
	api.service.PublisherPool = true
	api.run = api.publish(t, api.service)
	sibling := api
	sibling.run = sibling.publish(t, sibling.service)
	preview := f.preview(t, "handoff-restart", f.service, api.service)
	secret := bytes.Repeat([]byte{37}, 32)
	share := f.share(t, preview.ID, "handoff-restart", secret, f.service, api.service)
	initial, err := f.database.RedeemShare(t.Context(), f.auth(), share.ID, secret, nil, f.now)
	if err != nil {
		t.Fatal(err)
	}
	next, err := url.Parse(initial.NextURL)
	if err != nil || next.Hostname() != api.service.Endpoint.Hostname {
		t.Fatal("share did not hand off to the other service", err)
	}
	ticket, err := base64.RawURLEncoding.Strict().DecodeString(strings.TrimPrefix(next.Path, "/__tnl/share/handoff/"))
	if err != nil || len(ticket) != 32 {
		t.Fatal("share did not issue a valid handoff ticket", err)
	}
	later := api
	later.run = later.publish(t, later.service)
	if _, err := f.database.RedeemShare(t.Context(), later.auth(), "", nil, ticket, f.now); !errors.Is(err, ErrShareNotFound) {
		t.Fatal("a later ready run redeemed an unconsumed ticket outside its capture", err)
	}
	digest := sha256.Sum256(ticket)
	var unconsumed bool
	if err := f.database.pool.QueryRow(t.Context(), `SELECT consumed_at IS NULL FROM control.share_handoffs WHERE token_digest=$1`, digest[:]).Scan(&unconsumed); err != nil || !unconsumed {
		t.Fatal("rejected replacement consumed the captured run's ticket", err)
	}
	if err := f.database.CloseServiceRun(t.Context(), api.service.ID, api.run.RunID, api.run.Token, f.now); err != nil {
		t.Fatal(err)
	}
	installed, err := f.database.RedeemShare(t.Context(), sibling.auth(), "", nil, ticket, f.now)
	if err != nil || installed.ShareID != share.ID {
		t.Fatal("closing a captured run prevented its captured sibling from redeeming", err)
	}
	if _, err := f.database.RedeemShare(t.Context(), sibling.auth(), "", nil, ticket, f.now); !errors.Is(err, ErrShareNotFound) {
		t.Fatal("a consumed handoff ticket was replayed", err)
	}
	if err := f.database.CloseServiceRun(t.Context(), sibling.service.ID, sibling.run.RunID, sibling.run.Token, f.now); err != nil {
		t.Fatal(err)
	}
	source := ShareSessionTokenSource{ShareID: share.ID, Secret: installed.CookieSecret, RunID: later.run.RunID}
	permission, err := f.database.IssueVisitorToken(t.Context(), testVisitorIssuer, later.auth().Subject, source, f.now)
	if err != nil || permission.Permission.Subject != (visitortoken.Share{ShareID: share.ID}) {
		t.Fatal("installed handoff cookie could not obtain permission after its captured runs closed", err)
	}
	if permission.Permission.ExpiresAt.After(installed.ExpiresAt) {
		t.Fatal("current-run permission extended the handoff cookie's original deadline")
	}
	if _, err := f.database.RedeemShare(t.Context(), sibling.auth(), share.ID, secret, nil, f.now); err == nil {
		t.Fatal("initial link redemption accepted a closed exact run")
	}
	if _, err := f.database.RedeemShare(t.Context(), later.auth(), share.ID, secret, nil, f.now); err != nil {
		t.Fatal("initial link redemption rejected the current ready run", err)
	}
}
