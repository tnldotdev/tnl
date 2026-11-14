// package visitorfixture also supplies the authority-side HTTP session fixture.
package visitorfixture

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

const PublicURLID = "url_0123456789abcdefghijkl"

type HTTPSource struct{ BrowserCookieSecret, ShareId, ShareCookieSecret *string }

func (*HTTPControl) ReportHTTPProtectionRejections(context.Context, controlv1.ReportHTTPProtectionRejectionsRequest, string) error {
	return errors.New("unexpected HTTP protection report")
}

type HTTPDecision struct {
	VisitAllowed bool
	ValidUntil   *time.Time
}
type HTTPControl struct {
	Mu       sync.Mutex
	Check    func(HTTPSource) (HTTPDecision, error)
	Calls    int
	Revision int64
	Sources  map[string]HTTPSource
	Allowed  map[string]bool
	Issued   map[string]visitortoken.Token
	Lease    *visitorlease.Lease
	Prepare  func(context.Context, json.RawMessage, controlv1.VisitorTokenResponse, time.Time) error
}

func (c *HTTPControl) Init() {
	c.Revision = 1
	c.Sources = make(map[string]HTTPSource)
	c.Allowed = make(map[string]bool)
	c.Issued = make(map[string]visitortoken.Token)
}
func BrowserSource(secret string) json.RawMessage {
	source, _ := json.Marshal(controlv1.VisitorTokenBrowserSessionSource{Kind: controlv1.VisitorTokenBrowserSession, Secret: secret})
	return source
}
func (c *HTTPControl) ReadPublisherVisitorPolicy(_ context.Context, body controlv1.PublisherVisitorPolicyRequest, _ string) (controlv1.VisitorPolicyUpdate, error) {
	c.Mu.Lock()
	defer c.Mu.Unlock()
	for key, input := range c.Sources {
		decision, err := c.Check(input)
		c.Calls++
		if errors.Is(err, clientcontrol.ErrUnavailable) {
			return controlv1.VisitorPolicyUpdate{}, err
		}
		allowed := err == nil && decision.VisitAllowed && decision.ValidUntil != nil && decision.ValidUntil.After(time.Now())
		if allowed != c.Allowed[key] {
			c.Revision++
			c.Allowed[key] = allowed
		}
	}
	now := time.Now()
	key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("l", 32)))
	events := []int64{}
	if body.AfterRevision != 0 {
		for next := body.AfterRevision + 1; next <= c.Revision; next++ {
			events = append(events, next)
		}
	}
	return controlv1.VisitorPolicyUpdate{AfterRevision: body.AfterRevision, Revisions: events, SnapshotRequired: body.AfterRevision == 0,
		VisitorSourceKey: SourceKeyBytes(),
		Policy: controlv1.VisitorPolicySnapshot{Resource: body.Resource, Hostname: "route.example", Port: 443, Issuer: "https://control.example.test", Enabled: true,
			VisitorPolicyRevision: c.Revision, KeyRevision: 1, ObservedAt: now, ValidUntil: now.Add(10 * time.Second),
			VerificationKeys: []controlv1.VisitorVerificationKey{{Id: "live", PublicKey: key.Public().(ed25519.PublicKey)}}, WorkloadLeases: []controlv1.VisitorWorkloadLease{}}}, nil
}

func (c *HTTPControl) IssueVisitorToken(_ context.Context, body controlv1.VisitorTokenRequest) (controlv1.VisitorTokenResponse, error) {
	var source struct {
		Kind    string `json:"kind"`
		Secret  string `json:"secret"`
		ShareID string `json:"share_id"`
	}
	if json.Unmarshal(body.Source, &source) != nil {
		return controlv1.VisitorTokenResponse{}, errors.New("invalid fixture token source")
	}
	keyID := source.Kind + ":" + source.ShareID + ":" + source.Secret
	c.Mu.Lock()
	defer c.Mu.Unlock()
	input, exists := c.Sources[keyID]
	if !exists {
		return controlv1.VisitorTokenResponse{}, &clientcontrol.ProblemError{Status: http.StatusForbidden}
	}
	decision, err := c.Check(input)
	c.Calls++
	if err != nil {
		if errors.Is(err, clientcontrol.ErrUnauthenticated) {
			return controlv1.VisitorTokenResponse{}, &clientcontrol.ProblemError{Status: http.StatusUnauthorized}
		}
		return controlv1.VisitorTokenResponse{}, err
	}
	if !decision.VisitAllowed || decision.ValidUntil == nil || !decision.ValidUntil.After(time.Now()) {
		return controlv1.VisitorTokenResponse{}, &clientcontrol.ProblemError{Status: http.StatusForbidden}
	}
	digest := sha256.Sum256([]byte(keyID))
	id := hex.EncodeToString(digest[:11])
	var subject visitortoken.Subject = visitortoken.Browser{IdentityID: "ident_" + id, SessionID: "cs_" + id}
	if source.Kind == "share_session" {
		subject = visitortoken.Share{ShareID: source.ShareID}
	}
	permission := visitortoken.Permission{Scope: visitorscope.Scope{Kind: visitorscope.PublicURL, ID: PublicURLID}, Hostname: "route.example", Port: 443,
		VisitorPolicyRevision: c.Revision, Subject: subject, ExpiresAt: decision.ValidUntil.Truncate(time.Second)}
	private := ed25519.NewKeyFromSeed([]byte(strings.Repeat("l", 32)))
	token, err := visitortoken.Sign("https://control.example.test", "live", private, permission, time.Now())
	if err != nil {
		return controlv1.VisitorTokenResponse{}, err
	}
	c.Issued[keyID] = token
	return controlv1.VisitorTokenResponse{Resource: body.Resource, Hostname: permission.Hostname, Port: 443, VisitorPolicyRevision: c.Revision,
		ExpiresAt: permission.ExpiresAt, VisitorToken: token.Reveal()}, nil
}

func (c *HTTPControl) Credential(t *testing.T, cookie string, share bool) string {
	t.Helper()
	kind, shareID := "browser_session", ""
	input := HTTPSource{BrowserCookieSecret: &cookie}
	var source json.RawMessage
	if share {
		kind, shareID = "share_session", "shr_0123456789abcdefghijkl"
		input.BrowserCookieSecret, input.ShareId, input.ShareCookieSecret = nil, &shareID, &cookie
		source, _ = json.Marshal(controlv1.VisitorTokenShareSessionSource{Kind: controlv1.VisitorTokenShareSession, ShareId: shareID, Secret: cookie})
	} else {
		source = BrowserSource(cookie)
	}
	key := kind + ":" + shareID + ":" + cookie
	c.Mu.Lock()
	if token, exists := c.Issued[key]; exists {
		c.Mu.Unlock()
		return token.Reveal()
	}
	c.Sources[key], c.Allowed[key] = input, true
	c.Mu.Unlock()
	response, err := c.IssueVisitorToken(t.Context(), controlv1.VisitorTokenRequest{Resource: controlv1.VisitorResourceScope{Kind: "public_url", Id: PublicURLID}, Source: source})
	if err != nil {
		return "invalid-visitor-permission"
	}
	if err := c.Prepare(t.Context(), source, response, time.Now().Add(30*time.Minute)); err != nil {
		t.Fatal(err)
	}
	c.Mu.Lock()
	c.Issued[key] = visitortoken.Token(response.VisitorToken)
	c.Mu.Unlock()
	return response.VisitorToken
}

func (c *HTTPControl) Permission(t *testing.T, cookie string, share bool) controlv1.VisitorTokenResponse {
	t.Helper()
	token := c.Credential(t, cookie, share)
	view, _, _ := c.Lease.Current()
	permission, err := visitortoken.VerifyBearer(visitortoken.Token(token), view, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return controlv1.VisitorTokenResponse{Resource: controlv1.VisitorResourceScope{Kind: "public_url", Id: view.Scope.ID}, Hostname: view.Hostname, Port: int(view.Port),
		VisitorPolicyRevision: permission.Facts().VisitorPolicyRevision, ExpiresAt: permission.Facts().ExpiresAt, VisitorToken: token}
}
