//go:build !js || !wasm

package service

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	"github.com/tnldotdev/tnl/internal/publisher/requestlimit"
	servicestream "github.com/tnldotdev/tnl/internal/publisher/service/stream"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/testutil/visitorfixture"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type feedbackProofControl struct {
	HTTPControl
	pages  chan controlv1.PreviewPageFeedbackRequest
	denied atomic.Bool
}

func (c *feedbackProofControl) AuthorizeReviewerFeedback(_ context.Context, service, run string, input controlv1.AuthorizeReviewerFeedbackRequest, _ credentials.ServiceRunToken) (controlv1.FeedbackAuthorization, error) {
	c.pages <- controlv1.PreviewPageFeedbackRequest{PreviewId: input.PreviewId, RunNumber: input.RunNumber, Access: input.Access}
	if c.denied.Load() {
		return controlv1.FeedbackAuthorization{}, errors.New("private upstream failure: " + string(input.Access.VisitProof))
	}
	return testFeedbackDecision(service, run, input), nil
}

func feedbackProofRuntime(t *testing.T, frontend *HTTP, control *feedbackProofControl) {
	t.Helper()
	frontend.Control = serviceHTTPControl{HTTPControl: control}
	frontend.State = testFeedbackState(t)
	frontend.Feedback, frontend.PreviewID, frontend.ProjectService, frontend.Demo = true, "pv_0123456789abcdefghijkl", "web", true
	runtime, err := newFeedbackRuntime(*frontend)
	if err != nil {
		t.Fatal(err)
	}
	frontend.feedback, frontend.ResponseHooks = runtime, runtime.responseHooks(frontend.ResponseHooks)
}

func TestFeedbackVisitProofPreservesExplicitNullForRejection(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		body := `{"visit_allowed":true}`
		if explicit {
			body = `{"visit_allowed":true,"visit_proof":null}`
		}
		var access controlv1.FeedbackReviewerAccess
		if err := json.Unmarshal([]byte(body), &access); err != nil {
			t.Fatal(err)
		}
		if (len(access.VisitProof) != 0) != explicit || explicit && string(access.VisitProof) != "null" {
			t.Fatal("explicit invalid proof was normalized into absent anonymous proof")
		}
		encoded, err := json.Marshal(access)
		if err != nil || strings.Contains(string(encoded), `"visit_proof":null`) != explicit {
			t.Fatal("proof presence was lost at the API/state boundary", err)
		}
	}
}

func TestFeedbackBearerProofUsesSelectedRenewalAndIndependentAuthor(t *testing.T) {
	control := &feedbackProofControl{pages: make(chan controlv1.PreviewPageFeedbackRequest, 8)}
	var initial, renewed controlv1.VisitorTokenResponse
	client, _, _, _ := serviceHTTPConfiguredFixture(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("reserved feedback reached the application")
	}), false, true, func(frontend *HTTP) {
		key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("p", 32)))
		policy, err := httpaccess.PreparePolicy(t.Context(), &visitorfixture.PolicyClient{Key: key}, frontend.Subject, frontend.RunID, frontend.Number, "run-secret", nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(policy.Close)
		issuer := &visitorfixture.TokenClient{Issue: func(context.Context, controlv1.VisitorTokenRequest) (controlv1.VisitorTokenResponse, error) {
			return controlv1.VisitorTokenResponse{}, errors.New("authority unavailable")
		}}
		tokens, err := httpaccess.StartTokens(t.Context(), issuer, policy.Lease(), nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(tokens.Close)
		browser := &httpaccess.Browser{Policy: policy, Tokens: tokens}
		view, _, _ := policy.Lease().Current()
		sign := func(until time.Time) controlv1.VisitorTokenResponse {
			permission := visitortoken.Permission{Scope: frontend.Subject, Hostname: frontend.Hostname, Port: 443, VisitorPolicyRevision: 1,
				Subject: visitortoken.Browser{IdentityID: "ident_" + strings.Repeat("C", 22), SessionID: "cs_" + strings.Repeat("D", 22)}, ExpiresAt: until.Truncate(time.Second)}
			token, err := visitortoken.Sign(view.Issuer, "test-key", key, permission, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			return controlv1.VisitorTokenResponse{Resource: controlv1.VisitorResourceScope{Kind: "service", Id: frontend.Subject.ID},
				Hostname: frontend.Hostname, Port: 443, VisitorPolicyRevision: 1, ExpiresAt: permission.ExpiresAt, VisitorToken: token.Reveal()}
		}
		initial, renewed = sign(time.Now().Add(time.Minute)), sign(time.Now().Add(2*time.Minute))
		source := visitorfixture.BrowserSource(visitorfixture.BrowserCookie)
		parent := time.Now().Add(30 * time.Minute)
		for _, response := range []controlv1.VisitorTokenResponse{initial, renewed} {
			if _, err := browser.PrepareToken(t.Context(), source, response, parent); err != nil {
				t.Fatal(err)
			}
		}
		frontend.Policy, frontend.browser = policy.Lease(), browser
		feedbackProofRuntime(t, frontend, control)
	})
	for _, cookie := range []bool{false, true} {
		for _, author := range []bool{false, true} {
			request, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://preview.example.test/__tnl/feedback", nil)
			if cookie {
				request.AddCookie(&http.Cookie{Name: httpaccess.VisitorTokenCookie, Value: initial.VisitorToken})
			} else {
				request.Header.Set(httpaccess.VisitorTokenHeader, initial.VisitorToken)
			}
			if author {
				request.AddCookie(&http.Cookie{Name: httpaccess.BrowserCookieName, Value: visitorfixture.BrowserCookie})
			}
			request.Header.Set("X-Forwarded-For", "203.0.113.99")
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil || response.StatusCode != http.StatusOK {
				t.Fatal("selected bearer feedback failed", response.StatusCode, err)
			}
			access := (<-control.pages).Access
			var proof controlv1.FeedbackBearerVisitProof
			if access.VisitProof == nil || json.Unmarshal(access.VisitProof, &proof) != nil || proof.Kind != controlv1.FeedbackVisitBearer ||
				proof.Token != renewed.VisitorToken || access.SourceIp == nil || *access.SourceIp != "192.0.2.1" ||
				(access.BrowserCookieSecret != nil) != author || access.ShareId != nil || access.CookieSecret != nil {
				t.Fatal("selected proof, trusted source, or independent browser author changed")
			}
			cookies := response.Cookies()
			if len(cookies) != 1 || cookies[0].Value != proof.Token ||
				strings.Contains(string(body), proof.Token) || strings.Contains(string(body), visitorfixture.BrowserCookie) {
				t.Fatal("feedback response exposed proof or disagreed with its accepted replacement")
			}
		}
	}
}

func TestFeedbackConnectorProofUsesActualAdmissionAndAcceptedRenewal(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	var appCalls atomic.Int64
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		appCalls.Add(1)
		if r.Header.Get(httpaccess.VisitorTokenHeader) != "" || strings.Contains(r.Header.Get("Cookie"), "__Host-tnl-") ||
			r.Header.Get("Authorization") != "application-secret" {
			t.Error("connector proof or publisher cookies reached the application")
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<html><head></head><body>app</body></html>")
	}))
	defer app.Close()
	bound, peer, trust, opening, _ := connectorPeerFixture(t, app.Listener.Addr().String())
	bound.prepared.managedProtocol = config.ProtocolHTTP
	budget, err := requestlimit.NewHTTP(&controlv1.ProjectHTTPApplicationLimits{Total: new(1)})
	if err != nil {
		t.Fatal(err)
	}
	bound.prepared.serviceHTTPRequests = budget
	control := &feedbackProofControl{pages: make(chan controlv1.PreviewPageFeedbackRequest, 8)}
	view, _, _ := bound.prepared.policy.Current()
	frontend := HTTP{Subject: view.Scope, RunID: bound.prepared.Preparation.ServiceRunId,
		Number: bound.prepared.Preparation.RunNumber, Hostname: bound.prepared.managedHostname, Policy: bound.prepared.policy}
	feedbackProofRuntime(t, &frontend, control)
	bound.prepared.connectorHTTP, bound.prepared.httpResponseHooks = frontend, frontend.ResponseHooks
	client, server := connectorInnerPair(t, ctx, trust)
	served := make(chan error, 1)
	go func() { served <- serveConnectorInner(ctx, peer, server) }()
	defer func() { peer.Close(); <-served }()
	writer := connectorControl(t, ctx, client, peer)
	entry := opening("F")
	raw, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tunnelv1.WriteConnectorPeerVisitorOpening(raw, entry, nil); err != nil {
		t.Fatal(err)
	}
	secured := connectorVisitorTLS(raw, trust, entry.VisitorConnectionID)
	defer secured.Close()
	if err := secured.HandshakeContext(ctx); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(secured)
	call := func(path string) (*http.Response, []byte) {
		t.Helper()
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://127.0.0.1:15432"+path, nil)
		request.Header.Set("X-Forwarded-For", "203.0.113.99")
		request.Header.Set("Forwarded", "for=203.0.113.99")
		request.Header.Set("Authorization", "application-secret")
		request.AddCookie(&http.Cookie{Name: httpaccess.BrowserCookieName, Value: visitorfixture.BrowserCookie})
		if err := request.Write(secured); err != nil {
			t.Fatal(err)
		}
		response, err := http.ReadResponse(reader, request)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		return response, body
	}
	check := func(token string) {
		t.Helper()
		response, body := call("/__tnl/feedback")
		if response.StatusCode != http.StatusOK || strings.Contains(string(body), token) || strings.Contains(string(body), visitorfixture.BrowserCookie) {
			t.Fatal("connector reserved feedback failed or exposed proof", response.StatusCode)
		}
		access := (<-control.pages).Access
		var proof controlv1.FeedbackConnectorVisitProof
		if access.VisitProof == nil || json.Unmarshal(access.VisitProof, &proof) != nil || proof.Kind != controlv1.FeedbackVisitConnector ||
			proof.PairId != entry.PairID || proof.DeliveryGeneration != entry.DeliveryGeneration || proof.PermissionToken != token ||
			access.SourceIp == nil || *access.SourceIp != entry.SourceIP || access.BrowserCookieSecret == nil ||
			*access.BrowserCookieSecret != visitorfixture.BrowserCookie {
			t.Fatal("feedback did not forward the actual admission's coherent proof and trusted source")
		}
		if appCalls.Load() != 0 {
			t.Fatal("reserved connector request reached the target")
		}
	}
	check(entry.Permission.Token)
	admission := permissionAdmission(t, bound, peer, entry.VisitorConnectionID)
	update := signedPermissionUpdate(t, bound, peer, entry, 1, time.Now().Add(2*time.Minute))
	if err := writer.Renew(ctx, update); err != nil {
		t.Fatal("connector permission renewal failed", err)
	}
	snapshot, err := admission.HTTPAuthorization(ctx)
	if err != nil || snapshot.PermissionToken.Reveal() != update.Permission.Token || !snapshot.Permission.Facts().ExpiresAt.After(time.Now().Add(time.Minute)) {
		t.Fatal("accepted renewal did not update the proof snapshot coherently", err)
	}
	check(update.Permission.Token)
	stale := entry
	stale.DeliveryGeneration = 0
	if err := admission.renewPermission(stale, snapshot.Permission); err == nil {
		t.Fatal("invalid renewal was accepted")
	}
	after, err := admission.HTTPAuthorization(ctx)
	if err != nil || after.PermissionToken != snapshot.PermissionToken || after.Permission.Facts() != snapshot.Permission.Facts() {
		t.Fatal("rejected renewal changed the selected feedback proof", err)
	}
	check(update.Permission.Token)
	feedback := frontend.feedback.(*feedbackRuntime)
	for _, path := range []string{"/__tnl/access", "/__tnl/feedback/evidence", feedback.assetPath} {
		response, body := call(path)
		if response.StatusCode != http.StatusOK || strings.Contains(string(body), update.Permission.Token) ||
			strings.Contains(string(body), visitorfixture.BrowserCookie) {
			t.Fatal("reserved connector status, evidence, or asset response exposed credentials", path, response.StatusCode)
		}
	}
	select {
	case <-budget.Completed():
		t.Fatal("connector feedback spent the application request budget")
	default:
	}
	response, body := call("/")
	if response.StatusCode != http.StatusOK || appCalls.Load() != 1 || !strings.Contains(string(body), feedback.assetPath) ||
		strings.Contains(string(body), update.Permission.Token) {
		t.Fatal("connector application lost shared toolbar hooks or leaked credentials")
	}
	control.denied.Store(true)
	response, body = call("/__tnl/feedback")
	<-control.pages
	if response.StatusCode != http.StatusServiceUnavailable || strings.Contains(string(body), update.Permission.Token) {
		t.Fatal("control failure exposed proof or bypassed current authorization")
	}
	admission.Stop()
	if proof, err := admission.HTTPAuthorization(ctx); err == nil || proof.PermissionToken != "" {
		t.Fatal("retired connector admission supplied feedback proof")
	}
	for _, value := range []any{snapshot, &snapshot, feedbackAuthorization{proof: json.RawMessage(`{"token":"private"}`)}} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if output := fmt.Sprintf(format, value); strings.Contains(output, snapshot.PermissionToken.Reveal()) || strings.Contains(output, "private") {
				t.Fatal("feedback proof formatting exposed credentials")
			}
		}
	}
}

func TestFeedbackGrantProofAndInvalidExplicitCredentialNeverFallsBack(t *testing.T) {
	control := &feedbackProofControl{pages: make(chan controlv1.PreviewPageFeedbackRequest, 8)}
	var frontend HTTP
	client, policy, update, _ := serviceHTTPConfiguredFixture(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("reserved feedback reached the app")
	}), false, true, func(f *HTTP) {
		feedbackProofRuntime(t, f, control)
		frontend = *f
	})
	token, err := visitortoken.Sign(update.View.Issuer, "http", ed25519.NewKeyFromSeed([]byte(strings.Repeat("h", 32))), visitortoken.Permission{
		Scope: update.View.Scope, Hostname: update.View.Hostname, Port: 443, VisitorPolicyRevision: 1,
		Subject: visitortoken.Grant{GrantID: "shg_" + strings.Repeat("G", 22), Kind: "token"}, ExpiresAt: time.Now().Add(time.Minute),
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://preview.example.test/__tnl/feedback", nil)
	request.Header.Set(httpaccess.VisitorTokenHeader, token.Reveal())
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	access := (<-control.pages).Access
	var proof controlv1.FeedbackBearerVisitProof
	if response.StatusCode != http.StatusOK || access.VisitProof == nil || json.Unmarshal(access.VisitProof, &proof) != nil ||
		proof.Token != token.Reveal() || access.BrowserCookieSecret != nil {
		t.Fatal("token-only grant visitation supplied author identity or lost its selected proof")
	}
	update.Anonymous = true
	update.View.VisitorPolicyRevision++
	now := time.Now()
	update.View.ObservedAt, update.View.ValidUntil = now, now.Add(visitortoken.PolicyLifetime)
	if err := policy.Apply(policy.Begin(), update); err != nil {
		t.Fatal(err)
	}
	request, _ = http.NewRequestWithContext(t.Context(), http.MethodGet, "https://preview.example.test/__tnl/feedback", nil)
	request.Header.Set(httpaccess.VisitorTokenHeader, "invalid-explicit-proof")
	request.AddCookie(&http.Cookie{Name: httpaccess.BrowserCookieName, Value: visitorfixture.BrowserCookie})
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden || len(control.pages) != 0 {
		t.Fatal("invalid explicit bearer fell back to anonymous access or browser identity")
	}
	certificateRequest := visitorfixture.Request()
	certificateRequest.URL.Path = "/__tnl/feedback"
	certificateRequest.TLS.PeerCertificates = []*x509.Certificate{{}}
	recorder := httptest.NewRecorder()
	if !frontend.reserved(recorder, certificateRequest, nil) ||
		recorder.Code != http.StatusForbidden || len(control.pages) != 0 {
		t.Fatal("public certificate feedback escaped its missing possession-proof boundary")
	}
}

func TestFeedbackConnectorReservedRejectsWrongBindingsAndHTTPReplacement(t *testing.T) {
	// canonical possession verification supplies the test permission; a bare
	// local socket or client-supplied pair field never constructs this input.
	bound, peer, _, opening, _ := connectorPeerFixture(t, "127.0.0.1:1")
	entry := opening("N")
	view, _, _ := bound.prepared.policy.Current()
	permission, err := visitortoken.VerifyConnectorPeerSession(entry, nil, peer.bindingSnapshot().expected(), view, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	control := &feedbackProofControl{pages: make(chan controlv1.PreviewPageFeedbackRequest, 8)}
	frontend := HTTP{Subject: view.Scope, RunID: entry.ServiceRunID, Number: int64(entry.RunNumber), Hostname: view.Hostname}
	feedbackProofRuntime(t, &frontend, control)
	proof := servicestream.ConnectorHTTPAuthorization{ServiceID: entry.ServiceID, RunID: entry.ServiceRunID, RunNumber: entry.RunNumber,
		PairID: entry.PairID, DeliveryGeneration: 1, Source: netip.MustParseAddr(entry.SourceIP),
		PermissionToken: visitortoken.Token(entry.Permission.Token), Permission: permission, ValidUntil: time.Now().Add(time.Minute)}
	for _, test := range []struct {
		name   string
		change func(*servicestream.ConnectorHTTPAuthorization, *http.Request)
	}{
		{"missing proof", func(p *servicestream.ConnectorHTTPAuthorization, _ *http.Request) {
			*p = servicestream.ConnectorHTTPAuthorization{}
		}},
		{"wrong service", func(p *servicestream.ConnectorHTTPAuthorization, _ *http.Request) { p.ServiceID += "other" }},
		{"wrong run", func(p *servicestream.ConnectorHTTPAuthorization, _ *http.Request) { p.RunID += "other" }},
		{"wrong run number", func(p *servicestream.ConnectorHTTPAuthorization, _ *http.Request) { p.RunNumber++ }},
		{"missing pair", func(p *servicestream.ConnectorHTTPAuthorization, _ *http.Request) { p.PairID = "" }},
		{"missing binding", func(p *servicestream.ConnectorHTTPAuthorization, _ *http.Request) { p.DeliveryGeneration = 0 }},
		{"expired admission", func(p *servicestream.ConnectorHTTPAuthorization, _ *http.Request) {
			p.ValidUntil = time.Now().Add(-time.Second)
		}},
		{"missing source", func(p *servicestream.ConnectorHTTPAuthorization, _ *http.Request) { p.Source = netip.Addr{} }},
		{"missing token", func(p *servicestream.ConnectorHTTPAuthorization, _ *http.Request) { p.PermissionToken = "" }},
		{"unverified permission", func(p *servicestream.ConnectorHTTPAuthorization, _ *http.Request) {
			p.Permission = visitortoken.VerifiedPermission{}
		}},
		{"bearer header", func(_ *servicestream.ConnectorHTTPAuthorization, r *http.Request) {
			r.Header.Set(httpaccess.VisitorTokenHeader, "invalid")
		}},
		{"bearer cookie", func(_ *servicestream.ConnectorHTTPAuthorization, r *http.Request) {
			r.AddCookie(&http.Cookie{Name: httpaccess.VisitorTokenCookie, Value: "invalid"})
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := proof
			request := visitorfixture.Request()
			request.URL.Path = "/__tnl/feedback"
			test.change(&candidate, request)
			response := httptest.NewRecorder()
			if !frontend.ConnectorReserved(response, request, candidate) || response.Code != http.StatusForbidden || len(control.pages) != 0 {
				t.Fatal("invalid explicit connector proof fell back to another feedback source")
			}
		})
	}
}
