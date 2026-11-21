package service

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	servicestream "github.com/tnldotdev/tnl/internal/publisher/service/stream"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/testutil/visitorfixture"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
	"golang.org/x/net/websocket"
)

func serviceHTTPSessionFixture(t *testing.T, control *visitorfixture.HTTPControl, handler http.Handler, h2 bool) (*http.Client, HTTP, *atomic.Int64) {
	t.Helper()
	control.Init()
	scope := visitorscope.Scope{Kind: visitorscope.Service, ID: "svc_" + strings.Repeat("S", 22)}
	header := tunnelv1.ServiceForwardingHeader{ServiceStreamHeader: tunnelv1.ServiceStreamHeader{
		ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.ServiceForwardingStream,
		ServiceID: scope.ID, ServiceRunID: "srun_" + strings.Repeat("R", 22), RunNumber: 1,
		SourceIP: "192.0.2.1", VisitorConnectionID: "vc_" + strings.Repeat("V", 22),
		PublisherConnectionID: "pc_" + strings.Repeat("P", 22), ConnectionAssignmentRevision: 1,
		ExpiresAt:     time.Now().Add(time.Minute),
		PublicService: &tunnelv1.PublicServiceAdmission{IngressID: "ingress", IngressRunID: "ir_" + strings.Repeat("I", 22), IngressLeaseRevision: 1, DestinationPort: 443}},
		RelayID: "relay", RelayServiceID: "relay-service", RelayRunID: "rr_" + strings.Repeat("R", 22), RelayLeaseRevision: 1, ServingUntil: time.Now().Add(time.Minute)}
	backend := &serviceBrowserControl{HTTPControl: serviceHTTPControl{}, origin: "https://control.example.test", policy: control, tokens: control}
	frontend, closeHTTP, err := PrepareHTTP(t.Context(), HTTP{Control: backend, Subject: scope, RunID: header.ServiceRunID,
		Number: 1, Token: credentials.ServiceRunToken("run-secret"), Hostname: "route.example", Port: 443, Header: header, Source: netip.MustParseAddrPort("192.0.2.1:1234"), ReserveCapacity: func(context.Context) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := closeHTTP(); err != nil {
			t.Error(err)
		}
	})
	control.Lease = frontend.Policy
	control.Prepare = func(ctx context.Context, source json.RawMessage, response controlv1.VisitorTokenResponse, parent time.Time) error {
		_, err := frontend.browser.PrepareToken(ctx, source, response, parent)
		return err
	}
	// the shared live authority binds route.example. use the same hostname for
	// its certificate and forwarding header, without a real-clock TCP server.
	certificate := visitorfixture.Certificate(t, frontend.Hostname)
	var dials atomic.Int64
	transport := &http.Transport{ForceAttemptHTTP2: h2, TLSClientConfig: &tls.Config{ServerName: frontend.Hostname, RootCAs: visitorfixture.Roots(t, certificate)},
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			if dials.Add(1) != 1 {
				return nil, errors.New("visitor tried to replace its TLS connection")
			}
			visitor, raw := net.Pipe()
			server := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13, NextProtos: []string{"h2", "http/1.1"}})
			done := make(chan error, 1)
			go func() {
				defer server.Close()
				done <- frontend.Forward(t.Context(), server, servicestream.HTTPTarget{Handler: handler})
			}()
			t.Cleanup(func() {
				_ = visitor.Close()
				select {
				case err := <-done:
					if err != nil {
						t.Error("service HTTP session failed", err)
					}
				case <-time.After(5 * time.Second):
					t.Error("service HTTP session did not join")
				}
			})
			return visitor, nil
		}}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport}, frontend, &dials
}

func TestServiceHTTPLiveRenewalAndHTTP2Isolation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var revoked atomic.Bool
		control := &visitorfixture.HTTPControl{Check: func(input visitorfixture.HTTPSource) (visitorfixture.HTTPDecision, error) {
			if input.BrowserCookieSecret != nil && *input.BrowserCookieSecret == visitorfixture.BrowserCookie && revoked.Load() {
				return visitorfixture.HTTPDecision{}, clientcontrol.ErrUnauthenticated
			}
			return visitorfixture.HTTPDecision{VisitAllowed: true, ValidUntil: new(time.Now().Add(2 * time.Minute))}, nil
		}}
		var requests atomic.Int32
		keepSibling := make(chan struct{})
		client, _, dials := serviceHTTPSessionFixture(t, control, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests.Add(1)
			body, err := io.ReadAll(r.Body)
			if err != nil || string(body) != "original body" || r.Header.Get("Authorization") != "app-secret" || r.Header.Get("Cookie") != "app=unchanged" {
				t.Error("service visitor checks changed the application body or credentials", string(body), err)
			}
			w.Header().Set("X-App", "unchanged")
			_, _ = io.WriteString(w, "prefix")
			w.(http.Flusher).Flush()
			if r.URL.Query().Get("id") == "sibling" {
				select {
				case <-r.Context().Done():
					return
				case <-keepSibling:
					_, _ = io.WriteString(w, "still streaming")
					w.(http.Flusher).Flush()
				}
			}
			<-r.Context().Done()
		}), true)
		request := func(id, secret string) *http.Response {
			t.Helper()
			r, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://route.example/stream?id="+id, strings.NewReader("original body"))
			if err != nil {
				t.Fatal(err)
			}
			r.Header.Set("Authorization", "app-secret")
			r.Header.Set("Cookie", "app=unchanged; "+httpaccess.VisitorTokenCookie+"="+control.Credential(t, secret, false))
			control.Mu.Lock()
			before := control.Calls
			control.Mu.Unlock()
			response, err := client.Do(r)
			if err != nil {
				t.Fatal(err)
			}
			control.Mu.Lock()
			after := control.Calls
			control.Mu.Unlock()
			if after != before {
				t.Fatal("application request refreshed policy or issued visitor permission", before, after)
			}
			if response.StatusCode != http.StatusOK || response.ProtoMajor != 2 || response.Header.Get("X-App") != "unchanged" {
				t.Fatal("service did not retain its streaming HTTP/2 response", response.StatusCode, response.Proto)
			}
			prefix := make([]byte, len("prefix"))
			if _, err := io.ReadFull(response.Body, prefix); err != nil || string(prefix) != "prefix" {
				t.Fatal("service response did not begin streaming", string(prefix), err)
			}
			return response
		}
		first := request("original", visitorfixture.BrowserCookie)
		defer first.Body.Close()
		sibling := request("sibling", "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA")
		defer sibling.Body.Close()
		time.Sleep(5 * time.Minute)
		synctest.Wait()
		control.Mu.Lock()
		if control.Calls < 12 {
			t.Error("long service HTTP requests did not renew")
		}
		control.Mu.Unlock()
		revoked.Store(true)
		ended := make(chan error, 1)
		go func() { _, err := io.Copy(io.Discard, first.Body); ended <- err }()
		time.Sleep(30 * time.Second)
		synctest.Wait()
		select {
		case err := <-ended:
			if err == nil {
				t.Error("revoked service HTTP/2 stream ended as success")
			}
		default:
			t.Fatal("revoked service HTTP/2 stream survived renewal")
		}
		close(keepSibling)
		continued := make([]byte, len("still streaming"))
		if _, err := io.ReadFull(sibling.Body, continued); err != nil || string(continued) != "still streaming" {
			t.Fatal("revocation interrupted the unrelated service stream", string(continued), err)
		}
		third := request("future", "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA")
		_ = third.Body.Close()
		if requests.Load() != 3 || dials.Load() != 1 {
			t.Fatal("service replayed application work or replaced its TLS connection", requests.Load(), dials.Load())
		}
	})
}

func TestServiceHTTP2DisconnectedBrowserRegrant(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const siblingCookie = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA"
		oldGrant := "sgr_" + strings.Repeat("A", 22)
		newGrant := "sgr_" + strings.Repeat("B", 22)
		offline, grant := false, oldGrant // accessed under the fixture's mutex
		control := &visitorfixture.HTTPControl{Check: func(input visitorfixture.HTTPSource) (visitorfixture.HTTPDecision, error) {
			if offline {
				return visitorfixture.HTTPDecision{}, clientcontrol.ErrUnavailable
			}
			decision := visitorfixture.HTTPDecision{VisitAllowed: true, ValidUntil: new(time.Now().Add(2 * time.Minute))}
			if input.BrowserCookieSecret != nil && *input.BrowserCookieSecret == visitorfixture.BrowserCookie {
				decision.BrowserGrantID = grant
			}
			return decision, nil
		}}
		ended, continueSibling := make(chan struct{}), make(chan struct{})
		client, frontend, dials := serviceHTTPSessionFixture(t, control, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, "prefix")
			w.(http.Flusher).Flush()
			switch r.URL.Path {
			case "/original":
				<-r.Context().Done()
				close(ended)
			case "/sibling":
				select {
				case <-r.Context().Done():
				case <-continueSibling:
					_, _ = io.WriteString(w, "still streaming")
				}
			}
		}), true)
		request := func(path, token string) *http.Response {
			t.Helper()
			r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://route.example/"+path, nil)
			if err != nil {
				t.Fatal(err)
			}
			r.AddCookie(&http.Cookie{Name: httpaccess.VisitorTokenCookie, Value: token})
			response, err := client.Do(r)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = response.Body.Close() })
			return response
		}
		read := func(body io.Reader, want string) {
			t.Helper()
			got := make([]byte, len(want))
			if _, err := io.ReadFull(body, got); err != nil || string(got) != want {
				t.Fatalf("stream read = %q, %v; want %q", got, err, want)
			}
		}
		oldToken := control.Credential(t, visitorfixture.BrowserCookie, false)
		first := request("original", oldToken)
		sibling := request("sibling", control.Credential(t, siblingCookie, false))
		for _, response := range []*http.Response{first, sibling} {
			if response.StatusCode != http.StatusOK || response.ProtoMajor != 2 {
				t.Fatal("expected a live HTTP/2 response", response.StatusCode, response.Proto)
			}
			read(response.Body, "prefix")
		}
		control.Mu.Lock()
		offline = true
		control.Mu.Unlock()
		time.Sleep(3 * time.Second)
		synctest.Wait()
		select {
		case <-ended:
			t.Fatal("brief outage ended the original response before policy recovery")
		default:
		}
		control.Mu.Lock()
		// control committed revoke and regrant while the publisher was offline.
		control.Revision += 2
		grant, offline = newGrant, false
		control.Mu.Unlock()
		if err := frontend.browser.Policy.Refresh(t.Context()); err != nil {
			t.Fatal("recover policy after the outage", err)
		}
		time.Sleep(3 * time.Second)
		synctest.Wait()
		select {
		case <-ended:
		default:
			t.Fatal("the replacement grant kept the original response alive")
		}
		if _, err := io.Copy(io.Discard, first.Body); err == nil {
			t.Fatal("revoked HTTP/2 stream ended as success")
		}
		close(continueSibling)
		read(sibling.Body, "still streaming")
		if response := request("retired", oldToken); response.StatusCode == http.StatusOK {
			t.Fatal("the old cookie still admitted new requests")
		}
		control.Mu.Lock()
		replacement := control.Issued["browser_session::"+visitorfixture.BrowserCookie].Reveal()
		control.Mu.Unlock()
		if response := request("new", replacement); response.StatusCode != http.StatusOK || response.ProtoMajor != 2 {
			t.Fatal("the replacement grant did not admit a new request", response.StatusCode, response.Proto)
		}
		if dials.Load() != 1 {
			t.Fatal("browser grant change replaced the HTTP/2 connection")
		}
	})
}

func TestServiceHTTPStreamingKeepsOriginalPermissionDeadline(t *testing.T) {
	for _, mode := range []string{"browser expiry", "share expiry", "share revoked"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				deadline := time.Now().Add(90 * time.Second)
				var revoked atomic.Bool
				control := &visitorfixture.HTTPControl{Check: func(visitorfixture.HTTPSource) (visitorfixture.HTTPDecision, error) {
					if mode == "share revoked" && revoked.Load() {
						return visitorfixture.HTTPDecision{}, &clientcontrol.ProblemError{Status: http.StatusForbidden}
					}
					return visitorfixture.HTTPDecision{VisitAllowed: true, ValidUntil: &deadline}, nil
				}}
				started, ended := make(chan struct{}), make(chan struct{})
				var requests atomic.Int32
				client, _, dials := serviceHTTPSessionFixture(t, control, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					requests.Add(1)
					body, err := io.ReadAll(r.Body)
					if err != nil || string(body) != "exact body" {
						t.Error("service changed the application request body", string(body), err)
					}
					close(started)
					<-r.Context().Done()
					close(ended)
				}), false)
				request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://route.example/stream", strings.NewReader("exact body"))
				if err != nil {
					t.Fatal(err)
				}
				request.AddCookie(&http.Cookie{Name: httpaccess.VisitorTokenCookie, Value: control.Credential(t, visitorfixture.BrowserCookie, strings.HasPrefix(mode, "share"))})
				result := make(chan error, 1)
				go func() {
					response, err := client.Do(request)
					if response != nil {
						response.Body.Close()
					}
					result <- err
				}()
				select {
				case <-started:
				case err := <-result:
					t.Fatal("service request failed before reaching its application", err)
				}
				revoked.Store(true)
				if mode == "share revoked" {
					time.Sleep(30 * time.Second)
				} else {
					time.Sleep(time.Until(deadline) - time.Second)
					synctest.Wait()
					select {
					case <-ended:
						t.Fatal("service request ended before its last signed deadline")
					default:
					}
					time.Sleep(2 * time.Second)
				}
				synctest.Wait()
				select {
				case <-ended:
				default:
					t.Fatal("service request survived its permission deadline or revocation")
				}
				if err := <-result; err == nil {
					t.Fatal("terminated service request returned success")
				}
				if requests.Load() != 1 || dials.Load() != 1 {
					t.Fatal("service replayed a terminated request", requests.Load(), dials.Load())
				}
			})
		})
	}
}

func TestServiceHTTPReplacementOnlyAuthorizesFutureRequests(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		originalDeadline := time.Now().Add(90 * time.Second)
		replacement := "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA"
		control := &visitorfixture.HTTPControl{Check: func(input visitorfixture.HTTPSource) (visitorfixture.HTTPDecision, error) {
			until := time.Now().Add(2 * time.Minute)
			if input.BrowserCookieSecret != nil && *input.BrowserCookieSecret == visitorfixture.BrowserCookie {
				until = originalDeadline
			}
			return visitorfixture.HTTPDecision{VisitAllowed: true, ValidUntil: &until}, nil
		}}
		ended := make(chan string, 3)
		client, _, dials := serviceHTTPSessionFixture(t, control, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, "prefix")
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			ended <- r.URL.Path
		}), true)
		request := func(path, secret string) *http.Response {
			t.Helper()
			r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://route.example/"+path, nil)
			if err != nil {
				t.Fatal(err)
			}
			r.AddCookie(&http.Cookie{Name: httpaccess.VisitorTokenCookie, Value: control.Credential(t, secret, false)})
			response, err := client.Do(r)
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != http.StatusOK || response.ProtoMajor != 2 {
				t.Fatal("replacement request did not retain HTTP/2", response.StatusCode, response.Proto)
			}
			return response
		}
		old := request("original", visitorfixture.BrowserCookie)
		defer old.Body.Close()
		time.Sleep(30 * time.Second)
		fresh := request("replacement", replacement)
		defer fresh.Body.Close()
		time.Sleep(61 * time.Second)
		synctest.Wait()
		select {
		case path := <-ended:
			if path != "/original" {
				t.Fatal("replacement ended with the original permission", path)
			}
		default:
			t.Fatal("new service credential extended the original request")
		}
		select {
		case path := <-ended:
			t.Fatal("original permission expiry ended an unrelated request", path)
		default:
		}
		third := request("future", replacement)
		_ = third.Body.Close()
		if dials.Load() != 1 {
			t.Fatal("replacement required another TLS connection", dials.Load())
		}
	})
}

func TestServiceHTTPStreamingRetainsPreparedPolicyAgeDuringOutage(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var unavailable atomic.Bool
		control := &visitorfixture.HTTPControl{Check: func(visitorfixture.HTTPSource) (visitorfixture.HTTPDecision, error) {
			if unavailable.Load() {
				return visitorfixture.HTTPDecision{}, clientcontrol.ErrUnavailable
			}
			return visitorfixture.HTTPDecision{VisitAllowed: true, ValidUntil: new(time.Now().Add(2 * time.Minute))}, nil
		}}
		ended := make(chan struct{})
		client, frontend, dials := serviceHTTPSessionFixture(t, control, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/warm" {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			close(ended)
		}), true)
		request := func(path string) *http.Response {
			t.Helper()
			r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://route.example/"+path, nil)
			if err != nil {
				t.Fatal(err)
			}
			r.AddCookie(&http.Cookie{Name: httpaccess.VisitorTokenCookie, Value: control.Credential(t, visitorfixture.BrowserCookie, false)})
			response, err := client.Do(r)
			if err != nil {
				t.Fatal(err)
			}
			return response
		}
		warm := request("warm")
		if warm.StatusCode != http.StatusNoContent {
			t.Fatal("service warm-up request was denied", warm.StatusCode)
		}
		warm.Body.Close()
		time.Sleep(4 * time.Second)
		unavailable.Store(true)
		synctest.Wait()
		confirmed, _, _ := frontend.Policy.Current()
		time.Sleep(time.Until(confirmed.ValidUntil) - 2*time.Second)
		stream := request("stream")
		defer stream.Body.Close()
		if stream.StatusCode != http.StatusOK || stream.ProtoMajor != 2 {
			t.Fatal("temporary outage rejected a still-current service policy", stream.StatusCode, stream.Proto)
		}
		time.Sleep(time.Second)
		synctest.Wait()
		select {
		case <-ended:
			t.Fatal("outage canceled the stream before its confirmed policy deadline")
		default:
		}
		time.Sleep(2 * time.Second)
		synctest.Wait()
		select {
		case <-ended:
		default:
			t.Fatal("starting a service request reset the prepared policy's deadline")
		}
		if _, err := io.Copy(io.Discard, stream.Body); err == nil {
			t.Fatal("expired service policy ended a stream as success")
		}
		if dials.Load() != 1 {
			t.Fatal("policy outage replaced the service TLS connection", dials.Load())
		}
	})
}

func TestServiceHTTPWebSocketRenewsAndClosesOnRevocation(t *testing.T) {
	t.Run("revoked", func(t *testing.T) { checkServiceWebSocketGrantLoss(t, false) })
	t.Run("disconnected regrant", func(t *testing.T) { checkServiceWebSocketGrantLoss(t, true) })
}

func checkServiceWebSocketGrantLoss(t *testing.T, regrant bool) {
	t.Helper()
	synctest.Test(t, func(t *testing.T) {
		offline, revoked := false, false // accessed under the fixture's mutex
		grant := "sgr_" + strings.Repeat("A", 22)
		control := &visitorfixture.HTTPControl{Check: func(input visitorfixture.HTTPSource) (visitorfixture.HTTPDecision, error) {
			if input.BrowserCookieSecret == nil || *input.BrowserCookieSecret != visitorfixture.BrowserCookie {
				t.Error("service upgrade lost its original browser session")
			}
			if offline {
				return visitorfixture.HTTPDecision{}, clientcontrol.ErrUnavailable
			}
			if revoked {
				return visitorfixture.HTTPDecision{}, &clientcontrol.ProblemError{Status: http.StatusForbidden}
			}
			return visitorfixture.HTTPDecision{VisitAllowed: true, ValidUntil: new(time.Now().Add(2 * time.Minute)), BrowserGrantID: grant}, nil
		}}
		var upgrades atomic.Int32
		client, frontend, dials := serviceHTTPSessionFixture(t, control, websocket.Handler(func(ws *websocket.Conn) {
			upgrades.Add(1)
			defer ws.Close()
			for {
				var text string
				if websocket.Message.Receive(ws, &text) != nil || websocket.Message.Send(ws, text) != nil {
					return
				}
			}
		}), false)
		transport := client.Transport.(*http.Transport)
		raw, err := transport.DialContext(t.Context(), "tcp", "route.example:443")
		if err != nil {
			t.Fatal(err)
		}
		secure := tls.Client(raw, transport.TLSClientConfig.Clone())
		config, err := websocket.NewConfig("wss://route.example/socket", "https://route.example")
		if err != nil {
			t.Fatal(err)
		}
		config.Header.Set("Cookie", httpaccess.VisitorTokenCookie+"="+control.Credential(t, visitorfixture.BrowserCookie, false))
		ws, err := websocket.NewClient(config, secure)
		if err != nil {
			t.Fatal(err)
		}
		defer ws.Close()
		time.Sleep(5 * time.Minute)
		if err := websocket.Message.Send(ws, "still live"); err != nil {
			t.Fatal(err)
		}
		var text string
		if err := websocket.Message.Receive(ws, &text); err != nil || text != "still live" {
			t.Fatal("renewed service WebSocket changed its bytes or expired", text, err)
		}
		if regrant {
			control.Mu.Lock()
			offline = true
			control.Mu.Unlock()
			time.Sleep(3 * time.Second)
			control.Mu.Lock()
			control.Revision += 2
			grant, offline = "sgr_"+strings.Repeat("B", 22), false
			control.Mu.Unlock()
			if err := frontend.browser.Policy.Refresh(t.Context()); err != nil {
				t.Fatal("recover policy after the outage", err)
			}
		} else {
			control.Mu.Lock()
			revoked = true
			control.Mu.Unlock()
		}
		closed := make(chan error, 1)
		go func() { closed <- websocket.Message.Receive(ws, &text) }()
		time.Sleep(6 * time.Second)
		synctest.Wait()
		select {
		case err := <-closed:
			if err == nil {
				t.Fatal("revoked service WebSocket stayed open")
			}
		default:
			t.Fatal("service WebSocket survived revoked visitor permission")
		}
		if upgrades.Load() != 1 || dials.Load() != 1 {
			t.Fatal("service replayed an upgraded connection", upgrades.Load(), dials.Load())
		}
	})
}
