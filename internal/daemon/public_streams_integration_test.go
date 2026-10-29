package daemon

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationPublicStreamTransports(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	for _, restricted := range []bool{false, true} {
		t.Run(map[bool]string{false: "anonymous", true: "restricted"}[restricted], func(t *testing.T) { testIntegrationPublicStreamTransports(t, restricted) })
	}
}

func testIntegrationPublicStreamTransports(t *testing.T, restricted bool) {
	for _, role := range []string{"split", "standalone"} {
		for _, transport := range []string{"quic", "tls_yamux"} {
			t.Run(role+"/"+transport, func(t *testing.T) {
				var owner *runtimeTopology
				var identity *integrationPublishingIdentity
				var visitor *integrationVisitor
				var quic, tcp muxsession.Connector
				var ready func(*testing.T, *integrationPublisher) publisher.Event
				var diagnostics func() string
				if role == "split" {
					f := newSplitPublishFixture(t, "stream")
					owner, identity, visitor, ready = f.owner, f.identity, f.visitor, f.waitReady
					diagnostics = func() string { return integrationPublisherDiagnostics(f.inspect, f.pebble.logPath) }
					quic, tcp = f.connectors()
				} else {
					f := newStandalonePublishFixture(t, "stream")
					owner, identity, visitor, ready, diagnostics = f.owner, f.identity, f.visitor, f.waitReady, f.diagnostics
					quic, tcp = f.connectors()
				}
				disabled := muxsession.ConnectorFunc(func(ctx context.Context, _ muxsession.Endpoint) (muxsession.Session, error) {
					<-ctx.Done()
					return nil, context.Cause(ctx)
				})
				if transport == "quic" {
					tcp = disabled
				} else {
					quic = disabled
				}
				var requests atomic.Int32
				var completed atomic.Int32
				canceled, revoked := make(chan struct{}), make(chan struct{})
				target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					requests.Add(1)
					defer completed.Add(1)
					if r.Header.Get("Tnl-Share-Token") != "" || r.Header.Get("Tnl-Visitor-Token") != "" {
						t.Error("visitor credential reached target")
					}
					w.Header().Set("Content-Type", "application/octet-stream")
					if r.URL.Path == "/cancel" || r.URL.Path == "/revoke" {
						_, _ = io.WriteString(w, "ready")
						w.(http.Flusher).Flush()
						<-r.Context().Done()
						if r.URL.Path == "/cancel" {
							close(canceled)
						} else {
							close(revoked)
						}
						return
					}
					_, _ = io.Copy(w, r.Body)
				}))
				cleanupIntegrationHTTPServer(t, target, owner)
				config := identity.publisherConfig(target.URL, quic, tcp)
				if restricted {
					config.AccessMode = controlv1.Restricted
				}
				handle := startOwnedIntegrationPublisher(t, owner, config, diagnostics)
				event := ready(t, handle)
				var token, shareID string
				if restricted {
					response, _, err := visitor.requestURL(http.MethodGet, event.PublicURL, nil)
					if err != nil || response.StatusCode != http.StatusForbidden || requests.Load() != 0 {
						t.Fatalf("restricted visitor reached target: %v, %v", response, err)
					}
					visitor.transport.CloseIdleConnections()
					secret := make([]byte, 32)
					if _, err := rand.Read(secret); err != nil {
						t.Fatal(err)
					}
					fingerprint := sha256.Sum256(secret)
					share, err := identity.routes.CreateURLShare(t.Context(), "stream-promotion", controlv1.CreateShareRequest{PublicUrlIds: []string{event.PublicURLID}, ExpiresAt: time.Now().Add(time.Minute), SecretFingerprint: hex.EncodeToString(fingerprint[:])})
					if err != nil {
						t.Fatal(err)
					}
					shareID = share.Id
					// redeem the share through the publisher so its signed permission
					// and current policy are prepared before application requests.
					redeemer := *visitor.client
					redeemer.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
					redemption, err := redeemer.Get(event.PublicURL + "/__tnl/share/" + share.Id + "." + base64.RawURLEncoding.EncodeToString(secret))
					if err != nil {
						t.Fatal("share redemption failed")
					}
					_, readErr := io.Copy(io.Discard, redemption.Body)
					closeErr := redemption.Body.Close()
					if redemption.StatusCode != http.StatusSeeOther || readErr != nil || closeErr != nil || requests.Load() != 0 {
						t.Fatal("share redemption did not prepare access without target work", redemption.StatusCode)
					}
					for _, cookie := range redemption.Cookies() {
						if cookie.Name == "__Host-tnl-visitor" {
							token = cookie.Value
						}
					}
					if token == "" {
						t.Fatal("share redemption did not return a signed visitor permission")
					}
					visitor.transport.CloseIdleConnections()
				}
				for range 3 {
					request, err := http.NewRequest(http.MethodGet, event.PublicURL, nil)
					if err != nil {
						t.Fatal(err)
					}
					if restricted {
						request.Header.Set("Tnl-Visitor-Token", token)
					}
					response, body, err := visitor.request(request)
					if err != nil || response.StatusCode != http.StatusOK || len(body) != 0 {
						t.Fatalf("visitor response: %v %q %v", response, body, err)
					}
					visitor.transport.CloseIdleConnections()
				}
				if requests.Load() != 3 {
					t.Fatal("target request replayed", requests.Load())
				}
				// each held response is a real restricted visitor through ingress and
				// relay. the target must see cancellation once and join before teardown.
				if restricted {
					client := *visitor.client
					client.Timeout = 40 * time.Second
					openHeld := func(path string) (*http.Response, context.CancelFunc) {
						ctx, cancel := context.WithCancel(t.Context())
						t.Cleanup(cancel)
						request, err := http.NewRequestWithContext(ctx, http.MethodGet, event.PublicURL+path, nil)
						if err != nil {
							t.Fatal(err)
						}
						request.Header.Set("Tnl-Visitor-Token", token)
						response, err := client.Do(request)
						if err != nil {
							t.Fatal(err)
						}
						t.Cleanup(func() { _ = response.Body.Close() })
						var greeting [5]byte
						if _, err := io.ReadFull(response.Body, greeting[:]); err != nil || string(greeting[:]) != "ready" || response.StatusCode != http.StatusOK {
							t.Fatalf("held visitor did not reach target: %v %q %v", response.Status, greeting, err)
						}
						return response, cancel
					}
					response, cancel := openHeld("/cancel")
					cancel()
					if _, err := io.ReadAll(response.Body); !errors.Is(err, context.Canceled) {
						t.Fatal("visitor cancellation cause lost", err)
					}
					_ = response.Body.Close()
					if err := waitForDoneWithin(canceled, 5*time.Second); err != nil {
						t.Fatal("canceled visitor retained target work", err)
					}
					response, cancel = openHeld("/revoke")
					defer cancel()
					if _, err := identity.routes.RevokeShare(t.Context(), shareID); err != nil {
						t.Fatal(err)
					}
					if err := waitForDoneWithin(revoked, 31*time.Second); err != nil {
						t.Fatal("revoked visitor retained target work past authorization bound", err)
					}
					if _, err := io.ReadAll(response.Body); err == nil {
						t.Fatal("revoked response ended without a failure")
					}
					_ = response.Body.Close()
					visitor.transport.CloseIdleConnections()
					request, err := http.NewRequest(http.MethodGet, event.PublicURL, nil)
					if err != nil {
						t.Fatal(err)
					}
					request.Header.Set("Tnl-Visitor-Token", token)
					response, _, err = visitor.request(request)
					if err != nil || response.StatusCode != http.StatusForbidden || requests.Load() != 5 {
						t.Fatalf("revoked credential reached target: %v %v requests=%d", response, err, requests.Load())
					}
				}
				stopIntegrationPublisher(t, handle)
				target.Close()
				if completed.Load() != requests.Load() {
					t.Fatalf("target work did not join exactly once: entered=%d completed=%d", requests.Load(), completed.Load())
				}
			})
		}
	}
}
