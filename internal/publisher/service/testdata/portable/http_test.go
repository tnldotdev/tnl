//go:build js && wasm

package portable_test

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	"github.com/tnldotdev/tnl/internal/publisher/requestlimit"
	"github.com/tnldotdev/tnl/internal/publisher/service"
	servicestream "github.com/tnldotdev/tnl/internal/publisher/service/stream"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/testutil/visitorfixture"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestWasmServiceRejectsNativeFeedbackBeforeExternalWork(t *testing.T) {
	for _, flags := range [][2]bool{{true, false}, {false, true}, {true, true}} {
		// nil control and state deliberately cannot perform any external work.
		err := service.Publish(t.Context(), service.RunConfig{Feedback: flags[0], Demo: flags[1]})
		if !errors.Is(err, service.ErrFeedbackUnsupported) {
			t.Fatal("native-only publication was not rejected at entry", err)
		}
		prepared, closeHTTP, err := service.PrepareHTTP(t.Context(), service.HTTP{Feedback: flags[0], Demo: flags[1]})
		if !errors.Is(err, service.ErrFeedbackUnsupported) || closeHTTP != nil || prepared.Policy != nil {
			t.Fatal("native-only HTTP preparation started work", err)
		}
	}
}

type portableControl struct {
	service.HTTPControl
	policy *visitorfixture.PolicyClient
}

func (c portableControl) ControlURL() string { return "https://control.example.test" }

func (c portableControl) ReadPublisherVisitorPolicy(ctx context.Context, request controlv1.PublisherVisitorPolicyRequest, token string) (controlv1.VisitorPolicyUpdate, error) {
	return c.policy.ReadPublisherVisitorPolicy(ctx, request, token)
}

func TestWasmServiceInlineHTTPKeepsAuthorizationAndReservedPaths(t *testing.T) {
	key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("p", 32)))
	scope := visitorscope.Scope{Kind: visitorscope.Service, ID: "svc_" + strings.Repeat("A", 22)}
	runID := "srun_" + strings.Repeat("R", 22)
	requests, err := requestlimit.NewHTTP(nil)
	if err != nil {
		t.Fatal(err)
	}
	frontend, closeHTTP, err := service.PrepareHTTP(t.Context(), service.HTTP{
		Control: portableControl{policy: &visitorfixture.PolicyClient{Key: key}},
		Subject: scope, RunID: runID, Number: 1, Token: "run-secret",
		Hostname: "preview.example.test", Port: 443, Public: true, Requests: requests,
		Source: netip.MustParseAddrPort("192.0.2.1:1234"),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := closeHTTP(); err != nil {
			t.Error(err)
		}
		if _, enabled, _ := frontend.Policy.Current(); enabled {
			t.Error("HTTP cleanup left its visitor policy enabled")
		}
	})
	var reserved, apps atomic.Int64
	frontend.ReserveCapacity = func(context.Context) error { reserved.Add(1); return nil }
	frontend.Header = tunnelv1.ServiceForwardingHeader{
		ServiceStreamHeader: tunnelv1.ServiceStreamHeader{
			ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.ServiceForwardingStream,
			ServiceID: scope.ID, ServiceRunID: runID, RunNumber: 1, SourceIP: "192.0.2.1",
			VisitorConnectionID:          "vc_" + strings.Repeat("V", 22),
			PublisherConnectionID:        "pc_" + strings.Repeat("P", 22),
			ConnectionAssignmentRevision: 1, ExpiresAt: time.Now().Add(time.Minute),
			PublicService: &tunnelv1.PublicServiceAdmission{IngressID: "ingress",
				IngressRunID: "ir_" + strings.Repeat("I", 22), IngressLeaseRevision: 1, DestinationPort: 443},
		},
		RelayID: "relay", RelayServiceID: "relay-service", RelayRunID: "rr_" + strings.Repeat("R", 22),
		RelayLeaseRevision: 1, LeaseExpiresAt: time.Now().Add(time.Minute),
	}
	if err := frontend.Header.Validate(); err != nil {
		t.Fatal(err)
	}
	application := servicestream.HTTPTarget{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apps.Add(1)
		if r.Host != "preview.example.test" || r.TLS == nil || r.TLS.ServerName != r.Host ||
			r.RemoteAddr != "192.0.2.1:1234" || r.Header.Get(httpaccess.VisitorTokenHeader) != "" ||
			r.Header.Get("Authorization") != "application-private" {
			t.Error("inline application lost admitted facts or received visitor credentials")
		}
		_, _ = io.WriteString(w, "portable inline")
	})}
	certificate := visitorfixture.Certificate(t, "preview.example.test")
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: visitorfixture.Roots(t, certificate)},
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			visitor, raw := net.Pipe()
			server := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{certificate},
				MinVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}})
			done := make(chan error, 1)
			go func() {
				defer server.Close()
				done <- frontend.Forward(ctx, server, application)
			}()
			t.Cleanup(func() {
				_ = visitor.Close()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Error("portable HTTP visitor did not join")
				}
			})
			return visitor, nil
		},
	}
	t.Cleanup(transport.CloseIdleConnections)
	view, _, _ := frontend.Policy.Current()
	token, err := visitortoken.Sign(view.Issuer, "test-key", key, visitortoken.Permission{
		Scope: scope, Hostname: view.Hostname, Port: view.Port, VisitorPolicyRevision: view.VisitorPolicyRevision,
		Subject: visitortoken.Browser{IdentityID: "ident_" + strings.Repeat("B", 22),
			SessionID: "cs_" + strings.Repeat("C", 22)}, ExpiresAt: time.Now().Add(5 * time.Minute),
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	for _, test := range []struct {
		path       string
		credential bool
		status     int
	}{{"/", false, http.StatusForbidden}, {"/__tnl/unknown", true, http.StatusNotFound}, {"/app", true, http.StatusOK}} {
		request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://preview.example.test"+test.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Close = true
		request.Header.Set("Authorization", "application-private")
		if test.credential {
			request.Header.Set(httpaccess.VisitorTokenHeader, token.Reveal())
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil || response.StatusCode != test.status ||
			test.status == http.StatusOK && string(body) != "portable inline" {
			t.Fatal("portable frontend changed authorization or response", response.Status, string(body), err)
		}
	}
	if apps.Load() != 1 || reserved.Load() != 1 {
		t.Fatal("denied or reserved requests reached the app or spent ingress capacity", apps.Load(), reserved.Load())
	}
}
