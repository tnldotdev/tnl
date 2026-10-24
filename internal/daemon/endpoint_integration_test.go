package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	connectorstream "github.com/tnldotdev/tnl/internal/connector/stream"
	"github.com/tnldotdev/tnl/internal/ingress"
	"github.com/tnldotdev/tnl/internal/naming/tcpport"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationEndpointProductionPath(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	for _, standalone := range []bool{false, true} {
		t.Run(map[bool]string{false: "split", true: "standalone"}[standalone], func(t *testing.T) {
			f := newServiceRuntimeFixtureTiming(t, standalone, nil, false)
			var directIngress *ingress.Connector
			if !standalone {
				process := startSeparatedPrivateIngress(t, f, 0, "quic", nil)
				directIngress = process.ingresses[0].private
				startSeparatedPrivateIngress(t, f, 1, "quic", nil)
			} else {
				directIngress = f.composed.ingresses[0].private
			}
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/once" {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				_, _ = io.Copy(w, r.Body)
			}))
			t.Cleanup(target.Close)
			const project = "managed-runtime"
			group := "production"
			projectLabel := "storefront"
			protocol := controlv1.ServiceProtocolHTTP
			targetAddress := strings.TrimPrefix(target.URL, "http://")
			applied, err := f.identity.routes.ApplyProjectConfiguration(t.Context(), project, controlv1.ApplyProjectConfigurationRequest{TeamId: f.identity.teamID, SourceFingerprint: strings.Repeat("a", 64), ProjectLabel: &projectLabel, Configuration: controlv1.ProjectConfiguration{PublisherGroups: map[string]controlv1.ProjectPublisherGroup{group: {}}, Services: map[string]controlv1.ProjectServiceConfiguration{"api": {PublisherGroup: &group, Protocol: &protocol, Target: targetAddress}}, Webhooks: map[string]controlv1.ProjectWebhook{}}})
			if err != nil {
				t.Fatal(err)
			}
			public, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			enrollment, err := f.identity.routes.CreatePublisherGroupEnrollment(t.Context(), project, group, controlv1.CreatePublisherGroupEnrollmentRequest{TeamId: f.identity.teamID, MaxMembers: 1, ExpiresIn: 600})
			if err != nil {
				t.Fatal(err)
			}
			member, err := f.identity.routes.RedeemPublisherGroupEnrollment(t.Context(), enrollment.EnrollmentKey, public)
			if err != nil {
				t.Fatal(err)
			}
			owner, err := publisheridentity.NewGroup(f.identity.routes, f.identity.routes, f.identity.authority, "https://"+f.controlConfig.ServerHostname(), member, key)
			if err != nil {
				t.Fatal(err)
			}
			assignments, err := owner.Poll(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			assignment := assignments.Services[0]
			native, err := owner.Service(assignment)
			if err != nil {
				t.Fatal(err)
			}
			service, err := native.SavedService(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if service.Endpoint == nil || applied.Services[0].Hostname == nil || *applied.Services[0].Hostname != service.Endpoint.Hostname {
				t.Fatal("missing managed TLS metadata", service)
			}
			identity := authorityv1.PublisherEnrollmentResult{ClientId: member.PublisherIdentityId, KeyId: member.KeyId, TeamId: member.TeamId, GrantId: assignment.GrantId, Kind: authorityv1.Service, ServiceId: &assignment.ServiceId}
			quic, tcp := f.connectors()
			publisherCtx, stopPublisher := context.WithCancel(t.Context())
			publisherReady, publisherDone := make(chan struct{}), make(chan error, 1)
			go func() {
				publisherDone <- publisherservice.Publish(publisherCtx, publisherservice.RunConfig{Control: native, State: f.identity.state, Access: native.Access, Identity: identity, ServiceID: service.Id, Target: targetAddress, Metadata: publisheridentity.ServiceMetadata(service), HeartbeatInterval: 100 * time.Millisecond, Ready: func() error { close(publisherReady); return nil }, Connect: func(ctx context.Context, bound *publisherservice.Bound, slot uint8) (publisherservice.SlotSession, error) {
					return bound.ConnectSlotWithTransports(ctx, slot, false, quic, tcp)
				}})
			}()
			t.Cleanup(func() {
				stopPublisher()
				select {
				case err := <-publisherDone:
					if err != nil {
						t.Error(err)
					}
				case <-time.After(15 * time.Second):
					t.Error("publisher did not join")
				}
			})
			select {
			case <-publisherReady:
			case err := <-publisherDone:
				publisherDone <- err
				t.Fatal(err)
			case <-time.After(15 * time.Second):
				t.Fatal("managed publisher not ready")
			}
			person, err := f.identity.authority.IdentityContext(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			production, err := connectorstream.NewControl(f.identity.routes, f.identity.state, person.Identity.Id)
			if err != nil {
				t.Fatal(err)
			}
			control := &separatedVisitorControl{Control: production}
			if standalone {
				control.dialAddress = f.sharedQUIC
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			connectorCtx, stopConnector := context.WithCancel(t.Context())
			connectorReady, connectorDone := make(chan struct{}), make(chan error, 1)
			reconfigured := false
			oldConnectorJoined := false
			go func() {
				connectorDone <- connectorstream.Serve(connectorCtx, listener, connectorstream.Config{Control: control, ServiceID: service.Id, IdentityID: person.Identity.Id, Protocol: "http", TrustRevision: service.TrustRevision, Endpoint: service.Endpoint, ServiceTLS: f.visitorRoots, Ready: func() error { close(connectorReady); return nil }})
			}()
			t.Cleanup(func() {
				stopConnector()
				if oldConnectorJoined {
					return
				}
				select {
				case err := <-connectorDone:
					if err != nil && !(reconfigured && connectorstream.IsMetadataReload(err)) {
						t.Error(err)
					}
				case <-time.After(10 * time.Second):
					t.Error("connector did not join")
				}
			})
			select {
			case <-connectorReady:
			case <-time.After(10 * time.Second):
				t.Fatal("connector not ready")
			}
			transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: f.visitorRoots.RootCAs, ServerName: service.Endpoint.Hostname, MinVersion: tls.VersionTLS12, GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				t.Error("private HTTP requested an application client certificate")
				return nil, publisherservice.ErrPrivateStream
			}}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, listener.Addr().String())
			}}
			t.Cleanup(transport.CloseIdleConnections)
			client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
			response, err := client.Post("https://"+service.Endpoint.Hostname+"/once", "text/plain", strings.NewReader("native TLS reaches the publisher"))
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if err != nil || response.StatusCode != http.StatusOK || string(body) != "native TLS reaches the publisher" {
				t.Fatal(response.StatusCode, string(body), err)
			}
			// the authenticated connector is sufficient, but its device revocation
			// still prevents a fresh native HTTPS connection without client mTLS.
			device, err := production.ConnectorSigner(t.Context(), person.Identity.Id)
			if err != nil {
				t.Fatal(err)
			}
			checkManagedDirectTLS(t, f, directIngress, applied, service, device.Subject.DeviceID, person.Identity.Id, func() {
				reconfigured = true
				stopPublisher()
				select {
				case err := <-publisherDone:
					if err != nil {
						t.Fatal("previous publisher did not join", err)
					}
				case <-time.After(10 * time.Second):
					t.Fatal("previous publisher did not join")
				}
				updated, err := native.SavedService(t.Context())
				if err != nil || updated.Id != service.Id || updated.Endpoint == nil || updated.Endpoint.Port != service.Endpoint.Port {
					t.Fatal("updated service metadata", err)
				}
				publisherCtx, stopPublisher = context.WithCancel(t.Context())
				publisherReady, publisherDone = make(chan struct{}), make(chan error, 1)
				go func() {
					publisherDone <- publisherservice.Publish(publisherCtx, publisherservice.RunConfig{Control: native, State: f.identity.state, Access: native.Access, Identity: identity, ServiceID: service.Id, Target: targetAddress, Metadata: publisheridentity.ServiceMetadata(updated), HeartbeatInterval: 100 * time.Millisecond, Ready: func() error { close(publisherReady); return nil }, Connect: func(ctx context.Context, bound *publisherservice.Bound, slot uint8) (publisherservice.SlotSession, error) {
						return bound.ConnectSlotWithTransports(ctx, slot, false, quic, tcp)
					}})
				}()
				select {
				case <-publisherReady:
				case err := <-publisherDone:
					publisherDone <- err
					t.Fatal("public publisher not ready", err)
				case <-time.After(15 * time.Second):
					t.Fatal("public publisher not ready")
				}
			})
			// restore a current private connector before proving that revoking its
			// device closes fresh native HTTPS; the old approved revision exited
			// when the managed service changed reachability.
			stopConnector()
			select {
			case err := <-connectorDone:
				if !connectorstream.IsMetadataReload(err) {
					t.Fatal("old connector did not report stale metadata", err)
				}
				oldConnectorJoined = true
			case <-time.After(10 * time.Second):
				t.Fatal("old connector did not join")
			}
			_ = listener.Close()
			current, err := native.SavedService(t.Context())
			if err != nil || current.Endpoint == nil {
				t.Fatal("current private service", err)
			}
			renewedControl, err := connectorstream.NewControl(f.identity.routes, f.identity.state, person.Identity.Id)
			if err != nil {
				t.Fatal(err)
			}
			control = &separatedVisitorControl{Control: renewedControl}
			if standalone {
				control.dialAddress = f.sharedQUIC
			}
			listener, err = net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			activeCtx, stopActive := context.WithCancel(t.Context())
			activeReady, activeDone := make(chan struct{}), make(chan error, 1)
			go func() {
				activeDone <- connectorstream.Serve(activeCtx, listener, connectorstream.Config{Control: control, ServiceID: current.Id, IdentityID: person.Identity.Id, Protocol: "http", TrustRevision: current.TrustRevision, Endpoint: current.Endpoint, ServiceTLS: f.visitorRoots, Ready: func() error { close(activeReady); return nil }})
			}()
			t.Cleanup(func() {
				stopActive()
				select {
				case err := <-activeDone:
					if err != nil {
						t.Error(err)
					}
				case <-time.After(10 * time.Second):
					t.Error("current connector did not join")
				}
			})
			select {
			case <-activeReady:
			case err := <-activeDone:
				activeDone <- err
				t.Fatal("current connector not ready", err)
			case <-time.After(10 * time.Second):
				t.Fatal("current connector not ready")
			}
			transport.CloseIdleConnections()
			response, err = client.Get("https://" + service.Endpoint.Hostname + "/once")
			if err != nil || response.StatusCode != http.StatusOK {
				t.Fatal("current connector cannot serve before revocation", err)
			}
			_ = response.Body.Close()
			if err = f.identity.routes.RevokeVisitorDevice(t.Context(), device.Subject.DeviceID); err != nil {
				t.Fatal(err)
			}
			privateWait(t, 10*time.Second, func(context.Context) (bool, error) {
				transport.CloseIdleConnections()
				response, err := client.Get("https://" + service.Endpoint.Hostname + "/once")
				if err != nil {
					return true, nil
				}
				_ = response.Body.Close()
				return false, nil
			})
		})
	}
}

func checkManagedDirectTLS(t *testing.T, f *privateSeparatedFixture, connector *ingress.Connector, applied controlv1.AppliedProjectConfiguration, service controlv1.Service, device, identity string, restartPublisher func()) {
	t.Helper()
	ctx := t.Context()
	material, err := f.identity.state.EnsureServiceClientCertificate(ctx, identity, service.Id, device, func(ctx context.Context, csr []byte) (controlv1.ServiceClientCertificate, error) {
		return f.identity.routes.IssueServiceClientCertificate(ctx, service.Id, device, csr)
	})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := ingress.New(listener, ingress.Config{DirectOnly: true, RequireProxyHeader: true, TrustedProxyPeers: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}, DirectConnector: connector, ServicePortRanges: []tcpport.Range{{First: service.Endpoint.Port, Last: service.Endpoint.Port}}, MaxConnections: 64})
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve() }()
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Drain(cleanup)
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: f.visitorRoots.RootCAs, ServerName: service.Endpoint.Hostname, MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{material.Certificate}}, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		connection, err := (&net.Dialer{}).DialContext(ctx, network, listener.Addr().String())
		if err != nil {
			return nil, err
		}
		header, err := proxyproto.Encode(proxyproto.Header{Source: netip.MustParseAddrPort("192.0.2.44:4242"), Destination: netip.AddrPortFrom(netip.MustParseAddr("203.0.113.10"), uint16(service.Endpoint.Port))})
		if err == nil {
			_, err = connection.Write(header)
		}
		if err != nil {
			_ = connection.Close()
			return nil, err
		}
		return connection, nil
	}}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	endpoint := "https://" + net.JoinHostPort(service.Endpoint.Hostname, strconv.Itoa(service.Endpoint.Port)) + "/once"
	assertDenied := func() {
		t.Helper()
		transport.CloseIdleConnections()
		response, err := client.Get(endpoint)
		if err == nil {
			_ = response.Body.Close()
			t.Fatal("service admitted a direct visitor")
		}
	}
	assertDenied()
	setPublic := func(public bool) {
		t.Helper()
		group := applied.Configuration.PublisherGroups["production"]
		group.Public = &public
		applied.Configuration.PublisherGroups["production"] = group
		result, err := f.identity.routes.ApplyProjectConfiguration(ctx, "managed-runtime", controlv1.ApplyProjectConfigurationRequest{TeamId: f.identity.teamID, SourceFingerprint: strings.Repeat("a", 64), ExpectedRevision: applied.Revision, Configuration: applied.Configuration})
		if err != nil {
			t.Fatal(err)
		}
		applied = result
	}
	setPublic(true)
	restartPublisher()
	// the saved reachability change precedes ingress and publisher policy
	// installation. prove prepared access with a bodyless fixture read before
	// making the one application POST; never retry that POST after EOF.
	privateWait(t, 10*time.Second, func(context.Context) (bool, error) {
		transport.CloseIdleConnections()
		probe, err := client.Get(endpoint)
		if err != nil {
			return false, nil
		}
		_, _ = io.Copy(io.Discard, probe.Body)
		_ = probe.Body.Close()
		return probe.StatusCode == http.StatusOK, nil
	})
	response, err := client.Post(endpoint, "text/plain", strings.NewReader("service HTTP certificate"))
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || string(body) != "service HTTP certificate" {
		t.Fatalf("service HTTP default frontend: status=%d body=%q err=%v", response.StatusCode, body, err)
	}
	setPublic(false)
	privateWait(t, 10*time.Second, func(context.Context) (bool, error) {
		return !connector.DirectServiceReady(uint16(service.Endpoint.Port)), nil
	})
	assertDenied()
}
