package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"errors"
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
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestIntegrationEndpointProductionPath(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	for _, standalone := range []bool{false, true} {
		t.Run(map[bool]string{false: "split", true: "standalone"}[standalone], func(t *testing.T) {
			f := newServiceRuntimeFixtureTiming(t, standalone, nil, false)
			var publicServiceIngress *ingress.PublicServices
			if !standalone {
				process := startSeparatedPrivateIngress(t, f, 0, "quic", nil)
				publicServiceIngress = process.ingresses[0].publicServices
				startSeparatedPrivateIngress(t, f, 1, "quic", nil)
			} else {
				publicServiceIngress = f.composed.ingresses[0].publicServices
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
			applied, err := f.identity.routes.ApplyProjectConfiguration(t.Context(), project, controlv1.ApplyProjectConfigurationRequest{Deployment: group, ServiceDeclarations: controlv1.ProjectServiceDeclarations{"api": protocol}, TeamId: f.identity.teamID, Source: &testProjectSource, ProjectLabel: &projectLabel, Configuration: controlv1.ProjectConfiguration{Settings: &controlv1.DeploymentSettings{}, Services: map[string]controlv1.ProjectServiceConfiguration{"api": {Protocol: &protocol, Target: targetAddress, Public: new(true)}}, Webhooks: map[string]controlv1.ProjectWebhook{}}})
			if err != nil {
				t.Fatal(err)
			}
			// reserve public capacity, then start privately with that reservation
			// retained so enablement below does not replace the active run.
			binding := applied.Configuration.Services["api"]
			binding.Public = new(false)
			applied.Configuration.Services["api"] = binding
			applied, err = f.identity.routes.ApplyProjectConfiguration(t.Context(), project, controlv1.ApplyProjectConfigurationRequest{Deployment: group, ServiceDeclarations: applied.ServiceDeclarations, TeamId: f.identity.teamID, Source: &testProjectSource, ExpectedRevision: applied.Revision, Configuration: applied.Configuration})
			if err != nil {
				t.Fatal(err)
			}
			public, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			enrollment, err := f.identity.routes.CreateDeploymentPublisherEnrollment(t.Context(), f.identity.teamID, project, group, "endpoint-enrollment", controlv1.CreateDeploymentPublisherEnrollmentRequest{Services: []string{"api"}, MaxMembers: new(1), ExpiresIn: new(600)})
			if err != nil {
				t.Fatal(err)
			}
			member, err := f.identity.routes.RedeemDeploymentPublisherEnrollment(t.Context(), enrollment.EnrollmentKey, public)
			if err != nil {
				t.Fatal(err)
			}
			owner, err := publisheridentity.NewDeployment(publisheridentity.NativeControl{PublicURLControl: f.identity.routes, Services: f.identity.routes}, f.identity.routes, f.identity.authority, f.identity.routes.ControlURL(), member, key)
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
			if service.Endpoint == nil || applied.Services[0].Hostname == nil || *applied.Services[0].Hostname != service.Endpoint.Hostname || service.Endpoint.Port == 0 || service.Endpoint.Public {
				t.Fatal("missing private TLS metadata or retained public reservation", service)
			}
			identity := authorityv1.PublisherEnrollmentResult{ClientId: member.PublisherIdentityId, KeyId: member.KeyId, TeamId: member.TeamId, GrantId: assignment.GrantId, Kind: authorityv1.Service, ServiceId: &assignment.ServiceId}
			quic, tcp := f.connectors()
			publisherCtx, stopPublisher := context.WithCancel(t.Context())
			publisherReady, publisherDone := make(chan struct{}), make(chan error, 1)
			go func() {
				publisherDone <- publisherservice.Publish(publisherCtx, publisherservice.RunConfig{Control: native, State: f.identity.state, Access: native.Access, Identity: identity, ServiceID: service.Id, Target: targetAddress, Metadata: publisheridentity.ServiceMetadata(service), HeartbeatInterval: 100 * time.Millisecond, Ready: func() error { close(publisherReady); return nil }, RelayQUIC: quic, RelayTCP: tcp})
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
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			connectorCtx, stopConnector := context.WithCancel(t.Context())
			connectorReady, connectorDone := make(chan struct{}), make(chan error, 1)
			connectorJoined := false
			go func() {
				connectorDone <- connectorstream.Serve(connectorCtx, listener, connectorstream.Config{Control: production, ServiceID: service.Id, IdentityID: person.Identity.Id, Protocol: "http", TrustRevision: service.TrustRevision, Endpoint: service.Endpoint, ServiceTLS: f.visitorRoots, TransportTLS: f.roots, RelayQUIC: quic, RelayTCP: tcp, Ready: func() error { close(connectorReady); return nil }})
			}()
			t.Cleanup(func() {
				stopConnector()
				if connectorJoined {
					return
				}
				select {
				case err := <-connectorDone:
					if err != nil {
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
			// arrivals use prepared permission, not a control RPC. revocation must
			// terminate this owner on its background refresh within the existing
			// client request budget, without an application client certificate.
			device, err := production.ConnectorSigner(t.Context(), person.Identity.Id)
			if err != nil {
				t.Fatal(err)
			}
			checkManagedPublicEndpointTLS(t, f, publicServiceIngress, applied, service, device.Subject.DeviceID)
			if err = f.identity.routes.RevokeVisitorDevice(t.Context(), device.Subject.DeviceID); err != nil {
				t.Fatal(err)
			}
			revocation, stopRevocation := context.WithTimeout(t.Context(), client.Timeout)
			defer stopRevocation()
			if _, err := f.identity.routes.SelectServiceRun(revocation, service.Id, device.Subject.DeviceID); !defaultConnectorRevocationDenied(err) {
				t.Fatalf("control did not deny the exact revoked device: %v", err)
			}
			select {
			case err := <-connectorDone:
				connectorJoined = true
				var denial *tunnel.ProtocolError
				// revocation may close both relay legs before their denial reply
				// arrives. control above must independently deny this exact device.
				if !defaultConnectorRevocationDenied(err) && !(errors.As(err, &denial) && denial.Code == tunnelv1.Unauthenticated) && !errors.Is(err, connectorstream.ErrServiceConnection) {
					t.Fatalf("revoked connector did not stop after current access denial: %v", err)
				}
			case <-revocation.Done():
				t.Fatal("revoked connector owner did not join within the request budget")
			}
			transport.CloseIdleConnections()
			if response, err = client.Get("https://" + service.Endpoint.Hostname + "/once"); err == nil {
				_ = response.Body.Close()
				t.Fatal("revoked connector device retained service access")
			}
		})
	}
}

func checkManagedPublicEndpointTLS(t *testing.T, f *privateSeparatedFixture, connector *ingress.PublicServices, applied controlv1.AppliedProjectConfiguration, service controlv1.Service, device string) {
	t.Helper()
	ctx := t.Context()
	material := issueServiceClientCertificate(t, f, service.Id, device)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := ingress.New(listener, ingress.Config{PublicServicesOnly: true, RequireProxyHeader: true, TrustedProxyPeers: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}, PublicServices: connector, ServicePortRanges: []tcpport.Range{{First: service.Endpoint.Port, Last: service.Endpoint.Port}}, MaxConnections: 64})
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
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: f.visitorRoots.RootCAs, ServerName: service.Endpoint.Hostname, MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{material}}, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
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
		binding := applied.Configuration.Services["api"]
		binding.Public = &public
		applied.Configuration.Services["api"] = binding
		result, err := f.identity.routes.ApplyProjectConfiguration(ctx, "managed-runtime", controlv1.ApplyProjectConfigurationRequest{Deployment: applied.Deployment, ServiceDeclarations: applied.ServiceDeclarations, TeamId: f.identity.teamID, Source: &testProjectSource, ExpectedRevision: applied.Revision, Configuration: applied.Configuration})
		if err != nil {
			t.Fatal(err)
		}
		applied = result
	}
	setPublic(true)
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
	assertDenied()
}
