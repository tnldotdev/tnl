package daemon

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/client/auth"
	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/failure"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func redirectIntegrationConnector(address string, connector muxsession.Connector) muxsession.Connector {
	return muxsession.ConnectorFunc(func(ctx context.Context, endpoint muxsession.Endpoint) (muxsession.Session, error) {
		if address == "" {
			return nil, errors.New("integration connector address is empty")
		}
		endpoint.Address = address
		return connector.Connect(ctx, endpoint)
	})
}

func publicURLIntegrationConnector(addresses map[string]string, connector muxsession.Connector) muxsession.Connector {
	return muxsession.ConnectorFunc(func(ctx context.Context, endpoint muxsession.Endpoint) (muxsession.Session, error) {
		address := addresses[endpoint.Address]
		if address == "" {
			return nil, fmt.Errorf("integration connector has no destination for %q", endpoint.Address)
		}
		endpoint.Address = address
		return connector.Connect(ctx, endpoint)
	})
}

type integrationConnectorStats struct{ attempts, successful, postQuantum atomic.Int64 }

func observeIntegrationConnector(connector muxsession.Connector) (muxsession.Connector, *integrationConnectorStats) {
	stats := new(integrationConnectorStats)
	return muxsession.ConnectorFunc(func(ctx context.Context, endpoint muxsession.Endpoint) (muxsession.Session, error) {
		stats.attempts.Add(1)
		session, err := connector.Connect(ctx, endpoint)
		if err == nil {
			stats.successful.Add(1)
			if peer, ok := session.(muxsession.AcceptedPeer); ok && peer.TLSConnectionState().CurveID == tls.X25519MLKEM768 {
				stats.postQuantum.Add(1)
			}
		}
		return session, err
	}), stats
}

func disabledIntegrationConnector(message string) (muxsession.Connector, *integrationConnectorStats) {
	return observeIntegrationConnector(muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) {
		return nil, errors.New(message)
	}))
}

func newIntegrationHTTPSClient(t *testing.T, roots *x509.CertPool, address string, disableKeepAlives bool, owner *runtimeTopology) (*http.Client, *http.Transport) {
	t.Helper()
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}, DisableKeepAlives: disableKeepAlives,
	}
	if address != "" {
		transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return new(net.Dialer).DialContext(ctx, network, address)
		}
	}
	owner.cleanupResource(t, transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 10 * time.Second}, transport
}

type integrationVisitor struct {
	client    *http.Client
	transport *http.Transport
}

func newIntegrationVisitor(t *testing.T, roots *x509.CertPool, address string, owner *runtimeTopology) *integrationVisitor {
	t.Helper()
	client, transport := newIntegrationHTTPSClient(t, roots, address, true, owner)
	return &integrationVisitor{client: client, transport: transport}
}

func (v *integrationVisitor) request(request *http.Request) (*http.Response, []byte, error) {
	response, err := v.client.Do(request)
	if err != nil {
		return nil, nil, err
	}
	body, readErr := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	return response, body, errors.Join(readErr, closeErr)
}

func (v *integrationVisitor) requestURL(method, target string, body io.Reader) (*http.Response, []byte, error) {
	return v.requestURLContext(context.Background(), method, target, body)
}

func (v *integrationVisitor) requestURLContext(ctx context.Context, method, target string, body io.Reader) (*http.Response, []byte, error) {
	request, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, nil, err
	}
	return v.request(request)
}

func assertIntegrationPublicURLCertificate(t *testing.T, response *http.Response, hostname string) {
	t.Helper()
	if response.TLS == nil || len(response.TLS.PeerCertificates) == 0 {
		t.Fatal("visitor response has no verified route TLS certificate")
	}
	if err := response.TLS.PeerCertificates[0].VerifyHostname(hostname); err != nil {
		t.Fatalf("route TLS certificate hostname: %v", err)
	}
}

type integrationPublishingIdentity struct {
	controlOrigin, hostname, teamID, domainID, membershipID string
	state                                                   *clientstate.Store
	routes                                                  *clientcontrol.Client
	authority                                               *clientauthority.Client
}

func newIntegrationPublishingIdentity(t *testing.T, controlOrigin string, controlHTTP *http.Client, hostnameLabel string, owner *runtimeTopology) *integrationPublishingIdentity {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	stateDatabase, err := clientstate.OpenWithOptions(ctx, filepath.Join(owner.directory, "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	owner.cleanupResource(t, func() { _ = stateDatabase.Close() })
	saveRuntimeOIDCSession(t, stateDatabase, controlOrigin, owner.databaseURL, owner.managedDomain)
	authenticated, err := auth.Authenticate(ctx, auth.Config{
		ServerEndpoint: controlOrigin, State: stateDatabase, HTTPClient: controlHTTP, Diagnostics: io.Discard,
	})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := authenticated.Authority.IdentityContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	team, err := authenticated.Authority.GetTeam(ctx, identity.PersonalTeamId)
	if err != nil {
		t.Fatal(err)
	}
	domainPage, err := authenticated.Authority.ListTeamDomains(ctx, team.Id)
	if err != nil {
		t.Fatal(err)
	}
	var membership authorityv1.Membership
	for _, candidate := range identity.Memberships {
		if candidate.TeamId == team.Id {
			membership = candidate
			break
		}
	}
	if membership.Id == "" {
		t.Fatal("personal team membership is missing")
	}
	var domain authorityv1.Domain
	for _, candidate := range domainPage.Domains {
		if candidate.Id == team.DefaultDomainId {
			domain = candidate
			break
		}
	}
	if domain.Id == "" || domain.State != authorityv1.DomainStateReady {
		t.Fatalf("default domain is not ready: %#v", domain)
	}
	publisherState, err := stateDatabase.Server(ctx, controlOrigin)
	if err != nil {
		t.Fatal(err)
	}
	hostname := hostnameLabel + "." + membership.ManagedLabel + "." + domain.CanonicalDomain
	return &integrationPublishingIdentity{
		controlOrigin: controlOrigin, hostname: hostname, teamID: team.Id, domainID: domain.Id, membershipID: membership.Id,
		state: publisherState, routes: authenticated.Control, authority: authenticated.Authority,
	}
}

// preparation uses management authority only to save the declaration and issue
// the exact native grant. the service owner never inherits that control session.
func (i *integrationPublishingIdentity) prepareService(t *testing.T, target string, quic, tcp muxsession.Connector, declaration controlv1.ProjectServiceConfiguration) (controlv1.Service, publisherservice.RunConfig) {
	t.Helper()
	declaration.Protocol, declaration.Public = new(controlv1.ServiceProtocolHTTP), new(true)
	if declaration.Hostname == nil {
		declaration.Hostname = &i.hostname
	}
	declaration.DomainId = &i.domainID
	if declaration.Target == "" {
		declaration.Target = target
		if target == "" {
			declaration.Target = "app"
		}
	}
	if declaration.Http == nil {
		declaration.Http = &controlv1.ProjectServiceHTTP{}
	}
	if declaration.Http.Access == nil {
		declaration.Http.Access = &controlv1.ProjectHTTPAccess{}
	}
	if declaration.Http.Access.Mode == nil {
		declaration.Http.Access.Mode = new(controlv1.Anonymous)
	}
	if declaration.Http.Access.Ip == nil {
		declaration.Http.Access.Ip = new([]string{"127.0.0.1/32"})
	}
	digest := sha256.Sum256([]byte(*declaration.Hostname))
	name := "fixture-" + hex.EncodeToString(digest[:8])
	saved, err := i.routes.CreateServiceAt(t.Context(), i.teamID, name, "fixture:"+*declaration.Hostname,
		&controlv1.ServicePlacement{DomainId: &i.domainID, Hostname: declaration.Hostname},
		controlv1.ServiceMetadata{Protocol: controlv1.ServiceProtocolHTTP}, &declaration)
	if err != nil {
		t.Fatal("save fixture service", err)
	}
	native, identity, err := publisheridentity.EnsureServiceOwner(t.Context(), i.state, i.routes, i.authority, saved)
	if err != nil {
		t.Fatal("enroll fixture service publisher", err)
	}
	return saved, publisherservice.RunConfig{
		Control: native, Access: native.Access, State: i.state, ServiceID: saved.Id,
		PublisherIdentityID: identity.ClientId, PublisherGrantID: identity.GrantId, PublisherKeyID: identity.KeyId,
		Target: strings.TrimPrefix(target, "http://"), Metadata: publisheridentity.ServiceMetadata(saved),
		RelayQUIC: quic, RelayTCP: tcp, DrainTime: time.Second, HeartbeatInterval: 100 * time.Millisecond,
	}
}

type integrationPublisher struct {
	cancel      context.CancelFunc
	done        chan struct{}
	events      eventRecorder[publisherservice.RunStatus]
	ready       eventRecorder[controlv1.ServiceRunPreparation]
	cursor      int
	mu          sync.Mutex
	err         error
	diagnostics func() string
}

func startOwnedIntegrationPublisher(t *testing.T, owner *runtimeTopology, config publisherservice.RunConfig, diagnostics func() string) *integrationPublisher {
	return startOwnedIntegrationPublisherContext(t, context.Background(), owner, config, diagnostics)
}

func startOwnedIntegrationPublisherContext(t *testing.T, parent context.Context, owner *runtimeTopology, config publisherservice.RunConfig, diagnostics func() string) *integrationPublisher {
	t.Helper()
	ctx, cancel := context.WithCancel(parent)
	handle := &integrationPublisher{cancel: cancel, done: make(chan struct{}), diagnostics: diagnostics}
	owner.publishers = append(owner.publishers, runtimeProcess{name: "publisher", cancel: cancel, wait: handle.wait})
	var binding controlv1.ServiceRunPreparation
	prepared, ready, status := config.Prepared, config.Ready, config.ObserveReadiness
	config.Prepared = func(run controlv1.ServiceRunPreparation) error {
		if prepared != nil {
			if err := prepared(run); err != nil {
				return err
			}
		}
		binding = run
		return nil
	}
	config.Ready = func() error {
		if ready != nil {
			if err := ready(); err != nil {
				return err
			}
		}
		handle.ready.append(binding)
		return nil
	}
	config.ObserveReadiness = func(current publisherservice.RunStatus) {
		if status != nil {
			status(current)
		}
		handle.observe(current)
	}
	go func() {
		err := publisherservice.Publish(ctx, config)
		handle.mu.Lock()
		handle.err = err
		handle.mu.Unlock()
		handle.events.close()
		handle.ready.close()
		close(handle.done)
	}()
	return handle
}

func (p *integrationPublisher) observe(event publisherservice.RunStatus) error {
	p.events.append(event)
	return nil
}

func (p *integrationPublisher) observedEvents() []publisherservice.RunStatus {
	events, _ := p.events.snapshot()
	return events
}

func (p *integrationPublisher) result() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.err
}

func (p *integrationPublisher) stop() error {
	p.cancel()
	return p.wait()
}

func (p *integrationPublisher) wait() error {
	if err := waitForDoneWithin(p.done, 10*time.Second); err != nil {
		return fmt.Errorf("publisher did not stop: %w", err)
	}
	if err := p.result(); err != nil && !failure.Only(err, context.Canceled) {
		return err
	}
	return nil
}

func waitForPublisherReady(t *testing.T, handle *integrationPublisher) controlv1.ServiceRunPreparation {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	run, err := handle.ready.next(ctx, &handle.cursor)
	if err != nil {
		diagnostics := ""
		if handle.diagnostics != nil {
			diagnostics = handle.diagnostics()
		}
		t.Fatalf("publisher did not become ready: %v; result %v%s", err, handle.result(), diagnostics)
	}
	return run
}

func serviceHTTPAddress(run controlv1.ServiceRunPreparation) string { return "https://" + run.Hostname }

func stopIntegrationPublisher(t *testing.T, handle *integrationPublisher) {
	t.Helper()
	if err := handle.stop(); err != nil {
		t.Fatal(err)
	}
}
