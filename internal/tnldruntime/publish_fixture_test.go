package tnldruntime

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/authorityclient"
	"github.com/tnldotdev/tnl/internal/clientauth"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/internal/publisher"
	nativeauth "github.com/tnldotdev/tnl/internal/publisheridentity/native"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
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

type integrationConnectorStats struct{ attempts, successful atomic.Int64 }

func observeIntegrationConnector(connector muxsession.Connector) (muxsession.Connector, *integrationConnectorStats) {
	stats := new(integrationConnectorStats)
	return muxsession.ConnectorFunc(func(ctx context.Context, endpoint muxsession.Endpoint) (muxsession.Session, error) {
		stats.attempts.Add(1)
		session, err := connector.Connect(ctx, endpoint)
		if err == nil {
			stats.successful.Add(1)
		}
		return session, err
	}), stats
}

func disabledIntegrationConnector(message string) (muxsession.Connector, *integrationConnectorStats) {
	return observeIntegrationConnector(muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) {
		return nil, errors.New(message)
	}))
}

func newIntegrationHTTPSClient(t *testing.T, roots *x509.CertPool, address string, disableKeepAlives bool, owners ...*runtimeTopology) (*http.Client, *http.Transport) {
	t.Helper()
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}, DisableKeepAlives: disableKeepAlives,
	}
	if address != "" {
		transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return new(net.Dialer).DialContext(ctx, network, address)
		}
	}
	var owner *runtimeTopology
	if len(owners) != 0 {
		owner = owners[0]
	}
	owner.cleanupResource(t, transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 10 * time.Second}, transport
}

type integrationVisitor struct {
	client    *http.Client
	transport *http.Transport
}

func newIntegrationVisitor(t *testing.T, roots *x509.CertPool, address string, owners ...*runtimeTopology) *integrationVisitor {
	t.Helper()
	client, transport := newIntegrationHTTPSClient(t, roots, address, true, owners...)
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
	policyRevision                                          uint64
	state                                                   *clientstate.Store
	routes                                                  *controlclient.Client
	authority                                               *authorityclient.Client
	certificatePlan                                         controlv1.CertificatePlan
	publicURLScope                                          controlv1.PublicURLScope
}

func newIntegrationPublishingIdentity(t *testing.T, controlOrigin string, controlHTTP *http.Client, hostnameLabel string, owners ...*runtimeTopology) *integrationPublishingIdentity {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	var owner *runtimeTopology
	var directory string
	if len(owners) != 0 {
		owner = owners[0]
		directory = owner.directory
	} else {
		directory = t.TempDir()
	}
	stateDatabase, err := clientstate.Open(ctx, filepath.Join(directory, "state"))
	if err != nil {
		t.Fatal(err)
	}
	owner.cleanupResource(t, func() { _ = stateDatabase.Close() })
	saveRuntimeOIDCSession(t, stateDatabase, controlOrigin, owner.databaseURL, owner.managedDomain)
	authenticated, err := clientauth.Authenticate(ctx, clientauth.Config{
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
		policyRevision: uint64(team.PolicyRevision), state: publisherState, routes: authenticated.Control, authority: authenticated.Authority, publicURLScope: controlv1.Member,
		certificatePlan: controlv1.CertificatePlan{CacheKey: hostname, Scope: hostname, Identifiers: []string{hostname}, ChallengeMethod: controlv1.Dns01},
	}
}

// the fixture retains a control session only until the selected saved URL and
// its native publisher are prepared, before the runtime acquires identity locks.
type integrationScopedRunControl struct {
	*controlclient.Client
	state     *clientstate.Store
	authority *authorityclient.Client
}

func (i *integrationPublishingIdentity) publisherConfig(target string, quicConnector, tcpConnector muxsession.Connector) publisher.Config {
	return publisher.Config{
		Control: &integrationScopedRunControl{Client: i.routes, state: i.state, authority: i.authority}, ControlURL: i.controlOrigin, TeamID: i.teamID, DomainID: i.domainID, MembershipID: i.membershipID,
		PolicyRevision: i.policyRevision, PublicURLScope: i.publicURLScope, Purpose: controlv1.App,
		Hostname: i.hostname, Target: target, AccessMode: controlv1.Anonymous, AllowedIPPrefixes: []string{"127.0.0.1/32"},
		State: i.state, QUICConnector: quicConnector, TCPConnector: tcpConnector,
		FallbackDelay: 10 * time.Millisecond, DrainTime: time.Second,
	}
}

type integrationPublisher struct {
	cancel      context.CancelFunc
	done        chan struct{}
	events      eventRecorder[publisher.Event]
	cursor      int
	mu          sync.Mutex
	err         error
	diagnostics func() string
}

func prepareIntegrationPublisher(ctx context.Context, config publisher.Config) (publisher.Config, error) {
	bootstrap, _ := config.Control.(*integrationScopedRunControl)
	observed, _ := config.Control.(*certificateObservingControlClient)
	if observed != nil {
		bootstrap = observed.bootstrap
	}
	if bootstrap != nil {
		prepare, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		route, err := bootstrap.GetPublicURLByHostname(prepare, config.TeamID, config.Hostname)
		if errors.Is(err, controlclient.ErrNotFound) {
			mode := config.AccessMode
			if mode == "" {
				mode = controlv1.Anonymous
			}
			target := config.Target
			if config.PreserveSavedURLTarget {
				target = ""
			}
			body := controlv1.CreatePublicURLRequest{TeamId: config.TeamID, DomainId: config.DomainID,
				CanonicalHostname: config.Hostname, PublicUrlScope: config.PublicURLScope,
				Purpose: config.Purpose, Target: target, AccessMode: &mode,
				AllowedIpPrefixes: &config.AllowedIPPrefixes, Ephemeral: &config.Ephemeral}
			if config.PublicURLScope == controlv1.Member {
				body.MembershipId = &config.MembershipID
			}
			route, err = bootstrap.CreatePublicURL(prepare, body, "fixture-"+config.Hostname)
		}
		if err != nil {
			return config, fmt.Errorf("prepare saved public URL: %w", err)
		}
		native, identity, err := nativeauth.EnsureOwner(prepare, bootstrap.state, bootstrap.Client, bootstrap.authority, route)
		if err != nil {
			return config, fmt.Errorf("prepare enrolled public publisher: %w", err)
		}
		config.Control, config.PublisherID = native, identity.ClientId
		if observed != nil {
			observed.Native = native
			config.Control = observed
		}
	}
	return config, nil
}

func startOwnedIntegrationPublisher(t *testing.T, owner *runtimeTopology, config publisher.Config, diagnostics func() string) *integrationPublisher {
	return startOwnedIntegrationPublisherContext(t, context.Background(), owner, config, diagnostics)
}

func startOwnedIntegrationPublisherContext(t *testing.T, parent context.Context, owner *runtimeTopology, config publisher.Config, diagnostics func() string) *integrationPublisher {
	t.Helper()
	var err error
	config, err = prepareIntegrationPublisher(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(parent)
	handle := &integrationPublisher{cancel: cancel, done: make(chan struct{}), diagnostics: diagnostics}
	if owner != nil {
		owner.publishers = append(owner.publishers, handle)
	} else {
		t.Cleanup(func() {
			if err := handle.stop(); err != nil {
				t.Errorf("publisher cleanup: %v", err)
			}
		})
	}
	config.Logf = t.Logf
	previous := config.Observe
	config.Observe = func(event publisher.Event) error {
		if previous != nil {
			if err := previous(event); err != nil {
				return err
			}
		}
		return handle.observe(event)
	}
	go func() {
		err := publisher.Run(ctx, config)
		handle.mu.Lock()
		handle.err = err
		handle.mu.Unlock()
		handle.events.close()
		close(handle.done)
	}()
	return handle
}

func (p *integrationPublisher) observe(event publisher.Event) error {
	p.events.append(event)
	return nil
}

func (p *integrationPublisher) observedEvents() []publisher.Event {
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
	if err := waitForDoneWithin(p.done, 10*time.Second); err != nil {
		return fmt.Errorf("publisher did not stop: %w", err)
	}
	if err := p.result(); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

func waitForPublisherReady(t *testing.T, handle *integrationPublisher) publisher.Event {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	for {
		event, err := handle.events.next(ctx, &handle.cursor)
		if err != nil {
			diagnostics := ""
			if handle.diagnostics != nil {
				diagnostics = handle.diagnostics()
			}
			t.Fatalf("publisher did not become ready: %v; result %v%s", err, handle.result(), diagnostics)
		}
		if event.Type == publisher.EventReady {
			return event
		}
	}
}

func stopIntegrationPublisher(t *testing.T, handle *integrationPublisher) {
	t.Helper()
	if err := handle.stop(); err != nil {
		t.Fatal(err)
	}
}
