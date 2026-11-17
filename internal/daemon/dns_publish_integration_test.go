package daemon

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/testutil"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestDNSIntegrationSplitAutomaticRelayCertificates(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierDNS)
	if runtime.GOOS == "darwin" {
		t.Skip("automatic DNS integration requires binding privileged port 53")
	}
	if integrationDNSSubprocess(t) {
		return
	}
	const serverDomain = "split.integration.test"
	dnsFixture := newIntegrationRoute53(t, "server", serverDomain, newRuntimeTopology(t))
	fixture := newSplitPublishFixtureWithOptions(t, "automatic", splitPublishOptions{dns: dnsFixture})
	namespace, found := strings.CutPrefix(fixture.identity.hostname, "automatic.")
	if !found {
		t.Fatalf("route hostname %q is outside the expected namespace", fixture.identity.hostname)
	}
	cleanupStarted, releaseCleanup := make(chan struct{}), make(chan struct{})
	var blockCleanup, releaseCleanupOnce sync.Once
	release := func() { releaseCleanupOnce.Do(func() { close(releaseCleanup) }) }
	defer release()
	dnsFixture.setBeforeChange(func(ctx context.Context, change integrationDNSChange) error {
		if change.Action != "DELETE" || change.Record.Name != dns.Fqdn("_acme-challenge."+fixture.identity.hostname) {
			return nil
		}
		blockCleanup.Do(func() {
			close(cleanupStarted)
			select {
			case <-releaseCleanup:
			case <-ctx.Done():
			}
		})
		return ctx.Err()
	})
	var targetRequests atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		targetRequests.Add(1)
		_, _ = io.WriteString(response, "real DNS publish")
	}))
	cleanupIntegrationHTTPServer(t, target, fixture.owner)

	quic, tcp := fixture.connectors()
	finalizing := make(chan controlv1.ServiceCertificateIssuance, 1)
	certificateObserved, readyObserved := make(chan time.Time, 1), make(chan time.Time, 1)
	observation := integrationDNSStartupObservation{started: time.Now()}
	saved, config := fixture.identity.prepareService(t, target.URL, quic, tcp, controlv1.ProjectServiceConfiguration{})
	observation.ownerPrepared = time.Now()
	certificateClient := &certificateObservingControlClient{
		Native: config.Control.(*publisheridentity.Native),
		observe: func(issuance controlv1.ServiceCertificateIssuance) {
			if issuance.CertificatePem != nil && *issuance.CertificatePem != "" {
				select {
				case certificateObserved <- time.Now():
				default:
				}
			}
			if issuance.State == controlv1.CertificateIssuanceStateFinalizing {
				select {
				case finalizing <- issuance:
				default:
				}
			}
		},
	}
	config.Control = certificateClient
	// observe the real publisher callback before the fixture records its event;
	// this does not grant readiness or wait for routing installation.
	config.Ready = func() error {
		select {
		case readyObserved <- time.Now():
		default:
		}
		return nil
	}
	observation.publisherStarted = time.Now()
	handle := startOwnedIntegrationPublisher(t, fixture.owner, config, func() string {
		return integrationPublisherDiagnostics(fixture.inspect, fixture.pebble.logPath)
	})
	select {
	case <-cleanupStarted:
	case <-time.After(30 * time.Second):
		t.Fatal("public URL DNS challenge cleanup did not start")
	}
	// finalizing can finish before the publisher's next poll; readiness must not
	// wait for DNS challenge cleanup to finish.
	ready := waitForPublisherReady(t, handle)
	if ready.ServiceId != saved.Id {
		t.Fatal("startup observation changed the saved service")
	}
	select {
	case observation.ready = <-readyObserved:
	default:
		t.Fatal("publisher Ready callback was not observed")
	}
	select {
	case observation.certificateObserved = <-certificateObserved:
	default:
		t.Fatal("cold service certificate material was not observed before Ready")
	}
	// resolve the service name against the configured authoritative DNS, not
	// the fixture's usual pinned ingress dial. only the disposable front port
	// differs from public 443; DNS still selects its IP and TLS checks its name.
	_, frontPort, err := net.SplitHostPort(fixture.publicIngressAddress)
	if err != nil {
		t.Fatal(err)
	}
	dialer := &net.Dialer{Resolver: &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, dnsFixture.address)
	}}}
	fixture.visitor.transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		hostname, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		if hostname != ready.Hostname || port != "443" {
			return nil, fmt.Errorf("unexpected first public destination %q", address)
		}
		return dialer.DialContext(ctx, network, net.JoinHostPort(hostname, frontPort))
	}
	observation.firstGETStarted = time.Now()
	first, body, err := fixture.visitor.requestURLContext(t.Context(), http.MethodGet, serviceHTTPAddress(ready), nil)
	observation.firstGETFinished = time.Now()
	if err != nil {
		t.Fatal("first configured-DNS request after Ready", err)
	}
	if first.StatusCode != http.StatusOK || string(body) != "real DNS publish" ||
		first.TLS == nil || len(first.TLS.VerifiedChains) == 0 || targetRequests.Load() != 1 {
		t.Fatal("first configured-DNS request did not reach the target once over verified TLS", first.Status, string(body), targetRequests.Load())
	}
	changesAtFirstGET := dnsFixture.serviceChanges(ready.Hostname, observation.started, observation.firstGETFinished)
	phases, err := observation.phases(changesAtFirstGET)
	if err != nil {
		t.Fatal("per-service startup observation", err)
	}
	orders := integrationServiceOrderCount(t, fixture.inspect, ready.ServiceId)
	if orders != 1 || certificateClient.createCalls.Load() < 1 {
		t.Fatal("cold service did not record its certificate order and publisher issuance operation", orders, certificateClient.createCalls.Load())
	}
	measurement, err := json.Marshal(map[string]any{
		"sample": "one_cold_service_ready_roles", "service_id": ready.ServiceId, "service_run_number": ready.RunNumber,
		"phase_ns": phases, "dns_record_mutations_at_first_get": changesAtFirstGET,
		"publisher_certificate_create_calls": certificateClient.createCalls.Load(), "publisher_certificate_poll_calls": certificateClient.pollCalls.Load(),
		"persisted_service_certificate_orders": orders, "first_get_target_requests": targetRequests.Load(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Log("startup sample uses local authoritative DNS, the Route 53 HTTP fixture, and Pebble; excludes role startup, cloud cost, and Internet DNS convergence; DNS/certificate offsets overlap")
	t.Logf("service_startup_measurement %s", measurement)
	select {
	case issuance := <-finalizing:
		if issuance.CertificatePem != nil || issuance.NotBefore != nil || issuance.NotAfter != nil {
			t.Fatalf("finalizing issuance exposed certificate material: %#v", issuance)
		}
	default:
	}
	release()
	assertIntegrationPublishedService(t, fixture.inspect, fixture.visitor, fixture.identity, ready)
	assertSplitRoutePlacement(t, fixture.inspect, ready.ServiceId, ready.RunNumber)
	assertIntegrationDNSChanges(t, dnsFixture, fixture.identity.hostname, false)
	dnsFixture.mu.Lock()
	_, exact := dnsFixture.zone.records[dns.Fqdn(fixture.identity.hostname)+"/A"]
	_, owner := dnsFixture.zone.records[dns.Fqdn("_tnl-owner."+fixture.identity.hostname)+"/TXT"]
	_, wildcard := dnsFixture.zone.records[dns.Fqdn("*."+namespace)+"/A"]
	dnsFixture.mu.Unlock()
	if !exact || !owner || wildcard {
		t.Fatalf("service endpoint DNS lost exact ownership or published a broader namespace: A=%t, owner=%t, wildcard=%t", exact, owner, wildcard)
	}
	assertIntegrationDNSChanges(t, dnsFixture, fixture.identity.hostname, true)
	changesAfterCleanup, err := json.Marshal(dnsFixture.serviceChanges(ready.Hostname, observation.started, time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("service_dns_record_mutations_after_challenge_cleanup service_id=%s %s", ready.ServiceId, changesAfterCleanup)

	for _, relay := range []splitRelayFixture{fixture.relayA, fixture.relayB} {
		if relay.config.RelayTLSCertificateFile != "" || relay.config.RelayTLSPrivateKeyFile != "" {
			t.Fatal("automatic relay test has a static certificate override")
		}
		hostname := strings.TrimSuffix(relay.config.RelayAddress, ":443")
		assertIntegrationDNSChanges(t, dnsFixture, hostname, true)
		var orders int
		var installed bool
		if err := fixture.inspect.QueryRowContext(integrationOperationContext(t), `
			SELECT count(orders.id), coalesce(bool_and(
				orders.state = 'complete'
				AND orders.tls_server_name = $2
				AND orders.certificate_pem IS NOT NULL
				AND services.tls_server_name = $2
				AND services.transport_certificate_pem IS NOT NULL
				AND orders.certificate_pem = convert_to(services.transport_certificate_pem, 'UTF8')
			), false)
			FROM control.relay_services AS services
			LEFT JOIN control.relay_certificate_orders AS orders
				ON orders.relay_service_id = services.relay_service_id
			WHERE services.relay_service_id = $1
		`, relay.config.RelayServiceID, hostname).Scan(&orders, &installed); err != nil {
			t.Fatal(err)
		}
		if orders != 1 || !installed {
			t.Errorf("relay service %s certificate orders = %d, installed = %t; want one installed order", relay.config.RelayServiceID, orders, installed)
		}
	}
}

type certificateObservingControlClient struct {
	*publisheridentity.Native
	observe                func(controlv1.ServiceCertificateIssuance)
	createCalls, pollCalls atomic.Int64
}

func (c *certificateObservingControlClient) CreateServiceCertificateIssuance(
	ctx context.Context,
	serviceID, runID string,
	runNumber int64,
	token credentials.ServiceRunToken,
	csr []byte,
	idempotencyKey string,
) (controlv1.ServiceCertificateIssuance, error) {
	c.createCalls.Add(1)
	issuance, err := c.Native.CreateServiceCertificateIssuance(
		ctx, serviceID, runID, runNumber, token, csr, idempotencyKey,
	)
	c.observeResponse(issuance, err)
	return issuance, err
}

func (c *certificateObservingControlClient) GetServiceCertificateIssuance(
	ctx context.Context,
	serviceID, runID, issuanceID string,
	token credentials.ServiceRunToken,
) (controlv1.ServiceCertificateIssuance, error) {
	c.pollCalls.Add(1)
	issuance, err := c.Native.GetServiceCertificateIssuance(ctx, serviceID, runID, issuanceID, token)
	c.observeResponse(issuance, err)
	return issuance, err
}

func (c *certificateObservingControlClient) observeResponse(issuance controlv1.ServiceCertificateIssuance, err error) {
	if err == nil {
		c.observe(issuance)
	}
}

func assertIntegrationPublishedService(t *testing.T, database *sql.DB, visitor *integrationVisitor,
	identity *integrationPublishingIdentity, ready controlv1.ServiceRunPreparation,
) {
	t.Helper()
	if ready.Hostname != identity.hostname || ready.CertificatePlan == nil {
		t.Fatalf("publisher ready event = %#v", ready)
	}
	var teamID, domainID, membershipID string
	var planJSON []byte
	if err := database.QueryRowContext(integrationOperationContext(t), `
		SELECT r.team_id, endpoint.domain_id, membership.id,
			json_build_object('cache_key', s.certificate_cache_key, 'scope', s.certificate_scope,
				'identifiers', s.certificate_identifiers, 'challenge_method', issuance.challenge_method)
		FROM control.services r JOIN control.service_runs s ON s.service_id = r.id
		JOIN control.acme_orders issuance ON issuance.id=s.certificate_issuance_id
		JOIN control.service_endpoints endpoint ON endpoint.service_id=r.id AND endpoint.hostname=$3
		JOIN control.team_memberships membership ON membership.team_id=r.team_id AND membership.identity_id=r.created_by_identity_id
		WHERE r.id = $1 AND s.run_number = $2 AND s.id=$4
	`, ready.ServiceId, ready.RunNumber, ready.Hostname, ready.ServiceRunId).Scan(&teamID, &domainID, &membershipID, &planJSON); err != nil {
		t.Fatal(err)
	}
	if teamID != identity.teamID || domainID != identity.domainID || membershipID != identity.membershipID {
		t.Errorf("persisted service team/domain/creator membership = %s/%s/%s, want %s/%s/%s", teamID, domainID, membershipID,
			identity.teamID, identity.domainID, identity.membershipID)
	}
	var plan controlv1.CertificatePlan
	if err := json.Unmarshal(planJSON, &plan); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(plan, *ready.CertificatePlan) {
		t.Errorf("persisted authority certificate plan = %#v, want %#v", plan, *ready.CertificatePlan)
	}
	response, body, err := visitor.requestURL(http.MethodGet, serviceHTTPAddress(ready), nil)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || string(body) != "real DNS publish" {
		t.Fatalf("visitor response = %s, %q", response.Status, body)
	}
	assertIntegrationPublicURLCertificate(t, response, identity.hostname)
	actual := slices.Clone(response.TLS.PeerCertificates[0].DNSNames)
	want := slices.Clone(ready.CertificatePlan.Identifiers)
	slices.Sort(actual)
	slices.Sort(want)
	if !slices.Equal(actual, want) {
		t.Errorf("publisher certificate SANs = %v, want authority plan %v", actual, want)
	}
}

func assertIntegrationDNSChanges(t *testing.T, fixture *integrationRoute53, hostname string, challenge bool) {
	t.Helper()
	name, recordType := hostname+".", "A"
	if challenge {
		name, recordType = "_acme-challenge."+name, "TXT"
	}
	waitForIntegrationCondition(t, 10*time.Second, func(context.Context) (bool, error) {
		fixture.mu.Lock()
		defer fixture.mu.Unlock()
		published, removed := false, false
		for _, change := range fixture.changes {
			if change.Record.Name != name || change.Record.Type != recordType {
				continue
			}
			if change.zoneID != fixture.zoneID {
				return false, fmt.Errorf("DNS mutation used zone %q, want %q", change.zoneID, fixture.zoneID)
			}
			if change.Action == "DELETE" {
				removed = true
			} else {
				published = true
			}
		}
		_, present := fixture.zone.records[name+"/"+recordType]
		if challenge {
			return published && removed && !present,
				fmt.Errorf("DNS %s %s: published=%t, removed=%t, present=%t", recordType, name, published, removed, present)
		}
		return published && present,
			fmt.Errorf("DNS %s %s: published=%t, present=%t", recordType, name, published, present)
	})
}
