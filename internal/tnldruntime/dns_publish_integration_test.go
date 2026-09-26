package tnldruntime

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
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
	dnsFixture := newIntegrationRoute53(t, "server", serverDomain)
	fixture := newSplitPublishFixtureWithOptions(t, "automatic", splitPublishOptions{dns: dnsFixture})
	namespace, found := strings.CutPrefix(fixture.identity.hostname, "automatic.")
	if !found {
		t.Fatalf("route hostname %q is outside the expected namespace", fixture.identity.hostname)
	}
	fixture.identity.certificatePlan = controlv1.CertificatePlan{
		CacheKey: namespace, Scope: namespace,
		Identifiers: []string{"*." + namespace, namespace}, ChallengeMethod: controlv1.Dns01,
	}
	cleanupStarted, releaseCleanup := make(chan struct{}), make(chan struct{})
	var blockCleanup, releaseCleanupOnce sync.Once
	release := func() { releaseCleanupOnce.Do(func() { close(releaseCleanup) }) }
	defer release()
	dnsFixture.setBeforeChange(func(ctx context.Context, change integrationDNSChange) error {
		if change.Action != "DELETE" || change.Record.Name != dns.Fqdn("_acme-challenge."+namespace) {
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
	target := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(response, "real DNS publish")
	}))
	cleanupIntegrationHTTPServer(t, target, fixture.owner)

	quic, tcp := fixture.connectors()
	finalizing := make(chan controlv1.CertificateIssuance, 1)
	config := fixture.identity.publisherConfig(target.URL, quic, tcp)
	config.Control = &certificateObservingControlClient{
		PublicURLControlClient: config.Control,
		observe: func(issuance controlv1.CertificateIssuance) {
			if issuance.State == controlv1.CertificateIssuanceStateFinalizing {
				select {
				case finalizing <- issuance:
				default:
				}
			}
		},
	}
	handle := startOwnedIntegrationPublisher(t, fixture.owner, config, func() string {
		return integrationPublisherDiagnostics(fixture.inspect, fixture.pebble.logPath)
	})
	select {
	case <-cleanupStarted:
	case <-time.After(30 * time.Second):
		t.Fatal("public URL DNS challenge cleanup did not start")
	}
	select {
	case issuance := <-finalizing:
		if issuance.CertificatePem != nil || issuance.NotBefore != nil || issuance.NotAfter != nil {
			t.Fatalf("finalizing issuance exposed certificate material: %#v", issuance)
		}
	case <-handle.done:
		t.Fatalf("publisher stopped during public URL DNS challenge cleanup: %v", handle.result())
	case <-time.After(10 * time.Second):
		t.Fatal("publisher did not observe the finalizing certificate issuance")
	}
	release()
	ready := fixture.waitReady(t, handle)
	assertIntegrationPublishedPublicURL(t, fixture.inspect, fixture.visitor, fixture.identity, ready)
	assertSplitRoutePlacement(t, fixture.inspect, ready.PublicURLID, ready.PublishRunNumber)
	assertIntegrationDNSChanges(t, dnsFixture, fixture.identity.hostname, false)
	assertIntegrationDNSChanges(t, dnsFixture, namespace, true)

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
	publisher.PublicURLControlClient
	observe func(controlv1.CertificateIssuance)
}

func (c *certificateObservingControlClient) CreateCertificateIssuance(
	ctx context.Context,
	publishRunID string,
	publishRunNumber uint64,
	token credentials.PublishRunToken,
	csr []byte,
	idempotencyKey string,
) (controlv1.CertificateIssuance, error) {
	issuance, err := c.PublicURLControlClient.CreateCertificateIssuance(
		ctx, publishRunID, publishRunNumber, token, csr, idempotencyKey,
	)
	c.observeResponse(issuance, err)
	return issuance, err
}

func (c *certificateObservingControlClient) GetCertificateIssuance(
	ctx context.Context,
	issuanceID string,
	token credentials.PublishRunToken,
) (controlv1.CertificateIssuance, error) {
	issuance, err := c.PublicURLControlClient.GetCertificateIssuance(ctx, issuanceID, token)
	c.observeResponse(issuance, err)
	return issuance, err
}

func (c *certificateObservingControlClient) MarkCertificateChallengeReady(
	ctx context.Context,
	issuanceID string,
	token credentials.PublishRunToken,
) (controlv1.CertificateIssuance, error) {
	issuance, err := c.PublicURLControlClient.MarkCertificateChallengeReady(ctx, issuanceID, token)
	c.observeResponse(issuance, err)
	return issuance, err
}

func (c *certificateObservingControlClient) observeResponse(issuance controlv1.CertificateIssuance, err error) {
	if err == nil {
		c.observe(issuance)
	}
}

func assertIntegrationPublishedPublicURL(t *testing.T, database *sql.DB, visitor *integrationVisitor,
	identity *integrationPublishingIdentity, ready publisher.Event,
) {
	t.Helper()
	if ready.Hostname != identity.hostname || ready.PublicURL != "https://"+identity.hostname {
		t.Fatalf("publisher ready event = %#v", ready)
	}
	var teamID, domainID, membershipID, scope string
	var planJSON []byte
	if err := database.QueryRowContext(integrationOperationContext(t), `
		SELECT r.team_id, r.domain_id, coalesce(r.membership_id, ''), r.public_url_scope,
			json_build_object('cache_key', s.certificate_cache_key, 'scope', s.certificate_scope,
				'identifiers', s.certificate_identifiers, 'challenge_method', s.certificate_challenge)
		FROM control.public_urls r JOIN control.publish_runs s ON s.public_url_id = r.id
		WHERE r.id = $1 AND s.publish_run_number = $2
	`, ready.PublicURLID, ready.PublishRunNumber).Scan(&teamID, &domainID, &membershipID, &scope, &planJSON); err != nil {
		t.Fatal(err)
	}
	if teamID != identity.teamID || domainID != identity.domainID || membershipID != identity.membershipID || scope != string(identity.publicURLScope) {
		t.Errorf("persisted route ownership = %s/%s/%s/%s, want %s/%s/%s/%s", teamID, domainID, membershipID, scope,
			identity.teamID, identity.domainID, identity.membershipID, identity.publicURLScope)
	}
	var plan controlv1.CertificatePlan
	if err := json.Unmarshal(planJSON, &plan); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(plan, identity.certificatePlan) {
		t.Errorf("persisted authority certificate plan = %#v, want %#v", plan, identity.certificatePlan)
	}
	response, body, err := visitor.requestURL(http.MethodGet, ready.PublicURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || string(body) != "real DNS publish" {
		t.Fatalf("visitor response = %s, %q", response.Status, body)
	}
	assertIntegrationPublicURLCertificate(t, response, identity.hostname)
	actual := slices.Clone(response.TLS.PeerCertificates[0].DNSNames)
	want := slices.Clone(identity.certificatePlan.Identifiers)
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
