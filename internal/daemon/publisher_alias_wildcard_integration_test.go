package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	"github.com/tnldotdev/tnl/internal/testutil"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationPublisherAliasWildcardPublicTraffic(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	ctx := t.Context()
	f := newServiceRuntimeFixture(t, false, nil)
	const (
		domainName = "wildcard-fixture.example.test"
		parent     = "publishers." + domainName
		canonical  = "shared." + parent
		project    = "wildcard-fixture"
		deployment = "production"
	)
	f.dns.mu.Lock()
	f.dns.customDomain = domainName
	f.dns.mu.Unlock()
	if err := f.database.EnsurePrimaryIngressPool(ctx, "127.0.0.1", "", time.Now()); err != nil {
		t.Fatal(err)
	}
	person, err := f.identity.authority.IdentityContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	domain, err := f.database.ClaimTeamDomain(ctx, controlstate.ClaimDomainRequest{
		TeamID: f.identity.teamID, IdentityID: person.Identity.Id, Domain: domainName,
		IdempotencyKey: domainName, RequestDigest: sha256.Sum256([]byte(domainName)),
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	privateWait(t, 5*time.Second, func(ctx context.Context) (bool, error) {
		authority, err := f.database.GetDNSAuthority(ctx, domain.DNSAuthorityReference)
		return authority.State == controlstate.DNSAuthorityReady, err
	})
	ingress := startSeparatedPrivateIngress(t, f, 0, "wss", nil)
	dial := workloadPublicEndpointDialer(t, ingress.ingresses[0].server, 443)
	transport := &http.Transport{
		TLSClientConfig: f.visitorRoots.Clone(), DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			ready, err := f.dns.VerifyAddress(ctx, host, []string{"127.0.0.1"}, nil, nil)
			if err != nil {
				return nil, err
			}
			if !ready {
				return nil, &net.DNSError{Err: "fixture DNS does not send hostname to ingress", Name: host}
			}
			return dial(ctx, network, address)
		},
	}
	t.Cleanup(transport.CloseIdleConnections)
	visitor := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	var response atomic.Value
	response.Store("first workload")
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, response.Load().(string))
	}))
	cleanupIntegrationHTTPServer(t, target, f.owner)
	mode, protocol := controlv1.Anonymous, controlv1.ServiceProtocolHTTP
	_, err = f.identity.routes.ApplyProjectConfiguration(ctx, project, controlv1.ApplyProjectConfigurationRequest{
		TeamId: f.identity.teamID, Source: &testProjectSource, Deployment: deployment,
		ServiceDeclarations: controlv1.ProjectServiceDeclarations{"web": protocol},
		Configuration: controlv1.ProjectConfiguration{
			Settings: &controlv1.DeploymentSettings{DomainId: &domain.ID},
			Services: map[string]controlv1.ProjectServiceConfiguration{
				"web": {Hostname: new(canonical), PublisherAliasParent: new(parent), CertificateScope: new(parent),
					Target: target.URL, Protocol: &protocol, Public: new(true), Http: &controlv1.ProjectServiceHTTP{Access: &controlv1.ProjectHTTPAccess{Mode: &mode}}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	// exercise pre-provisioning before enrolling any publisher.
	var queued bool
	if err := f.inspect.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM control.publisher_alias_wildcards WHERE parent=$1)`, parent).Scan(&queued); err != nil || !queued {
		var actual string
		_ = f.inspect.QueryRowContext(ctx, `SELECT json_build_array(service.run_alias_parent,service.certificate_scope,service.public, endpoint.dns_automation,
		    endpoint.namespace, domain.kind, domain.state, deployment.domain_id, domain.id,
		    authority.state, authority.provider_zone_id, claim.namespace)::text
		    FROM control.services service JOIN control.service_endpoints endpoint ON endpoint.hostname=service.certificate_hostname
		    JOIN control.domains domain ON domain.id=service.domain_id JOIN control.deployments deployment ON deployment.id=endpoint.deployment_id
		    LEFT JOIN control.dns_authorities authority ON authority.authority_reference=domain.dns_authority_reference
		    LEFT JOIN control.service_namespace_claims claim ON claim.namespace=service.run_alias_parent WHERE endpoint.hostname=$1`, canonical).Scan(&actual)
		t.Fatal("apply did not queue wildcard work", actual, err)
	}
	privateWait(t, 5*time.Second, func(ctx context.Context) (bool, error) {
		var verified bool
		err := f.inspect.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM control.publisher_alias_wildcards WHERE parent=$1 AND verified_until>now())`, parent).Scan(&verified)
		return verified, err
	})
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := f.identity.routes.CreateDeploymentPublisherEnrollment(ctx, f.identity.teamID, project, deployment, "wildcard-member",
		controlv1.CreateDeploymentPublisherEnrollmentRequest{Services: []string{"web"}, MaxMembers: new(1), ExpiresIn: new(600)})
	if err != nil {
		t.Fatal(err)
	}
	member, err := f.identity.routes.RedeemDeploymentPublisherEnrollment(ctx, enrollment.EnrollmentKey, pub)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := publisheridentity.NewDeployment(publisheridentity.NativeControl{Services: f.identity.routes, Runtime: f.identity.routes},
		f.identity.routes, f.identity.authority, f.identity.routes.ControlURL(), member, key)
	if err != nil {
		t.Fatal(err)
	}
	assignments, err := owner.Poll(ctx)
	if err != nil || len(assignments.Services) != 1 {
		t.Fatal("load publisher assignment", err)
	}
	assignment := assignments.Services[0]
	native, err := owner.Service(assignment)
	if err != nil {
		t.Fatal(err)
	}
	service, err := native.SavedService(ctx)
	if err != nil {
		t.Fatal(err)
	}
	quic, tcp := f.connectors()
	start := func() (*integrationPublisher, controlv1.ServiceRunPreparation) {
		t.Helper()
		handle := startOwnedIntegrationPublisher(t, f.owner, publisherservice.RunConfig{
			Control: native, Access: native.Access, State: f.identity.state, ServiceID: service.Id,
			PublisherIdentityID: member.PublisherIdentityId, PublisherGrantID: assignment.GrantId, PublisherKeyID: member.KeyId,
			Metadata: publisheridentity.ServiceMetadata(service), Target: strings.TrimPrefix(target.URL, "http://"),
			RelayQUIC: quic, RelayWebSocket: tcp, HeartbeatInterval: 100 * time.Millisecond, DrainTime: time.Second,
		}, nil)
		run := waitForPublisherReady(t, handle)
		if run.RunHostname == nil || !strings.HasSuffix(*run.RunHostname, "."+parent) {
			t.Fatal("run was not assigned an exact publisher hostname")
		}
		return handle, run
	}
	visit := func(hostname, want string) {
		t.Helper()
		privateWait(t, 10*time.Second, func(ctx context.Context) (bool, error) {
			r, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+hostname, nil)
			if err != nil {
				return false, err
			}
			result, err := visitor.Do(r)
			if err != nil {
				return want == "", nil
			}
			defer result.Body.Close()
			body, err := io.ReadAll(result.Body)
			return result.StatusCode == http.StatusOK && string(body) == want, err
		})
	}
	unknown := "p-aaaaaaaaaaaaaaaaaaaaaaaaaa." + parent
	if resolves, err := f.dns.VerifyAddress(ctx, unknown, []string{"127.0.0.1"}, nil, nil); err != nil || !resolves {
		t.Fatal("unknown alias did not resolve by wildcard", err)
	}
	first, firstRun := start()
	alias := *firstRun.RunHostname
	visit(canonical, "first workload")
	visit(alias, "first workload")
	visit(unknown, "")
	for _, fence := range []string{"shadow", "wrong ingress address", "expired proof"} {
		var change string
		switch fence {
		case "shadow":
			change = `UPDATE control.publisher_alias_wildcards SET shadowed_labels=ARRAY[split_part($2,'.',1)] WHERE parent=$1`
		case "wrong ingress address":
			change = `UPDATE control.publisher_alias_wildcards SET ipv4_address='192.0.2.200' WHERE parent=$1 AND $2<>''`
		case "expired proof":
			change = `UPDATE control.publisher_alias_wildcards SET verified_until=now()-interval '1 second' WHERE parent=$1 AND $2<>''`
		}
		if _, err := f.inspect.ExecContext(ctx, change, parent, alias); err != nil {
			t.Fatal(fence, err)
		}
		visit(alias, "")
		visit(canonical, "first workload")
		// the real DNS worker must observe the current provider/authority
		// facts again before an alias can be routed after proof withdrawal.
		if _, err := f.inspect.ExecContext(ctx, `UPDATE control.publisher_alias_wildcards SET available_at=now() WHERE parent=$1`, parent); err != nil {
			t.Fatal(err)
		}
		visit(alias, "first workload")
	}
	stopIntegrationPublisher(t, first)
	visit(alias, "")
	response.Store("replacement workload")
	second, secondRun := start()
	if *secondRun.RunHostname != alias || secondRun.RunNumber <= firstRun.RunNumber {
		t.Fatal("returning identity did not retain its hostname on a newer run")
	}
	visit(alias, "replacement workload")
	stopIntegrationPublisher(t, second)
	visit(alias, "")
	f.dns.mu.Lock()
	exact, shared := f.dns.exactWrites[alias+"."], f.dns.exactWrites[canonical+"."]
	f.dns.mu.Unlock()
	if exact != 0 || shared == 0 {
		t.Fatalf("DNS writes: %d at publisher alias, %d at canonical hostname", exact, shared)
	}
	if _, err := f.inspect.ExecContext(ctx, `UPDATE control.services SET enabled=false WHERE id=$1`, service.Id); err != nil {
		t.Fatal(err)
	}
	if _, err := f.inspect.ExecContext(ctx, `UPDATE control.publisher_alias_wildcards SET available_at=now() WHERE parent=$1`, parent); err != nil {
		t.Fatal(err)
	}
	privateWait(t, 5*time.Second, func(ctx context.Context) (bool, error) {
		resolves, err := f.dns.VerifyAddress(ctx, unknown, []string{"127.0.0.1"}, nil, nil)
		if err != nil || resolves {
			return false, err
		}
		var retired bool
		err = f.inspect.QueryRowContext(ctx, `SELECT NOT EXISTS (SELECT 1 FROM control.publisher_alias_wildcards WHERE parent=$1)`, parent).Scan(&retired)
		return retired, err
	})
}
