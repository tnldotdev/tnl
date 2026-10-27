package daemon

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	daemonconfig "github.com/tnldotdev/tnl/internal/daemon/config"
	"github.com/tnldotdev/tnl/internal/ingress"
	"github.com/tnldotdev/tnl/internal/naming/tcpport"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationServiceHTTPAuthentication(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	var oidcAddress string
	var issuer *serviceHTTPTestOIDC
	f := newServiceRuntimeFixtureTiming(t, false, nil, false, func(c *daemonconfig.Config, transport *http.Transport, ca *testCertificateAuthority) {
		issuer = newServiceHTTPTestOIDC(t, c.OIDCClientID, "https://"+c.ServerHostname()+"/v1/browser/callback")
		server := httptest.NewUnstartedServer(issuer)
		server.TLS = serviceRuntimeTLS(t, ca, "identity.fixture.test")
		server.StartTLS()
		t.Cleanup(server.Close)
		oidcAddress = server.Listener.Addr().String()
		transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			if address == "identity.fixture.test:443" {
				address = oidcAddress
			}
			return (&net.Dialer{}).DialContext(ctx, network, address)
		}
	})
	team, err := f.identity.authority.CreateTeam(t.Context(), authorityv1.CreateTeamRequest{DisplayName: "http-company", MemberSlug: new("operator")}, "service-http-team")
	if err != nil {
		t.Fatal(err)
	}
	f.identity.teamID = team.Id
	direct := startSeparatedPrivateIngress(t, f, 0, "quic", nil).ingresses[0].private
	startSeparatedPrivateIngress(t, f, 1, "quic", nil)
	var requests atomic.Int64
	var targetConnection atomic.Value
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		targetConnection.Store(r.RemoteAddr)
		if r.Header.Get("Tnl-Access-Token") != "" || r.Header.Get("Tnl-Share-Token") != "" || strings.Contains(r.Header.Get("Cookie"), "__Host-tnl-") || r.Header.Get("X-Forwarded-Host") != "" || r.Header.Get("X-Real-IP") != "" || r.Header.Get("Forwarded") != "" {
			t.Error("target received visitor credentials or spoofed forwarding identity")
		}
		if r.URL.Path == "/cookie-whitespace" && r.Header.Get("Cookie") != "app_session=kept" {
			t.Error("cookie stripping changed the application cookie")
		}
		if r.TLS == nil {
			t.Error("target TLS was not independent of visitor TLS")
		}
		if (r.URL.Path == "/app-auth" || len(r.Header.Values("Authorization")) != 0) && !slices.Equal(r.Header.Values("Authorization"), []string{"caller-one", "caller-two"}) {
			t.Error("application authorization headers changed")
		}
		switch r.URL.Path {
		case "/watch":
			_, _ = io.WriteString(w, "data: ready\n\n")
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		case "/upgrade":
			c, b, err := w.(http.Hijacker).Hijack()
			if err != nil {
				return
			}
			defer c.Close()
			_, _ = io.WriteString(b, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
			_ = b.Flush()
			_, _ = io.Copy(c, b)
		default:
			_, _ = io.WriteString(w, "service-http")
		}
	}))
	targetCA := newTestCertificateAuthority(t)
	const hostname = "target.private.integration.test"
	target.TLS = serviceRuntimeTLS(t, targetCA, hostname)
	target.StartTLS()
	t.Cleanup(target.Close)
	// use a local CA for target trust, separately from Pebble's visitor roots.
	caPEM := string(targetCA.certificatePEM)
	trust := serviceHTTPTestTargetTrust(hostname, caPEM)
	group := "production"
	public := true
	protocol := controlv1.ServiceProtocolHTTP
	configuration := controlv1.ProjectConfiguration{PublisherGroups: map[string]controlv1.ProjectPublisherGroup{group: {Public: &public}}, Services: map[string]controlv1.ProjectServiceConfiguration{"api": {PublisherGroup: &group, Protocol: &protocol, Target: target.URL, TargetTls: &trust, Http: &controlv1.ProjectServiceHTTP{Limits: &controlv1.ProjectHTTPApplicationLimits{Concurrency: new(1)}}}}, Webhooks: map[string]controlv1.ProjectWebhook{}}
	applied, err := f.identity.routes.ApplyProjectConfiguration(t.Context(), "http-auth", controlv1.ApplyProjectConfigurationRequest{TeamId: f.identity.teamID, SourceFingerprint: strings.Repeat("a", 64), Configuration: configuration})
	if err != nil {
		t.Fatal(err)
	}
	if applied.Services[0].ServiceKind != "service" || applied.Services[0].Public == nil || !*applied.Services[0].Public {
		t.Fatal("group HTTP did not use its managed endpoint", applied.Services)
	}
	serviceID := *applied.Services[0].ServiceId
	// a group assignment is the only publisher grant for this service.
	startServiceHTTPGroupPublisher(t, f, applied, "http-auth", group, target.Listener.Addr().String())
	services, err := f.identity.routes.ListAvailableServices(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var service controlv1.Service
	for _, s := range services {
		if s.Id == serviceID {
			service = s
		}
	}
	if service.Endpoint == nil {
		t.Fatal("missing managed endpoint")
	}
	privateWait(t, 5*time.Second, func(context.Context) (bool, error) {
		return direct.DirectServiceReady(uint16(service.Endpoint.Port)), nil
	})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := ingress.New(listener, ingress.Config{DirectOnly: true, RequireProxyHeader: true, TrustedProxyPeers: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}, DirectConnector: direct, ServicePortRanges: []tcpport.Range{{First: service.Endpoint.Port, Last: service.Endpoint.Port}}, MaxConnections: 64})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Drain(ctx)
		<-done
	})
	base := "https://" + net.JoinHostPort(service.Endpoint.Hostname, strconv.Itoa(service.Endpoint.Port))
	newTransport := func(certificate *tls.Certificate) *http.Transport {
		roots := f.visitorRoots.RootCAs.Clone()
		roots.AddCert(f.certificateAuthority.certificate)
		tlsConfig := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
		if certificate != nil {
			tlsConfig.Certificates = []tls.Certificate{*certificate}
		}
		transport := &http.Transport{Proxy: nil, TLSClientConfig: tlsConfig, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if address == "identity.fixture.test:443" {
				return (&net.Dialer{}).DialContext(ctx, network, oidcAddress)
			}
			if address == f.controlConfig.ServerHostname()+":443" {
				return (&net.Dialer{}).DialContext(ctx, network, f.publicControlAddress)
			}
			if address != strings.TrimPrefix(base, "https://") {
				return nil, net.InvalidAddrError("unexpected fixture destination")
			}
			conn, err := (&net.Dialer{}).DialContext(ctx, network, listener.Addr().String())
			if err != nil {
				return nil, err
			}
			metadata, _ := proxyproto.Encode(proxyproto.Header{Source: netip.MustParseAddrPort("192.0.2.44:4242"), Destination: netip.AddrPortFrom(netip.MustParseAddr("203.0.113.10"), uint16(service.Endpoint.Port))})
			if _, err = conn.Write(metadata); err != nil {
				_ = conn.Close()
				return nil, err
			}
			return conn, nil
		}}
		t.Cleanup(transport.CloseIdleConnections)
		return transport
	}
	client := &http.Client{Transport: newTransport(nil), Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request := func(client *http.Client, path, header, secret string, want int) *http.Response {
		t.Helper()
		r, _ := http.NewRequestWithContext(t.Context(), "GET", base+path, nil)
		if header != "" {
			r.Header.Set(header, secret)
		}
		r.Header.Set("X-Forwarded-Host", "attacker.example")
		r.Header.Set("X-Real-IP", "203.0.113.99")
		r.Header["Authorization"] = []string{"caller-one", "caller-two"}
		var response *http.Response
		// a freshly issued credential may precede the publisher's background
		// policy update. retry only explicit pre-admission denials in this fixture;
		// transport failures and application responses are never replayed.
		for deadline := time.Now().Add(5 * time.Second); ; {
			var err error
			response, err = client.Do(r.Clone(r.Context()))
			if err != nil {
				t.Fatal(err)
			}
			if (want != 200 && want != 303) || (response.StatusCode != 403 && response.StatusCode != 503) || !time.Now().Before(deadline) {
				break
			}
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			time.Sleep(10 * time.Millisecond)
		}
		if response.StatusCode != want {
			body, _ := io.ReadAll(response.Body)
			_ = response.Body.Close()
			t.Fatalf("%s status=%d want=%d body=%s", path, response.StatusCode, want, body)
		}
		return response
	}
	closeResponse := func(response *http.Response) { _, _ = io.Copy(io.Discard, response.Body); _ = response.Body.Close() }
	waitDenied := func(client *http.Client, path, header, secret string) {
		t.Helper()
		privateWait(t, 10*time.Second, func(context.Context) (bool, error) {
			r, _ := http.NewRequestWithContext(t.Context(), "GET", base+path, nil)
			if header != "" {
				r.Header.Set(header, secret)
			}
			response, err := client.Do(r)
			if err != nil {
				return false, err
			}
			defer closeResponse(response)
			return response.StatusCode == 403, nil
		})
	}
	createCredential := func(kind controlv1.CreateVisitorCredentialRequestKind) controlv1.VisitorCredential {
		t.Helper()
		credential, err := f.identity.routes.CreateVisitorCredential(t.Context(), controlv1.CreateVisitorCredentialRequest{Resource: controlv1.VisitorResourceScope{Kind: "service", Id: service.Id}, Kind: kind, ExpiresAt: time.Now().Add(time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
		return credential
	}
	baseline := requests.Load()
	closeResponse(request(client, "/", "", "", 403))
	if requests.Load() != baseline {
		t.Fatal("anonymous request reached target")
	}
	token := createCredential("token")
	closeResponse(request(client, "/app-auth", "Tnl-Visitor-Token", token.Permission.VisitorToken, 200))
	firstConnection := targetConnection.Load()
	closeResponse(request(client, "/", "Tnl-Visitor-Token", token.Permission.VisitorToken, 200))
	if targetConnection.Load() != firstConnection {
		t.Fatal("HTTP keepalive selected more than one upstream")
	}
	wrongCertificate := &http.Client{Transport: newTransport(&target.TLS.Certificates[0]), Timeout: 10 * time.Second}
	closeResponse(request(wrongCertificate, "/", "", "", 403))
	closeResponse(request(wrongCertificate, "/", "Tnl-Visitor-Token", token.Permission.VisitorToken, 200))
	closeResponse(request(client, "/__tnl/share/"+token.Permission.VisitorToken, "", "", 403))
	if err = f.identity.routes.RevokeServiceHTTPGrant(t.Context(), service.Id, token.GrantId); err != nil {
		t.Fatal(err)
	}
	waitDenied(client, "/", "Tnl-Visitor-Token", token.Permission.VisitorToken)
	share := createCredential("share")
	if share.Permission.Hostname != service.Endpoint.Hostname || share.Permission.Port != service.Endpoint.Port {
		t.Fatal("share lost allocated port")
	}
	closeResponse(request(client, "/", "Tnl-Visitor-Token", share.Permission.VisitorToken, 403))
	closeResponse(request(client, "/", "Tnl-Access-Token", share.Permission.VisitorToken, 403))
	jar, _ := cookiejar.New(nil)
	shareClient := *client
	shareClient.Jar = jar
	closeResponse(request(&shareClient, "/__tnl/share/"+share.Permission.VisitorToken, "", "", 303))
	closeResponse(request(&shareClient, "/", "", "", 200))
	if err = f.identity.routes.RevokeServiceHTTPGrant(t.Context(), service.Id, share.GrantId); err != nil {
		t.Fatal(err)
	}
	waitDenied(&shareClient, "/", "", "")
	// a browser completes real OIDC discovery, PKCE/code redemption and the same
	// control callback used by public URLs. it never supplies a TLS certificate.
	browser := *client
	browser.Jar, _ = cookiejar.New(nil)
	response := request(&browser, "/__tnl/team/login?return=/", "", "", 303)
	login := response.Header.Get("Location")
	closeResponse(response)
	response, err = browser.Get(login)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 302 {
		t.Fatalf("browser login: %d", response.StatusCode)
	}
	authorize, err := url.Parse(response.Header.Get("Location"))
	closeResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	fields := authorize.Query()
	if fields.Get("redirect_uri") != "https://"+f.controlConfig.ServerHostname()+"/v1/browser/callback" {
		t.Fatal("browser used another callback", fields.Get("redirect_uri"))
	}
	authorize.RawQuery = ""
	response, err = browser.PostForm(authorize.String(), fields)
	if err != nil {
		t.Fatal(err)
	}
	callback := response.Header.Get("Location")
	closeResponse(response)
	response, err = browser.Get(callback)
	if err != nil {
		t.Fatal(err)
	}
	handoff := response.Header.Get("Location")
	if response.StatusCode != 303 || !strings.HasPrefix(handoff, base+"/__tnl/team/handoff/") {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("browser callback lost managed port: status=%d location=%s body=%s", response.StatusCode, handoff, body)
	}
	closeResponse(response)
	response, err = browser.Get(handoff)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 303 {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("handoff: %d %s", response.StatusCode, body)
	}
	for _, cookie := range response.Cookies() {
		if cookie.Name == "__Host-tnl-browser" && (!cookie.Secure || !cookie.HttpOnly || cookie.Domain != "" || cookie.Path != "/") {
			t.Fatal("unsafe browser cookie")
		}
	}
	closeResponse(response)
	closeResponse(request(&browser, "/", "", "", 200))
	// net/http accepts whitespace between a reserved cookie name and '='.
	// use the actual signed-in browser credential through ingress and control,
	// and verify the target still receives only the application cookie.
	originForCookies, _ := url.Parse(base)
	var browserSecret, browserPermission string
	for _, cookie := range browser.Jar.Cookies(originForCookies) {
		if cookie.Name == "__Host-tnl-browser" {
			browserSecret = cookie.Value
		}
		if cookie.Name == "__Host-tnl-visitor" {
			browserPermission = cookie.Value
		}
	}
	if browserSecret == "" || browserPermission == "" {
		t.Fatal("browser credential missing")
	}
	for _, space := range []string{" ", "\t", " \t "} {
		closeResponse(request(client, "/cookie-whitespace", "Cookie", "app_session=kept; __Host-tnl-visitor"+space+"="+browserPermission+"; __Host-tnl-browser"+space+"="+browserSecret+"; __Host-tnl-share"+space+"=unused; __Host-tnl-feedback-browser"+space+"=unused; __Host-tnl-browser-attempt"+space+"=unused", 200))
	}
	badOrigin, _ := http.NewRequestWithContext(t.Context(), "POST", base+"/__tnl/team/logout", nil)
	badOrigin.Header.Set("Origin", "https://"+service.Endpoint.Hostname)
	badOriginResponse, err := browser.Do(badOrigin)
	if err != nil {
		t.Fatal(err)
	}
	if badOriginResponse.StatusCode != 403 {
		t.Fatal("logout accepted an origin without its allocated port")
	}
	closeResponse(badOriginResponse)
	badHost, _ := http.NewRequestWithContext(t.Context(), "GET", base+"/", nil)
	badHost.Host = service.Endpoint.Hostname
	badHost.Header.Set("X-Forwarded-Host", strings.TrimPrefix(base, "https://"))
	badHostResponse, err := browser.Do(badHost)
	if err != nil {
		t.Fatal(err)
	}
	if badHostResponse.StatusCode != 421 {
		t.Fatal("forwarded host overrode the allocated port")
	}
	closeResponse(badHostResponse)
	closeResponse(request(&browser, "/__tnl/feedback/threads", "", "", 404))
	closeResponse(request(&browser, "/", "Tnl-Access-Token", "invalid", 403))
	privateWait(t, 10*time.Second, func(ctx context.Context) (bool, error) {
		replay, err := http.NewRequestWithContext(ctx, http.MethodGet, handoff, nil)
		if err != nil {
			return false, err
		}
		response, err := browser.Do(replay)
		if err != nil {
			return false, err
		}
		defer closeResponse(response)
		if response.StatusCode == http.StatusServiceUnavailable {
			// policy preparation precedes redemption; a transient 503 cannot
			// spend the ticket or count as evidence of a replay bypass.
			return false, nil
		}
		if response.StatusCode != http.StatusForbidden {
			return false, fmt.Errorf("handoff replay succeeded: status=%d", response.StatusCode)
		}
		return true, nil
	})
	checkServiceHTTPUpgrade(t, &browser, base)
	// revocation terminates already admitted streaming responses, and the next
	// request on a keepalive connection cannot reuse the earlier decision.
	response = request(&browser, "/watch", "", "", 200)
	reader := bufio.NewReader(response.Body)
	if line, err := reader.ReadString('\n'); err != nil || line != "data: ready\n" {
		t.Fatal(line, err)
	}
	closeResponse(request(&browser, "/", "", "", 503))
	origin, _ := url.Parse(base)
	var cookie string
	for _, c := range browser.Jar.Cookies(origin) {
		if c.Name == "__Host-tnl-browser" {
			cookie = c.Value
		}
	}
	if cookie == "" {
		t.Fatal("browser session cookie missing")
	}
	logout, _ := http.NewRequestWithContext(t.Context(), "POST", base+"/__tnl/team/logout", nil)
	logout.Header.Set("Origin", base)
	loggedOut, err := browser.Do(logout)
	if err != nil {
		t.Fatal(err)
	}
	if loggedOut.StatusCode != 204 {
		t.Fatal("port-bound logout failed", loggedOut.StatusCode)
	}
	closeResponse(loggedOut)
	if _, err = io.Copy(io.Discard, reader); err == nil {
		t.Fatal("revocation did not close the stream")
	}
	_ = response.Body.Close()
	closeResponse(request(&browser, "/", "", "", 403))
	// real native mTLS, with curl verifying the independently issued service CA.
	person, err := f.identity.authority.IdentityContext(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	key, _, _ := ed25519.GenerateKey(rand.Reader)
	device, err := f.identity.routes.EnrollVisitorDevice(t.Context(), key)
	if err != nil {
		t.Fatal(err)
	}
	material, err := f.identity.state.EnsureServiceClientCertificate(t.Context(), person.Identity.Id, service.Id, device.Id, func(ctx context.Context, csr []byte) (controlv1.ServiceClientCertificate, error) {
		return f.identity.routes.IssueServiceClientCertificate(ctx, service.Id, device.Id, csr)
	})
	if err != nil {
		t.Fatal(err)
	}
	mtls := &http.Client{Transport: newTransport(&material.Certificate), Timeout: 10 * time.Second}
	closeResponse(request(mtls, "/", "", "", 200))
	transition := createCredential("token")
	connectionBeforeProofChange := targetConnection.Load()
	closeResponse(request(mtls, "/", "Tnl-Visitor-Token", transition.Permission.VisitorToken, 200))
	closeResponse(request(mtls, "/", "", "", 200))
	if targetConnection.Load() != connectionBeforeProofChange {
		t.Fatal("credential selection changed the selected upstream")
	}
	if err = f.identity.routes.RevokeServiceHTTPGrant(t.Context(), service.Id, transition.GrantId); err != nil {
		t.Fatal(err)
	}
	closeResponse(request(mtls, "/", "Tnl-Access-Token", "invalid", 403))
	serviceHTTPCurl(t, f, listener.Addr().String(), service, material.Certificate)
	certificateDigest := sha256.Sum256(material.Certificate.Certificate[0])
	if _, err = f.inspect.ExecContext(t.Context(), `UPDATE control.service_client_certificates SET revoked_at=now() WHERE certificate_digest=$1`, certificateDigest[:]); err != nil {
		t.Fatal(err)
	}
	waitDenied(mtls, "/", "", "")
	key, _, _ = ed25519.GenerateKey(rand.Reader)
	device, err = f.identity.routes.EnrollVisitorDevice(t.Context(), key)
	if err != nil {
		t.Fatal(err)
	}
	material, err = f.identity.state.EnsureServiceClientCertificate(t.Context(), person.Identity.Id, service.Id, device.Id, func(ctx context.Context, csr []byte) (controlv1.ServiceClientCertificate, error) {
		return f.identity.routes.IssueServiceClientCertificate(ctx, service.Id, device.Id, csr)
	})
	if err != nil {
		t.Fatal(err)
	}
	mtls = &http.Client{Transport: newTransport(&material.Certificate), Timeout: 10 * time.Second}
	closeResponse(request(mtls, "/", "", "", 200))
	if err = f.identity.routes.RevokeVisitorDevice(t.Context(), device.Id); err != nil {
		t.Fatal(err)
	}
	waitDenied(mtls, "/", "", "")
	// stale public DNS cannot override current private reachability, and neither
	// the stable hostname nor allocated port changes during the transition.
	g := applied.Configuration.PublisherGroups[group]
	g.Public = new(false)
	applied.Configuration.PublisherGroups[group] = g
	updated, err := f.identity.routes.ApplyProjectConfiguration(t.Context(), "http-auth", controlv1.ApplyProjectConfigurationRequest{TeamId: f.identity.teamID, SourceFingerprint: strings.Repeat("a", 64), ExpectedRevision: applied.Revision, Configuration: applied.Configuration})
	if err != nil {
		t.Fatal(err)
	}
	if *updated.Services[0].Hostname != service.Endpoint.Hostname || *updated.Services[0].Port != service.Endpoint.Port {
		t.Fatal("reachability changed endpoint")
	}
	privateWait(t, 10*time.Second, func(context.Context) (bool, error) {
		return !direct.DirectServiceReady(uint16(service.Endpoint.Port)), nil
	})
	client.Transport.(*http.Transport).CloseIdleConnections()
	if response, err = client.Get(base + "/"); err == nil {
		_ = response.Body.Close()
		t.Fatal("stale DNS admitted service directly")
	}
	g.Public = new(true)
	updated.Configuration.PublisherGroups[group] = g
	if _, err = f.identity.routes.ApplyProjectConfiguration(t.Context(), "http-auth", controlv1.ApplyProjectConfigurationRequest{TeamId: f.identity.teamID, SourceFingerprint: strings.Repeat("a", 64), ExpectedRevision: updated.Revision, Configuration: updated.Configuration}); err != nil {
		t.Fatal(err)
	}
	privateWait(t, 10*time.Second, func(context.Context) (bool, error) {
		return direct.DirectServiceReady(uint16(service.Endpoint.Port)), nil
	})
	checkServiceHTTPCompany(t, f, issuer, client, base, service, person.Identity.Id)
	var publicURLs int
	if err = f.inspect.QueryRowContext(t.Context(), `SELECT count(*) FROM control.public_urls`).Scan(&publicURLs); err != nil || publicURLs != 0 {
		t.Fatal("managed authentication fabricated public URL state", publicURLs, err)
	}
}

func checkServiceHTTPUpgrade(t *testing.T, client *http.Client, base string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	upgrading := *client
	upgrading.Timeout = 0
	r, _ := http.NewRequestWithContext(ctx, "GET", base+"/upgrade", nil)
	r.Header.Set("Connection", "Upgrade")
	r.Header.Set("Upgrade", "websocket")
	response, err := upgrading.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 101 {
		t.Fatal("upgrade denied", response.StatusCode)
	}
	stream := response.Body.(io.ReadWriteCloser)
	_, _ = io.WriteString(stream, "one-upstream")
	value := make([]byte, len("one-upstream"))
	if _, err = io.ReadFull(stream, value); err != nil || string(value) != "one-upstream" {
		t.Fatal("upgrade changed bytes", err)
	}
}

func serviceHTTPCurl(t *testing.T, f *privateSeparatedFixture, direct string, service controlv1.Service, certificate tls.Certificate) {
	t.Helper()
	// curl connects to a fixture edge which supplies trusted outer PROXY v2.
	edge, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer edge.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := edge.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		up, err := net.Dial("tcp", direct)
		if err != nil {
			return
		}
		defer up.Close()
		metadata, _ := proxyproto.Encode(proxyproto.Header{Source: netip.MustParseAddrPort("192.0.2.44:4242"), Destination: netip.AddrPortFrom(netip.MustParseAddr("203.0.113.10"), uint16(service.Endpoint.Port))})
		_, _ = up.Write(metadata)
		copied := make(chan struct{})
		go func() { defer close(copied); _, _ = io.Copy(up, c); _ = up.Close() }()
		_, _ = io.Copy(c, up)
		_ = c.Close()
		<-copied
	}()
	directory := t.TempDir()
	var chain []byte
	for _, der := range certificate.Certificate {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	key := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	for name, data := range map[string][]byte{"client.pem": chain, "key.pem": key, "root.pem": f.visitorRootPEM} {
		if err = os.WriteFile(filepath.Join(directory, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	port := strconv.Itoa(service.Endpoint.Port)
	command := exec.CommandContext(t.Context(), "curl", "--silent", "--show-error", "--fail", "--max-time", "10", "--noproxy", "*", "--cacert", filepath.Join(directory, "root.pem"), "--cert", filepath.Join(directory, "client.pem"), "--key", filepath.Join(directory, "key.pem"), "--connect-to", service.Endpoint.Hostname+":"+port+":"+edge.Addr().String(), "https://"+net.JoinHostPort(service.Endpoint.Hostname, port)+"/")
	output, err := command.CombinedOutput()
	_ = edge.Close()
	<-done
	if err != nil || string(output) != "service-http" {
		t.Fatalf("mTLS curl: %s %v", output, err)
	}
}

func serviceHTTPTestTargetTrust(hostname, caPEM string) controlv1.ProjectTargetTLS {
	digest := sha256.Sum256([]byte("tnl-target-tls/v1\x00" + hostname + "\x00" + caPEM))
	return controlv1.ProjectTargetTLS{Hostname: hostname, CaPem: &caPEM, Digest: hex.EncodeToString(digest[:])}
}

func startServiceHTTPGroupPublisher(t *testing.T, f *privateSeparatedFixture, applied controlv1.AppliedProjectConfiguration, project, group, target string) {
	t.Helper()
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
	if assignment.ServiceId != *applied.Services[0].ServiceId {
		t.Fatal("group selected another service")
	}
	native, err := owner.Service(assignment)
	if err != nil {
		t.Fatal(err)
	}
	service, err := native.SavedService(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	identity := authorityv1.PublisherEnrollmentResult{ClientId: member.PublisherIdentityId, KeyId: member.KeyId, TeamId: member.TeamId, GrantId: assignment.GrantId, Kind: authorityv1.Service, ServiceId: &service.Id}
	quic, tcp := f.connectors()
	ctx, cancel := context.WithCancel(t.Context())
	ready, done := make(chan struct{}), make(chan error, 1)
	go func() {
		done <- publisherservice.Publish(ctx, publisherservice.RunConfig{Control: native, State: f.identity.state, Access: native.Access, Identity: identity, ServiceID: service.Id, Target: target, Metadata: publisheridentity.ServiceMetadata(service), HeartbeatInterval: 100 * time.Millisecond, Ready: func() error { close(ready); return nil }, Connect: func(ctx context.Context, b *publisherservice.Bound, slot uint8) (publisherservice.SlotSession, error) {
			return b.ConnectSlotWithTransports(ctx, slot, false, quic, tcp)
		}})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(15 * time.Second):
			t.Error("service HTTP publisher did not join")
		}
	})
	select {
	case <-ready:
	case err := <-done:
		done <- err
		t.Fatal(err)
	case <-time.After(15 * time.Second):
		t.Fatal("service HTTP publisher not ready")
	}
}
