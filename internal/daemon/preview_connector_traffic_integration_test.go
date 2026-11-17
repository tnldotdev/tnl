package daemon

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	connectorstream "github.com/tnldotdev/tnl/internal/connector/stream"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// preview attachment is not connector authority. this adds real data traffic to
// the separate CLI proof of attachment, certificate setup and public-link exclusion.
func TestIntegrationPreviewConnectorOnlyHTTPIndependentGrantTraffic(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	f := newServiceRuntimeFixtureTiming(t, false, nil, true)
	ctx := t.Context()
	team, err := f.identity.authority.CreateTeam(ctx, authorityv1.CreateTeamRequest{DisplayName: "preview-connector-traffic"}, "preview-connector-team")
	if err != nil {
		t.Fatal(err)
	}
	// session issuance is fixture setup, not a login proof. device enrollment,
	// protected keys and all service/preview/grant operations use real clients.
	now := time.Now()
	session, err := f.database.CreateOIDCControlSession(ctx, f.controlConfig.ManagedDomain, controlstate.OIDCIdentity{
		Issuer: f.controlConfig.OIDCIssuer, Subject: "preview-connector-reviewer", DisplayName: "preview connector reviewer",
		AssertionDigest: sha256.Sum256([]byte("preview-connector-reviewer")), AssertionExpiry: now.Add(time.Hour),
	}, time.Hour, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	reviewer, err := clientcontrol.New(f.controlConfig.ControlOrigin(), f.publicHTTP, session.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := clientauthority.New(f.controlConfig.ControlOrigin(), f.publicHTTP, session.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	invitation, err := f.identity.authority.CreateTeamInvitation(ctx, team.Id, authorityv1.CreateInvitationRequest{
		MemberSlug: "reviewer", InitialRole: "member", ExpiresAt: now.Add(time.Hour),
	}, "preview-connector-reviewer")
	if err != nil {
		t.Fatal(err)
	}
	member, err := authority.AcceptInvitation(ctx, invitation.Secret)
	if err != nil || member.Role != "member" {
		t.Fatal("reviewer did not receive an ordinary membership", err)
	}
	identity, err := authority.IdentityContext(ctx)
	if err != nil || identity.Identity.Administrator || identity.Identity.Id != session.Identity.Identity.ID {
		t.Fatal("connector reviewer borrowed the publisher's administrative identity", err)
	}
	state, err := clientstate.OpenWithOptions(ctx, filepath.Join(f.owner.directory, "reviewer-state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	f.owner.cleanupResource(t, func() { _ = state.Close() })
	if err := controltest.SaveSession(ctx, state, f.controlConfig.ControlOrigin(), session); err != nil {
		t.Fatal(err)
	}
	profile, err := state.Server(ctx, f.controlConfig.ControlOrigin())
	if err != nil {
		t.Fatal(err)
	}
	native, err := connectorstream.NewControl(reviewer, profile, session.Identity.Identity.ID)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := native.ConnectorSigner(ctx, session.Identity.Identity.ID)
	if err != nil {
		t.Fatal(err)
	}
	device, found, err := profile.VisitorDevice(ctx, session.Identity.Identity.ID)
	if err != nil || !found || device.ID != signer.Subject.DeviceID {
		t.Fatal("native connector did not use the reviewer's protected enrolled device", err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, device.SigningKey)
	if err != nil {
		t.Fatal(err)
	}
	service, err := f.identity.routes.CreateService(ctx, team.Id, "preview-private", "preview-connector-service",
		controlv1.ServiceMetadata{Protocol: controlv1.ServiceProtocolHTTP}, nil)
	if err != nil || service.Endpoint == nil || service.Endpoint.Public || service.Endpoint.Port != 443 {
		t.Fatal("fixture did not create connector-only HTTP", err)
	}
	preview, err := f.identity.routes.CreatePreview(ctx, team.Id, "preview-connector")
	if err != nil {
		t.Fatal(err)
	}
	attached, err := f.identity.routes.AddPreviewService(ctx, preview.Id, service.Id)
	if err != nil || !slices.Equal(attached.ServiceIds, []string{service.Id}) {
		t.Fatal("real preview API did not attach the connector-only service", err)
	}
	if _, err := f.identity.routes.SetPreviewTeamAccess(ctx, preview.Id, true); err != nil {
		t.Fatal(err)
	}
	share, err := f.identity.routes.CreateShare(ctx, preview.Id, "preview-connector-share", controlv1.CreateShareRequest{
		ServiceIds: []string{service.Id}, EntryServiceId: service.Id, ExpiresAt: now.Add(time.Hour),
	})
	if err != nil || !slices.Equal(share.Share.ServiceIds, []string{service.Id}) {
		t.Fatal("HTTP share did not capture the attached service", err)
	}
	browserSource, err := json.Marshal(controlv1.VisitorTokenControlSessionSource{Kind: "control_session", PreviewId: &preview.Id})
	if err != nil {
		t.Fatal(err)
	}
	shareSource, err := json.Marshal(share.TokenSource)
	if err != nil {
		t.Fatal(err)
	}
	assertHTTPPermissionsRemain := func() {
		t.Helper()
		for _, source := range []json.RawMessage{browserSource, shareSource} {
			permission, err := reviewer.IssueVisitorToken(ctx, controlv1.VisitorTokenRequest{
				Resource: controlv1.VisitorResourceScope{Kind: "service", Id: service.Id}, Source: source,
			})
			if err != nil || permission.VisitorToken == "" {
				t.Fatal("connector denial used an inactive HTTP share or preview-team permission", err)
			}
		}
		current, err := f.identity.routes.GetPreview(ctx, preview.Id)
		if err != nil || !slices.Equal(current.ServiceIds, []string{service.Id}) || current.TeamAccessEnabled == nil || !*current.TeamAccessEnabled {
			t.Fatal("connector grant mutation changed preview attachment/team permission", err)
		}
		currentShare, err := f.identity.routes.GetShare(ctx, share.Share.Id)
		if err != nil || currentShare.RevokedAt != nil {
			t.Fatal("connector grant mutation revoked the independent HTTP share", err)
		}
	}
	assertHTTPPermissionsRemain()
	assertConnectorAuthorityDenied := func() {
		t.Helper()
		if rows, err := reviewer.ListAvailableServices(ctx, controlv1.ServiceAccessPathConnector); err != nil || len(rows) != 0 {
			t.Fatal("HTTP preview permission became connector inventory", err)
		}
		if _, err := native.VisitorPermission(ctx, service.Id); !defaultConnectorRevocationDenied(err) {
			t.Fatal("HTTP preview permission became enrolled-device authority", err)
		}
		if _, err := native.ResolveService(ctx, service.Id); !defaultConnectorRevocationDenied(err) {
			t.Fatal("HTTP preview permission admitted native run selection", err)
		}
		_, err := reviewer.IssueServiceClientCertificate(ctx, service.Id, device.ID, csr)
		var problem *clientcontrol.ProblemError
		if !errors.As(err, &problem) || problem.Status != http.StatusForbidden || problem.Problem.Code != controlv1.Forbidden {
			t.Fatal("native certificate API lost its current forbidden decision", err)
		}
	}
	assertConnectorAuthorityDenied()
	started, targetClosed := make(chan struct{}, 1), make(chan struct{})
	var closeTarget sync.Once
	var requests atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path != "/original" {
			http.Error(w, "unexpected target request", http.StatusBadRequest)
			return
		}
		defer closeTarget.Do(func() { close(targetClosed) })
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: independently authorized preview\n\n")
		if err := http.NewResponseController(w).Flush(); err != nil {
			return
		}
		select {
		case started <- struct{}{}:
		default:
		}
		<-r.Context().Done()
	}))
	cleanupIntegrationHTTPServer(t, target, f.owner)
	stopPublisher := startPrivateHTTPPublisher(t, f, service, target.Listener.Addr().String())
	defer stopPublisher()
	quic, tcp := f.connectors()
	// the native owner must fail before advertising local readiness, not merely
	// hide inventory while admitting an owner through an already known ID.
	deniedListener := serviceRuntimeListener(t, f.owner)
	var deniedReady atomic.Bool
	setup, finishSetup := context.WithTimeout(ctx, 5*time.Second)
	err = connectorstream.Serve(setup, deniedListener, connectorstream.Config{
		Control: native, IdentityID: session.Identity.Identity.ID, ServiceID: service.Id,
		Protocol: string(service.Protocol), TrustRevision: service.TrustRevision, Endpoint: service.Endpoint,
		ServiceTLS: f.visitorRoots, TransportTLS: f.roots, RelayQUIC: quic, RelayTCP: tcp,
		Ready: func() error { deniedReady.Store(true); return nil },
	})
	finishSetup()
	_ = deniedListener.Close()
	if !defaultConnectorRevocationDenied(err) || deniedReady.Load() || requests.Load() != 0 {
		t.Fatal("HTTP-only preview permission started a native connector or reached its target", err)
	}
	grant, err := f.identity.routes.CreateServiceGrant(ctx, service.Id, "preview-independent-connector", controlv1.CreateServiceGrantRequest{
		Kind: "identity", IdentityId: new(session.Identity.Identity.ID),
	})
	if err != nil {
		t.Fatal(err)
	}
	if rows, err := reviewer.ListAvailableServices(ctx, controlv1.ServiceAccessPathConnector); err != nil || len(rows) != 1 ||
		rows[0].Id != service.Id || rows[0].VisitorAccess != "identity_grant" || rows[0].Endpoint == nil || rows[0].Endpoint.Public {
		t.Fatal("independent grant did not select the exact connector-only service", err)
	}
	listener, stopConnector := startRuntimeConnector(t, f, service, connectorstream.Config{
		Control: native, IdentityID: session.Identity.Identity.ID, RelayQUIC: quic, RelayTCP: tcp,
	}, revokedConnectorOwnerStop)
	defer stopConnector()
	run, err := native.ResolveService(ctx, service.Id)
	if err != nil {
		t.Fatal(err)
	}
	permission, err := native.VisitorPermission(ctx, service.Id)
	if err != nil {
		t.Fatal(err)
	}
	// the request owns its original deadline before any bytes flow. revocation
	// must interrupt it before this deadline and its captured authority bounds;
	// no recheck, renewal, request retry or cleanup adds time to that budget.
	deadline := minTime(time.Now().Add(10*time.Second), minTime(run.ValidUntil, permission.ExpiresAt))
	original, finishOriginal := context.WithDeadline(ctx, deadline)
	defer finishOriginal()
	verification := f.visitorRoots.Clone()
	verification.ServerName = service.Endpoint.Hostname
	transport := &http.Transport{Proxy: nil, TLSClientConfig: verification, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	base := "https://" + listener.Addr().String()
	request, err := http.NewRequestWithContext(original, http.MethodGet, base+"/original", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal("real native connector request failed", err)
	}
	defer response.Body.Close()
	const payload = "data: independently authorized preview\n\n"
	body := make([]byte, len(payload))
	if _, err := io.ReadFull(response.Body, body); err != nil || response.StatusCode != http.StatusOK || string(body) != payload || requests.Load() != 1 {
		t.Fatal("native connector changed or replayed the target's response", err)
	}
	select {
	case <-started:
	case <-original.Done():
		t.Fatal("original target handler did not confirm the request")
	}
	var pairRun, pairDevice, pairSession string
	var pairNumber int64
	var pairExpires time.Time
	if err := f.inspect.QueryRowContext(ctx, `SELECT service_run_id,run_number,subject_id,parent_control_session_id,expires_at
		FROM control.connector_peer_pairs WHERE service_id=$1 AND subject_id=$2 AND retired_at IS NULL`,
		service.Id, device.ID).Scan(&pairRun, &pairNumber, &pairDevice, &pairSession, &pairExpires); err != nil ||
		pairRun != run.ServiceRunID || uint64(pairNumber) != run.RunNumber || pairDevice != device.ID || pairSession != session.SessionID {
		t.Fatal("actual traffic borrowed a publisher's device, another run or another session", err)
	}
	if err := f.identity.routes.RevokeServiceGrant(ctx, service.Id, grant.Id); err != nil {
		t.Fatal(err)
	}
	assertConnectorAuthorityDenied()
	assertHTTPPermissionsRemain()
	if _, err := io.Copy(io.Discard, response.Body); err == nil || original.Err() != nil || !time.Now().Before(minTime(deadline, pairExpires)) {
		t.Fatal("revocation did not interrupt the original stream within its unchanged bounds", err)
	}
	select {
	case <-targetClosed:
	case <-original.Done():
		t.Fatal("revocation did not join the original target request")
	}
	after, err := http.NewRequestWithContext(original, http.MethodGet, base+"/new-work", nil)
	if err != nil {
		t.Fatal(err)
	}
	denied, err := client.Do(after)
	if denied != nil && denied.Body != nil {
		_ = denied.Body.Close()
	}
	if !previewConnectorNewWorkDenied(denied, err) || original.Err() != nil {
		t.Fatal("revoked connector did not refuse new work within the original request deadline", err)
	}
	if requests.Load() != 1 {
		t.Fatal("revocation replayed the original request or forwarded new work")
	}
	stopConnector()
	var public, ports int
	if err := f.inspect.QueryRowContext(ctx, `SELECT
		(SELECT count(*) FROM control.service_endpoints WHERE service_id=$1 AND public AND retired_at IS NULL),
		(SELECT count(*) FROM control.service_port_claims WHERE service_id=$1)`, service.Id).Scan(&public, &ports); err != nil || public != 0 || ports != 0 {
		t.Fatal("preview attachment or connector traffic allocated a public endpoint", err)
	}
	if rows, err := reviewer.ListAvailableServices(ctx, controlv1.ServiceAccessPathPublicEndpoint); err != nil || len(rows) != 0 {
		t.Fatal("connector-only preview appeared in public endpoint discovery", err)
	}
	t.Logf("preview_id=%s service_id=%s service_run_id=%s: one original connector HTTP request; independent identity grant only; revocation interrupted it before %s; target and native owner joined; no public endpoint",
		preview.Id, service.Id, run.ServiceRunID, deadline.Format(time.RFC3339Nano))
}
