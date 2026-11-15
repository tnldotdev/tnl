package publishingtest_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/publisher/identity/publishingtest"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/testutil"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func fixtureState(t *testing.T, f *publishingtest.Fixture) *clientstate.Store {
	t.Helper()
	database, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(t.TempDir(), "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	profile, err := database.Server(t.Context(), f.URL)
	if err != nil {
		t.Fatal(err)
	}
	return profile
}

func TestSignedServiceFixtureRestrictedVisitorsAndCurrentPermission(t *testing.T) {
	exerciseServiceFixture(t, false, false)
}

func TestSignedServiceFixtureAnonymousPolicyIsExplicit(t *testing.T) {
	exerciseServiceFixture(t, true, false)
}

func TestSignedServiceFixtureIPPolicyUsesForwardedSource(t *testing.T) {
	exerciseServiceFixture(t, true, true)
}

func exerciseServiceFixture(t *testing.T, anonymous, denySource bool) {
	t.Helper()
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
	prepared := make(chan testutil.PublishingRun, 1)
	var closes atomic.Int32
	f := publishingtest.New(t, testutil.PublishingHooks{
		Ready: func(_ context.Context, run testutil.PublishingRun) error { prepared <- run; return nil },
		Close: func(testutil.PublishingRun) error { closes.Add(1); return nil },
	})
	owner, err := f.Owner()
	if err != nil {
		t.Fatal(err)
	}
	authority, err := clientauthority.New(f.URL, f.HTTP, "")
	if err != nil {
		t.Fatal(err)
	}
	configuration := controlv1.ProjectServiceConfiguration{Target: "app", Public: new(true)}
	if anonymous {
		configuration.Http = &controlv1.ProjectServiceHTTP{Access: &controlv1.ProjectHTTPAccess{Mode: new(controlv1.Anonymous)}}
	}
	if denySource {
		configuration.Http.Access.Ip = &[]string{"192.0.2.0/24"}
	}
	service, err := f.SavedService(t.Context(), "app", configuration)
	if err != nil {
		t.Fatal(err)
	}
	profile := fixtureState(t, f)
	native, identity, err := publisheridentity.EnsureServiceOwner(t.Context(), profile, owner, authority, service)
	if err != nil {
		t.Fatal(err)
	}
	reused, again, err := publisheridentity.EnsureServiceOwner(t.Context(), profile, owner, authority, service)
	if err != nil || again.ClientId != identity.ClientId || again.GrantId != identity.GrantId || f.Enrollments.Load() != 1 {
		t.Fatal("service owner retry replaced its exact grant", err)
	}
	saved, found, err := profile.PublisherIdentity(t.Context(), identity.ClientId)
	if err != nil || !found {
		t.Fatal(err)
	}
	_, wrong, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authority.ExchangePublisherAssertion(t.Context(), identity.ClientId, identity.GrantId, identity.KeyId, wrong); err == nil {
		t.Fatal("another signing key obtained publisher access")
	}
	if len(saved.SigningKey) != ed25519.PrivateKeySize || native == nil {
		t.Fatal("original owner key was not retained")
	}
	ctx, cancel := context.WithCancel(t.Context())
	ready, done := make(chan struct{}, 1), make(chan error, 1)
	var requests atomic.Int32
	go func() {
		done <- publisherservice.Publish(ctx, publisherservice.RunConfig{Control: reused, State: profile, Access: reused.Access,
			PublisherIdentityID: identity.ClientId, PublisherGrantID: identity.GrantId, PublisherKeyID: identity.KeyId,
			ServiceID: service.Id, Metadata: publisheridentity.ServiceMetadata(service), HeartbeatInterval: 10 * time.Millisecond,
			Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				_, _ = w.Write([]byte("service fixture"))
			}),
			Ready: func() error { ready <- struct{}{}; return nil }})
	}()
	joined := false
	defer func() {
		cancel()
		if !joined {
			select {
			case err := <-done:
				if err != nil {
					t.Error(err)
				}
			case <-time.After(3 * time.Second):
				t.Error("fixture publication did not join")
			}
		}
	}()
	select {
	case <-ready:
	case err := <-done:
		joined = true
		t.Fatal("fixture publication stopped before readiness", err)
	case <-time.After(10 * time.Second):
		t.Fatal("fixture publication was not ready")
	}
	run := <-prepared
	if run.Service.Id != service.Id || run.Setup.ServiceId != service.Id || run.Setup.ServiceRunId != run.Preparation.ServiceRunId ||
		run.Setup.RunNumber != 1 || run.Preparation.PublisherGrantId != identity.GrantId || run.Preparation.PublisherKeyId != identity.KeyId {
		t.Fatal("fixture changed its exact service/run/grant/key binding")
	}
	address := "https://" + service.Endpoint.Hostname
	status, _, err := f.Visit(t.Context(), address)
	if err != nil && !denySource {
		t.Fatal(err)
	}
	if denySource {
		if !errors.Is(err, io.EOF) || status != 0 || requests.Load() != 0 {
			t.Fatal("anonymous mode bypassed the saved IP policy", status)
		}
		permission, err := f.OwnerVisitorToken(t.Context(), service.Id)
		if err != nil {
			t.Fatal(err)
		}
		status, _, _, err = f.VisitWithHeaders(t.Context(), address, http.Header{
			httpaccess.VisitorTokenHeader: {permission.VisitorToken}, "X-Forwarded-For": {"192.0.2.10"}})
		if !errors.Is(err, io.EOF) || status != 0 || requests.Load() != 0 {
			t.Fatal("HTTP headers replaced trusted forwarding metadata", status, err)
		}
	} else if anonymous {
		if status != http.StatusOK || requests.Load() != 1 {
			t.Fatal("explicit anonymous HTTP policy was ignored", status)
		}
	} else {
		if status >= 200 && status < 300 || requests.Load() != 0 {
			t.Fatal("restricted service admitted an anonymous visitor", status)
		}
		status, _, _, err = f.VisitWithHeaders(t.Context(), address, http.Header{"Authorization": {"Bearer " + f.OwnerToken}})
		if err != nil || status >= 200 && status < 300 || requests.Load() != 0 {
			t.Fatal("control session substituted for visitor permission", status, err)
		}
		permission, err := f.OwnerVisitorToken(t.Context(), service.Id)
		if err != nil {
			t.Fatal(err)
		}
		headers := http.Header{httpaccess.VisitorTokenHeader: {permission.VisitorToken}}
		status, _, body, err := f.VisitWithHeaders(t.Context(), address, headers)
		if err != nil || status != http.StatusOK || string(body) != "service fixture" {
			t.Fatal("owner visitor permission did not carry real TLS/yamux bytes", status, err)
		}
		grant, err := owner.CreateServiceHTTPGrant(t.Context(), service.Id, controlv1.CreateVisitorCredentialRequest{Kind: controlv1.CreateVisitorCredentialRequestKind("token"), ExpiresAt: time.Now().Add(time.Minute)})
		if err != nil {
			t.Fatal(err)
		}
		status, _, _, err = f.VisitWithHeaders(t.Context(), address, http.Header{httpaccess.VisitorTokenHeader: {grant.Permission.VisitorToken}})
		if err != nil || status != http.StatusOK {
			t.Fatal("explicit token visitor permission was not admitted", status, err)
		}
		ticket := f.BrowserHandoff(service.Id)
		status, responseHeaders, _, err := f.VisitWithHeaders(t.Context(), address+"/__tnl/team/handoff/"+ticket, nil)
		if err != nil || status != http.StatusSeeOther {
			t.Fatal("service browser handoff was not redeemed", status, err)
		}
		var cookies []string
		for _, cookie := range (&http.Response{Header: responseHeaders}).Cookies() {
			if cookie.Value != "" {
				cookies = append(cookies, cookie.Name+"="+cookie.Value)
			}
		}
		status, _, _, err = f.VisitWithHeaders(t.Context(), address, http.Header{"Cookie": {strings.Join(cookies, "; ")}})
		if err != nil || status != http.StatusOK {
			t.Fatal("browser visitor permission was not admitted", status, err)
		}
		before := requests.Load()
		if err := owner.DeleteService(t.Context(), service.Id); err != nil {
			t.Fatal(err)
		}
		if _, err := f.OwnerVisitorToken(t.Context(), service.Id); err == nil {
			t.Fatal("disabled service issued fresh visitor permission")
		}
		// policy refresh is asynchronous. observe refusal of a reserved path,
		// which cannot contact the app or spend request budget, before checking
		// an old signed credential against the publisher's disabled policy.
		policy, stopPolicy := context.WithTimeout(t.Context(), 3*time.Second)
		defer stopPolicy()
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			probeStatus, _, probeBody, probeErr := f.VisitWithHeaders(policy, address+"/__tnl/missing", nil)
			if closedBeforeHTTP(probeStatus, probeBody, probeErr) {
				break
			}
			if probeErr != nil || probeStatus != http.StatusNotFound {
				t.Fatal("disablement failed outside the publisher's policy boundary", probeStatus, probeErr)
			}
			select {
			case <-policy.Done():
				t.Fatal("publisher did not install service disablement", policy.Err())
			case <-ticker.C:
			}
		}
		status, _, body, err = f.VisitWithHeaders(t.Context(), address, headers)
		if !closedBeforeHTTP(status, body, err) || requests.Load() != before {
			t.Fatal("signed permission bypassed current service disablement", status, err)
		}
	}
	cancel()
	select {
	case err := <-done:
		joined = true
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("service fixture did not join cleanup")
	}
	if closes.Load() != 1 || f.Runs.Load() != 1 || f.Allocations.Load() != 0 || f.Deletions.Load() != 0 {
		t.Fatal("saved service publication changed its lifecycle", closes.Load(), f.Runs.Load())
	}
}

// a policy refusal can close the yamux stream without a TLS close_notify.
// neither EOF form may carry an HTTP response or application body.
func closedBeforeHTTP(status int, body []byte, err error) bool {
	return status == 0 && len(body) == 0 && (failure.Only(err, io.EOF) || failure.Only(err, io.ErrUnexpectedEOF))
}

func TestPolicyRefusalKeepsIndependentTransportFailures(t *testing.T) {
	for _, closed := range []error{io.EOF, io.ErrUnexpectedEOF} {
		if !closedBeforeHTTP(0, nil, closed) ||
			closedBeforeHTTP(http.StatusOK, nil, closed) ||
			closedBeforeHTTP(0, []byte("partial response"), closed) ||
			closedBeforeHTTP(0, nil, errors.Join(closed, errors.New("independent cleanup failed"))) {
			t.Fatal("policy refusal hid a response or an independent transport failure")
		}
	}
	if closedBeforeHTTP(0, nil, nil) || closedBeforeHTTP(0, nil, context.Canceled) {
		t.Fatal("policy refusal treated cancellation or success as a closed transport")
	}
}

func TestSignedServiceFixtureAllocationRetryKeepsOriginalNamespaceGrant(t *testing.T) {
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
	f := publishingtest.New(t, testutil.PublishingHooks{})
	owner, err := f.Owner()
	if err != nil {
		t.Fatal(err)
	}
	authority, err := clientauthority.New(f.URL, f.HTTP, "")
	if err != nil {
		t.Fatal(err)
	}
	secret, err := f.NamespaceEnrollment(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	profile := fixtureState(t, f)
	native, identity, err := publisheridentity.EnrollNative(t.Context(), profile, publisheridentity.NativeControl{Services: owner, Allocations: owner}, authority, secret)
	if err != nil {
		t.Fatal(err)
	}
	invocation, err := opaqueid.New(opaqueid.InvocationPrefix)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Minute)
	request := controlv1.AllocateServiceRequest{InvocationId: invocation, ExpiresAt: &deadline, Configuration: controlv1.ProjectServiceConfiguration{Target: "app", Public: new(true),
		Traffic: &controlv1.TrafficSelection{Connections: new(7), TotalDownloadBytes: new(int64(4096))}}}
	service, err := native.AllocateService(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	again, err := native.AllocateService(t.Context(), request)
	if err != nil || service.Id != again.Id || f.Allocations.Load() != 1 || identity.Kind != "namespace" || identity.ServiceId != nil {
		t.Fatal("retry changed allocation or fabricated a service grant", err)
	}
	if service.ExpiresAt == nil || again.ExpiresAt == nil || !service.ExpiresAt.Equal(deadline) || !again.ExpiresAt.Equal(deadline) {
		t.Fatal("allocation retry lost or extended its fixed expiration")
	}
	*again.ExpiresAt = deadline.Add(time.Hour)
	scoped, err := native.SavedService(t.Context())
	if err != nil || scoped.ExpiresAt == nil || !scoped.ExpiresAt.Equal(deadline) {
		t.Fatal("scoped service read lost the captured allocation deadline or aliased a caller snapshot", err)
	}
	changedDeadline := request
	changedDeadline.ExpiresAt = new(deadline.Add(time.Hour))
	if _, err := native.AllocateService(t.Context(), changedDeadline); err == nil || f.Allocations.Load() != 1 {
		t.Fatal("allocation retry extended its original fixed deadline")
	}
	changed := request
	changed.Configuration.Target = "http://127.0.0.1:3001"
	if _, err := native.AllocateService(t.Context(), changed); err == nil || f.Allocations.Load() != 1 {
		t.Fatal("changed allocation intent replaced its original service", err)
	}
	key, err := opaqueid.New(opaqueid.IdempotencyPrefix)
	if err != nil {
		t.Fatal(err)
	}
	access, err := native.Access(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	declared := publisheridentity.ServiceDeclaration(service)
	preparation, err := native.PrepareServiceRun(t.Context(), service.Id, key, access, declared)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := native.PrepareServiceRun(t.Context(), service.Id, key, access, declared)
	if err != nil || retry.ServiceRunId != preparation.ServiceRunId || retry.PublisherGrantId != identity.GrantId || retry.PublisherKeyId != identity.KeyId ||
		!retry.ExpiresAt.Equal(deadline) || f.Runs.Load() != 1 {
		t.Fatal("run retry changed exact identities", err)
	}
	if preparation.Traffic.Connections != 7 || preparation.Traffic.TotalDownloadBytes == nil || *preparation.Traffic.TotalDownloadBytes != 4096 {
		t.Fatal("service allocation lost its independent traffic declaration")
	}
	if !preparation.ExpiresAt.Equal(deadline) {
		t.Fatal("run preparation extended the allocation deadline")
	}
	setup, err := native.StartServiceRun(t.Context(), service.Id, preparation.ServiceRunId, access, preparation.RunNumber)
	if err != nil {
		t.Fatal(err)
	}
	started, err := native.StartServiceRun(t.Context(), service.Id, preparation.ServiceRunId, access, preparation.RunNumber)
	if err != nil || setup.RunToken != started.RunToken {
		t.Fatal("uncertain start replaced the run token", err)
	}
	runToken := credentials.ServiceRunToken(setup.RunToken)
	for range 2 {
		state, err := native.HeartbeatServiceRun(t.Context(), service.Id, setup.ServiceRunId, runToken, controlv1.ServiceRunHeartbeat{Healthy: true, StreamCapacity: 7})
		if err != nil || state.ServiceId != service.Id || state.ServiceRunId != setup.ServiceRunId || state.RunNumber != setup.RunNumber ||
			!state.PublisherExpiresAt.Equal(deadline) {
			t.Fatal("service renewal lost or extended the allocation's fixed deadline", err)
		}
		scoped, err := native.SavedService(t.Context())
		if err != nil || scoped.ExpiresAt == nil || !scoped.ExpiresAt.Equal(deadline) {
			t.Fatal("service renewal changed the deadline returned by a scoped service read", err)
		}
	}
	policyRequest := controlv1.PublisherVisitorPolicyRequest{
		Resource: controlv1.VisitorResourceScope{Kind: controlv1.VisitorResourceScopeKindService, Id: service.Id},
		RunId:    setup.ServiceRunId, RunNumber: setup.RunNumber,
	}
	if _, err := owner.ReadPublisherVisitorPolicy(t.Context(), policyRequest, "wrong-token"); err == nil {
		t.Fatal("run token was not checked")
	}
	assertStarting := func() {
		t.Helper()
		state, err := owner.HeartbeatServiceRun(t.Context(), service.Id, setup.ServiceRunId, runToken,
			controlv1.ServiceRunHeartbeat{Healthy: true, StreamCapacity: 7})
		if err != nil || state.State != controlv1.ServiceRunStateStateStarting {
			t.Fatal("incomplete run became routable", state.State, err)
		}
	}
	assertStarting()
	policy, err := owner.ReadPublisherVisitorPolicy(t.Context(), policyRequest, runToken.String())
	if err != nil || policy.Policy.Resource != policyRequest.Resource || policy.Policy.ConnectionDeadline == nil ||
		!policy.Policy.ConnectionDeadline.Equal(deadline) || policy.Policy.ValidUntil.After(deadline) {
		t.Fatal("preparation policy lost its run or fixed allocation authority", err)
	}
	_, certificateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{"unapproved.example"}}, certificateKey)
	if err != nil {
		t.Fatal(err)
	}
	issuanceKey, err := opaqueid.New(opaqueid.IdempotencyPrefix)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := owner.CreateServiceCertificateIssuance(t.Context(), service.Id, setup.ServiceRunId, setup.RunNumber, runToken, csr, issuanceKey); err == nil {
		t.Fatal("certificate issuance escaped the exact approved hostname")
	}
	csr, err = x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{service.Endpoint.Hostname}}, certificateKey)
	if err != nil {
		t.Fatal(err)
	}
	issuance, err := owner.CreateServiceCertificateIssuance(t.Context(), service.Id, setup.ServiceRunId, setup.RunNumber, runToken, csr, issuanceKey)
	if err != nil {
		t.Fatal(err)
	}
	reissued, err := owner.CreateServiceCertificateIssuance(t.Context(), service.Id, setup.ServiceRunId, setup.RunNumber, runToken, csr, issuanceKey)
	if err != nil || reissued.Id != issuance.Id || issuance.NotAfter == nil || issuance.CertificatePem == nil || *reissued.CertificatePem != *issuance.CertificatePem {
		t.Fatal("certificate retry replaced the original issuance", err)
	}
	if err := owner.MarkServiceCertificateInstalled(t.Context(), service.Id, setup.ServiceRunId, setup.RunNumber, issuance.Id, time.Now(), runToken); err == nil {
		t.Fatal("certificate installation ignored its approved expiration")
	}
	if err := owner.MarkServiceCertificateInstalled(t.Context(), service.Id, setup.ServiceRunId, setup.RunNumber, issuance.Id, *issuance.NotAfter, runToken); err != nil {
		t.Fatal(err)
	}
	assertStarting()
	if err := native.CloseServiceRun(t.Context(), service.Id, setup.ServiceRunId, credentials.ServiceRunToken(setup.RunToken)); err != nil {
		t.Fatal(err)
	}
	if err := native.CloseServiceRun(t.Context(), service.Id, setup.ServiceRunId, runToken); err != nil {
		t.Fatal("uncertain cleanup was not retryable", err)
	}
	if err := native.DeleteAllocatedService(t.Context(), service.Id); err != nil {
		t.Fatal(err)
	}
	deleted := f.DeletedIDs()
	if len(deleted) != 1 || deleted[0] != service.Id {
		t.Fatal("cleanup deleted a different allocation", deleted)
	}
	data, err := json.Marshal(identity)
	if err != nil || strings.Contains(string(data), `"kind":"service"`) {
		t.Fatal("namespace signing identity was replaced")
	}
}
