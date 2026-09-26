package publisher

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/diagnostic"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestCreateOrLoadRouteReusesDurablePublicURL(t *testing.T) {
	want := controlv1.PublicURL{
		Id: "public_url_existing", TeamId: "team_1", DomainId: "domain_1", MembershipId: pointer("membership_1"),
		CanonicalHostname: "demo.example", PublicUrlScope: controlv1.Member, Target: "http://127.0.0.1:3000",
		LifecycleState: controlv1.Enabled,
	}
	control := &publisherControlStub{allowed: []string{"lookup"}, routes: []controlv1.PublicURL{want}}
	got, created, err := createOrLoadPublicURL(t.Context(), Config{
		Control: control, TeamID: "team_1", DomainID: "domain_1", MembershipID: "membership_1",
		Hostname: "demo.example", PublicURLScope: controlv1.Member, Target: "http://127.0.0.1:3000",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Id != want.Id || created || control.created != nil || control.updated != nil {
		t.Fatalf("route = %#v, create request = %#v, update request = %#v", got, control.created, control.updated)
	}
	if control.lookupCalls != 1 || control.lookup != [2]string{"team_1", "demo.example"} {
		t.Fatalf("expected one exact lookup, got %d calls for %v", control.lookupCalls, control.lookup)
	}
}

func TestCreateOrLoadRouteReconcilesTargetAndIPPolicy(t *testing.T) {
	existingPolicy := []string{"192.0.2.0/24"}
	control := &publisherControlStub{allowed: []string{"lookup", "update"}, routes: []controlv1.PublicURL{{
		Id: "public_url_existing", TeamId: "team_1", DomainId: "domain_1", MembershipId: pointer("membership_1"),
		CanonicalHostname: "demo.example", PublicUrlScope: controlv1.Member, Target: "http://127.0.0.1:3000",
		AllowedIpPrefixes: &existingPolicy, LifecycleState: controlv1.Enabled,
	}}}
	wantPolicy := []string{"198.51.100.0/24"}
	got, created, err := createOrLoadPublicURL(t.Context(), Config{
		Control: control, TeamID: "team_1", DomainID: "domain_1", MembershipID: "membership_1",
		Hostname: "demo.example", PublicURLScope: controlv1.Member, Target: "http://127.0.0.1:4000",
		AllowedIPPrefixes: wantPolicy,
	})
	if err != nil {
		t.Fatal(err)
	}
	if created || control.updated == nil || control.updated.Target != "http://127.0.0.1:4000" ||
		!slices.Equal(control.updated.AllowedIpPrefixes, wantPolicy) ||
		got.Target != "http://127.0.0.1:4000" {
		t.Fatalf("route = %#v, update request = %#v", got, control.updated)
	}
}

func TestCreateOrLoadRouteRejectsDifferentIdentityOrLifecycle(t *testing.T) {
	control := &publisherControlStub{allowed: []string{"lookup"}, routes: []controlv1.PublicURL{{
		Id: "public_url_existing", TeamId: "team_1", DomainId: "domain_other",
		CanonicalHostname: "demo.example", PublicUrlScope: controlv1.Shared, Target: "http://127.0.0.1:3000",
	}}}
	_, _, err := createOrLoadPublicURL(t.Context(), Config{
		Control: control, TeamID: "team_1", DomainID: "domain_1", Hostname: "demo.example",
		PublicURLScope: controlv1.Shared, Target: "http://127.0.0.1:3000",
	})
	if err == nil || control.updated != nil {
		t.Fatalf("mismatched route error = %v, update request = %#v", err, control.updated)
	}
	if code, ok := diagnostic.CodeOf(err); !ok || code != diagnostic.PublicURLConflict {
		t.Fatalf("mismatched route diagnostic = %q, %t", code, ok)
	}
}

func TestCreateOrLoadRouteNeverReusesEphemeralPublicURL(t *testing.T) {
	control := &publisherControlStub{allowed: []string{"create"}, routes: []controlv1.PublicURL{{
		Id: "public_url_existing", CanonicalHostname: "demo.example", Ephemeral: true,
	}}}
	route, created, err := createOrLoadPublicURL(t.Context(), Config{
		Control: control, TeamID: "team_1", DomainID: "domain_1", MembershipID: "membership_1",
		Hostname: "demo.example", PublicURLScope: controlv1.Member, Target: "http://127.0.0.1:3000", Ephemeral: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !created || route.Id != "public_url_created" || control.lookupCalls != 0 || control.created == nil {
		t.Fatalf("route = %#v, created = %t, lookup calls = %d", route, created, control.lookupCalls)
	}
}

func TestReconcileRouteRejectsSuspendedPublicURL(t *testing.T) {
	_, err := reconcilePublicURL(t.Context(), Config{
		Control: &publisherControlStub{}, Target: "http://127.0.0.1:3000",
	}, controlv1.PublicURL{Id: "public_url_suspended", LifecycleState: controlv1.Suspended})
	if err == nil || err.Error() != "publisher: public URL public_url_suspended is not enabled" {
		t.Fatalf("reconcile error = %v", err)
	}
	if code, ok := diagnostic.CodeOf(err); !ok || code != diagnostic.PublicURLConflict {
		t.Fatalf("reconcile diagnostic = %q, %t", code, ok)
	}
}

func TestCreateOrLoadRouteFindsSuspendedRouteWithoutRecreating(t *testing.T) {
	control := &publisherControlStub{allowed: []string{"lookup"}, routes: []controlv1.PublicURL{{
		Id: "public_url_suspended", TeamId: "team_1", DomainId: "domain_1", CanonicalHostname: "demo.example",
		PublicUrlScope: controlv1.Shared, LifecycleState: controlv1.Suspended,
	}}}
	_, created, err := createOrLoadPublicURL(t.Context(), Config{
		Control: control, TeamID: "team_1", DomainID: "domain_1", Hostname: "demo.example", PublicURLScope: controlv1.Shared,
	})
	if created || control.created != nil || control.updated != nil || control.lookupCalls != 1 {
		t.Fatalf("suspended route was changed: %+v", control)
	}
	if code, ok := diagnostic.CodeOf(err); !ok || code != diagnostic.PublicURLConflict {
		t.Fatalf("suspended route diagnostic = %q, %t: %v", code, ok, err)
	}
}

func TestCreateOrLoadRouteClassifiesHostnameConflict(t *testing.T) {
	control := &publisherControlStub{allowed: []string{"create"}, createErr: controlclient.ErrNameUnavailable}
	_, _, err := createOrLoadPublicURL(t.Context(), Config{
		Control: control, TeamID: "team_1", DomainID: "domain_1", MembershipID: "membership_1",
		Hostname: "demo.example", PublicURLScope: controlv1.Member, Target: "http://127.0.0.1:3000", Ephemeral: true,
	})
	if code, ok := diagnostic.CodeOf(err); !ok || code != diagnostic.PublicURLConflict ||
		!errors.Is(err, controlclient.ErrNameUnavailable) {
		t.Fatalf("create route error = %v, diagnostic = %q", err, code)
	}
}

func TestReconcileRouteClassifiesUpdateConflict(t *testing.T) {
	control := &publisherControlStub{allowed: []string{"update"}, updateErr: controlclient.ErrStatusConflict}
	_, err := reconcilePublicURL(t.Context(), Config{
		Control: control, Target: "http://127.0.0.1:4000",
	}, controlv1.PublicURL{
		Id: "public_url_existing", LifecycleState: controlv1.Enabled, Target: "http://127.0.0.1:3000",
	})
	if code, ok := diagnostic.CodeOf(err); !ok || code != diagnostic.PublicURLConflict ||
		!errors.Is(err, controlclient.ErrStatusConflict) {
		t.Fatalf("update route error = %v, diagnostic = %q", err, code)
	}
}

func TestCreatePublishRunClassifiesLifecycleConflict(t *testing.T) {
	control := &publisherControlStub{allowed: []string{"create_session"}, publishRunErr: controlclient.ErrStatusConflict}
	_, err := createPublishRun(t.Context(), Config{Control: control}, controlv1.PublicURL{Id: "public_url_1"})
	if code, ok := diagnostic.CodeOf(err); !ok || code != diagnostic.PublicURLConflict ||
		!errors.Is(err, controlclient.ErrStatusConflict) {
		t.Fatalf("create publish run error = %v, diagnostic = %q", err, code)
	}
}

func TestCreateOrLoadRouteCreatesTeamScopedPublicURL(t *testing.T) {
	control := &publisherControlStub{allowed: []string{"lookup", "create"}}
	allowed := []string{"2001:db8::1/64", "192.0.2.9/24"}
	wantAllowed := []string{"192.0.2.0/24", "2001:db8::/64"}
	got, created, err := createOrLoadPublicURL(t.Context(), Config{
		Control: control, TeamID: "team_1", MembershipID: "membership_1", DomainID: "domain_1",
		Hostname: "demo.example", PublicURLScope: controlv1.Member, Target: "http://127.0.0.1:3000",
		AllowedIPPrefixes: allowed,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !created || got.Id == "" || control.created == nil || control.created.TeamId != "team_1" ||
		control.created.MembershipId == nil || *control.created.MembershipId != "membership_1" ||
		control.created.DomainId != "domain_1" || control.created.CanonicalHostname != "demo.example" ||
		control.created.AllowedIpPrefixes == nil || !slices.Equal(*control.created.AllowedIpPrefixes, wantAllowed) ||
		!slices.Equal(allowed, []string{"2001:db8::1/64", "192.0.2.9/24"}) {
		t.Fatalf("route = %#v, create request = %#v", got, control.created)
	}
}

func TestCreateOrLoadRouteLookupErrorsDoNotCreate(t *testing.T) {
	for _, failure := range []error{controlclient.ErrUnavailable, controlclient.ErrUnauthenticated, errors.New("invalid filtered response")} {
		control := &publisherControlStub{allowed: []string{"lookup"}, lookupErr: failure}
		_, created, err := createOrLoadPublicURL(t.Context(), Config{Control: control, TeamID: "team_1", Hostname: "demo.example"})
		if !errors.Is(err, failure) || created || control.lookupCalls != 1 || control.created != nil {
			t.Fatalf("lookup error triggered creation: created=%t err=%v calls=%v", created, err, control.calls)
		}
	}
}

func TestCreateOrLoadRoutePreservesConcurrentCreationConflict(t *testing.T) {
	control := &publisherControlStub{allowed: []string{"lookup", "create"}, createErr: controlclient.ErrNameUnavailable}
	_, created, err := createOrLoadPublicURL(t.Context(), Config{
		Control: control, TeamID: "team_1", DomainID: "domain_1", Hostname: "demo.example", PublicURLScope: controlv1.Shared,
	})
	if created || !errors.Is(err, controlclient.ErrNameUnavailable) || control.lookupCalls != 1 || control.created == nil {
		t.Fatalf("concurrent create result = %t, %v", created, err)
	}
	if code, ok := diagnostic.CodeOf(err); !ok || code != diagnostic.PublicURLConflict {
		t.Fatalf("conflict diagnostic = %q, %t", code, ok)
	}
}

func TestHeartbeatFallbackSkipsPolicyDenialObservation(t *testing.T) {
	control := &publisherControlStub{heartbeat: func(context.Context, string, uint64, credentials.PublishRunToken) (controlv1.PublishRunHeartbeat, error) {
		return controlv1.PublishRunHeartbeat{}, controlclient.ErrUnavailable
	}}
	response, observed, err := heartbeatResponseOnce(
		t.Context(), control, "session_1", 1, "session-token", time.Now().Add(time.Minute),
	)
	if err != nil || observed || response.PolicyDenials != 0 {
		t.Fatalf("fallback = %#v, observed = %t, error = %v", response, observed, err)
	}
}

func TestHeartbeatCallDeadlineUsesConfirmedSessionUntilExpiry(t *testing.T) {
	for _, test := range []struct {
		name    string
		expires time.Duration
		wantErr error
	}{
		{name: "valid session", expires: 2 * heartbeatCallTimeout},
		{name: "expired session", expires: heartbeatCallTimeout / 2, wantErr: controlclient.ErrStatusConflict},
	} {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				control := &publisherControlStub{heartbeat: func(ctx context.Context, _ string, _ uint64, _ credentials.PublishRunToken) (controlv1.PublishRunHeartbeat, error) {
					<-ctx.Done()
					return controlv1.PublishRunHeartbeat{}, ctx.Err()
				}}
				expiresAt := time.Now().Add(test.expires)
				response, observed, err := heartbeatResponseOnce(t.Context(), control, "session_1", 1, "session-token", expiresAt)
				if !errors.Is(err, test.wantErr) || observed || !response.PublishRun.ExpiresAt.Equal(expiresAt) {
					t.Fatalf("fallback = %#v, observed = %t, error = %v; want %v", response, observed, err, test.wantErr)
				}
			})
		})
	}
}

func TestHeartbeatDoesNotHideUnrelatedDeadline(t *testing.T) {
	control := &publisherControlStub{heartbeat: func(context.Context, string, uint64, credentials.PublishRunToken) (controlv1.PublishRunHeartbeat, error) {
		return controlv1.PublishRunHeartbeat{}, context.DeadlineExceeded
	}}
	_, _, err := heartbeatResponseOnce(t.Context(), control, "session_1", 1, "session-token", time.Now().Add(time.Minute))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("unrelated heartbeat deadline = %v, want deadline exceeded", err)
	}
}

func TestExpiredHeartbeatLeavesStaleSessionConflictUnclassified(t *testing.T) {
	control := &publisherControlStub{heartbeat: func(context.Context, string, uint64, credentials.PublishRunToken) (controlv1.PublishRunHeartbeat, error) {
		return controlv1.PublishRunHeartbeat{}, controlclient.ErrUnavailable
	}}
	_, _, err := heartbeatResponseOnce(
		t.Context(), control, "session_1", 1, "session-token", time.Now().Add(-time.Second),
	)
	if !errors.Is(err, controlclient.ErrStatusConflict) {
		t.Fatalf("heartbeat error = %v", err)
	}
	if code, ok := diagnostic.CodeOf(err); ok {
		t.Fatalf("stale publish-run conflict was classified as %q", code)
	}
}

func TestHeartbeatIgnoresUpdateFailureAfterCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		control := &publisherControlStub{heartbeat: func(context.Context, string, uint64, credentials.PublishRunToken) (controlv1.PublishRunHeartbeat, error) {
			return controlv1.PublishRunHeartbeat{
				PublishRun:           controlv1.PublishRun{ExpiresAt: time.Now().Add(time.Minute)},
				PublisherConnections: []controlv1.ConnectionAssignment{{PublisherConnectionId: "publisher_connection_1"}},
			}, nil
		}}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		updateStarted := make(chan struct{})
		releaseUpdate := make(chan struct{})
		done := make(chan error, 1)
		joined := make(chan struct{})
		var once sync.Once
		release := func() { once.Do(func() { close(releaseUpdate) }) }
		go func() {
			defer close(joined)
			done <- heartbeatSessionAfterUpdate(
				ctx, control, "publish_run_1", 1, "publish-run-token", time.Now().Add(time.Minute),
				func([]controlv1.ConnectionAssignment) error {
					close(updateStarted)
					<-releaseUpdate
					return errors.New("connection manager is draining")
				}, nil, 0,
			)
		}()
		t.Cleanup(func() { cancel(); release(); awaitPublisherTest(t, joined) })
		select {
		case <-updateStarted:
		case <-time.After(heartbeatInterval + time.Second):
			t.Fatal("heartbeat did not begin the connection update")
		}
		cancel()
		release()
		if err := <-done; err != nil {
			t.Fatalf("heartbeat returned a shutdown race: %v", err)
		}
	})
}

func TestRunRequiresAuthoritativeSessionCertificatePlan(t *testing.T) {
	control, _, _ := newCertificateTransactionTest(t)
	config := startCertificateTLSYamuxHarness(t, control)
	control.setup.CertificatePlan = controlv1.CertificatePlan{}
	err := Run(t.Context(), config)
	if err == nil || err.Error() != "publisher: server returned an invalid certificate plan" {
		t.Fatalf("Run error = %v", err)
	}
}

func TestRunRejectsNegativeOptionalDurations(t *testing.T) {
	t.Parallel()
	for _, config := range []Config{
		{Control: &publisherControlStub{}, DrainTime: -time.Second},
		{Control: &publisherControlStub{}, FallbackDelay: -time.Second},
	} {
		if err := Run(t.Context(), config); err == nil || err.Error() != "publisher: drain time and fallback delay cannot be negative" {
			t.Fatalf("Run error = %v", err)
		}
	}
}

func TestRunRejectsNegativeProvisioningStalledDelay(t *testing.T) {
	err := Run(t.Context(), Config{
		Control: &publisherControlStub{}, ProvisioningStalledDelay: -time.Second,
	})
	if err == nil || err.Error() != "publisher: provisioning stalled delay cannot be negative" {
		t.Fatalf("Run error = %v", err)
	}
}

func TestObserveProvisioningStallFiresOnceAndCancels(t *testing.T) {
	setup := controlv1.PublishRunSetup{
		PublicUrl:  controlv1.PublicURL{Id: "public_url_1", CanonicalHostname: "demo.example"},
		PublishRun: controlv1.PublishRun{PublishRunNumber: 4},
	}
	var events []Event
	config := Config{ProvisioningStalledDelay: 10 * time.Millisecond, Observe: func(event Event) error {
		events = append(events, event)
		return nil
	}}
	if err := observeProvisioningStall(t.Context(), config, setup); err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Type != EventProvisioningStalled || events[0].PublishRunNumber != 4 ||
		events[0].Hostname != "demo.example" {
		t.Fatalf("provisioning events = %#v", events)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := observeProvisioningStall(ctx, config, setup); err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("canceled warning emitted events = %#v", events)
	}
}

func TestObserveHeartbeatPolicyDenialsReportsCumulativeIncreases(t *testing.T) {
	var events []Event
	config := Config{Observe: func(event Event) error {
		events = append(events, event)
		return nil
	}}
	setup := controlv1.PublishRunSetup{
		PublicUrl:  controlv1.PublicURL{Id: "public_url_1", CanonicalHostname: "demo.example"},
		PublishRun: controlv1.PublishRun{PublishRunNumber: 3},
	}
	var previous uint64
	for _, count := range []int64{0, 2, 2, 5} {
		if err := observeHeartbeatPolicyDenials(config, setup, count, &previous); err != nil {
			t.Fatal(err)
		}
	}
	if len(events) != 2 || events[0].PolicyDenials != 2 || events[1].PolicyDenials != 5 ||
		events[1].Type != EventIPPolicyDenials || events[1].PublishRunNumber != 3 {
		t.Fatalf("policy denial events = %#v", events)
	}
	decreased := int64(4)
	if err := observeHeartbeatPolicyDenials(config, setup, decreased, &previous); err == nil {
		t.Fatal("decreased policy denial count was accepted")
	}
}

type publisherControlStub struct {
	allowed       []string
	calls         []string
	routes        []controlv1.PublicURL
	created       *controlv1.CreatePublicURLRequest
	updated       *controlv1.UpdatePublicURLRequest
	deleted       *string
	lookupCalls   int
	lookup        [2]string
	lookupErr     error
	heartbeat     func(context.Context, string, uint64, credentials.PublishRunToken) (controlv1.PublishRunHeartbeat, error)
	createErr     error
	updateErr     error
	publishRunErr error
}

func (s *publisherControlStub) record(operation string) {
	if !slices.Contains(s.allowed, operation) {
		panic("unexpected publisher control operation: " + operation)
	}
	s.calls = append(s.calls, operation)
}

func (s *publisherControlStub) CreatePublicURL(_ context.Context, body controlv1.CreatePublicURLRequest, _ string) (controlv1.PublicURL, error) {
	s.record("create")
	s.created = &body
	if s.createErr != nil {
		return controlv1.PublicURL{}, s.createErr
	}
	route := controlv1.PublicURL{
		Id: "public_url_created", TeamId: body.TeamId, DomainId: body.DomainId, MembershipId: body.MembershipId,
		CanonicalHostname: body.CanonicalHostname, PublicUrlScope: body.PublicUrlScope, Target: body.Target, NextPublishRunNumber: 1,
		Ephemeral: body.Ephemeral != nil && *body.Ephemeral,
	}
	s.routes = append(s.routes, route)
	return route, nil
}

func (s *publisherControlStub) GetPublicURLByHostname(_ context.Context, teamID, hostname string) (controlv1.PublicURL, error) {
	s.record("lookup")
	s.lookupCalls++
	s.lookup = [2]string{teamID, hostname}
	if s.lookupErr != nil {
		return controlv1.PublicURL{}, s.lookupErr
	}
	for _, route := range s.routes {
		if route.CanonicalHostname == hostname {
			return route, nil
		}
	}
	return controlv1.PublicURL{}, controlclient.ErrNotFound
}

func (s *publisherControlStub) UpdatePublicURL(_ context.Context, id string, body controlv1.UpdatePublicURLRequest) (controlv1.PublicURL, error) {
	s.record("update")
	s.updated = &body
	if s.updateErr != nil {
		return controlv1.PublicURL{}, s.updateErr
	}
	for index := range s.routes {
		if s.routes[index].Id == id {
			s.routes[index].Target = body.Target
			s.routes[index].AllowedIpPrefixes = &body.AllowedIpPrefixes
			return s.routes[index], nil
		}
	}
	return controlv1.PublicURL{}, errors.New("update of unknown fixture route")
}

func (s *publisherControlStub) DeletePublicURL(_ context.Context, publicURLID string) error {
	s.record("delete")
	s.deleted = &publicURLID
	s.routes = slices.DeleteFunc(s.routes, func(existing controlv1.PublicURL) bool { return existing.Id == publicURLID })
	return nil
}

func (s *publisherControlStub) CreatePublishRun(context.Context, string, string) (controlv1.PublishRunSetup, error) {
	s.record("create_session")
	if s.publishRunErr != nil {
		return controlv1.PublishRunSetup{}, s.publishRunErr
	}
	return controlv1.PublishRunSetup{}, errors.New("not implemented")
}

func (*publisherControlStub) ClosePublishRun(context.Context, string, credentials.PublishRunToken) error {
	panic("unexpected ClosePublishRun")
}

func (*publisherControlStub) MarkPublishRunReady(context.Context, string, uint64, credentials.PublishRunToken) error {
	panic("unexpected MarkPublishRunReady")
}

func (s *publisherControlStub) HeartbeatPublishRun(ctx context.Context, publicURLID string, version uint64, token credentials.PublishRunToken) (controlv1.PublishRunHeartbeat, error) {
	if s.heartbeat != nil {
		return s.heartbeat(ctx, publicURLID, version, token)
	}
	return controlv1.PublishRunHeartbeat{}, errors.New("not implemented")
}

func (*publisherControlStub) CreateCertificateIssuance(context.Context, string, uint64, credentials.PublishRunToken, []byte, string) (controlv1.CertificateIssuance, error) {
	return controlv1.CertificateIssuance{}, errors.New("not implemented")
}

func (*publisherControlStub) GetCertificateIssuance(context.Context, string, credentials.PublishRunToken) (controlv1.CertificateIssuance, error) {
	return controlv1.CertificateIssuance{}, errors.New("not implemented")
}

func (*publisherControlStub) MarkCertificateChallengeReady(context.Context, string, credentials.PublishRunToken) (controlv1.CertificateIssuance, error) {
	return controlv1.CertificateIssuance{}, errors.New("not implemented")
}

func (*publisherControlStub) MarkCertificateChallengeRemoved(context.Context, string, credentials.PublishRunToken) error {
	panic("unexpected MarkCertificateChallengeRemoved")
}

func (*publisherControlStub) MarkPublishRunCertificateInstalled(context.Context, string, uint64, string, time.Time, credentials.PublishRunToken) error {
	panic("unexpected MarkPublishRunCertificateInstalled")
}

func pointer[T any](value T) *T { return &value }
