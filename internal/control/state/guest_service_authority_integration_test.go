package state

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/authorization"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestIntegrationGuestServicePublisherRequestsRequireCurrentSource(t *testing.T) {
	f, guest := guestAuthorityFixture(t, false)
	before := f.stored(t)
	scope := visitorscope.Scope{Kind: visitorscope.Service, ID: f.service.ID}
	for _, source := range []netip.Addr{{}, netip.IPv4Unspecified(), netip.IPv6Unspecified(),
		netip.MustParseAddr("fe80::1%en0"), netip.MustParseAddr("192.0.2.8")} {
		t.Run(source.String(), func(t *testing.T) {
			ctx := t.Context()
			if source.IsValid() {
				ctx = WithPublisherRequestSource(ctx, source)
			}
			if _, err := f.database.PrepareServiceRun(ctx, f.service.ID, f.publisher, "foreign", f.now,
				ServiceRunRequest{Metadata: f.service.ServiceMetadata}); err == nil {
				t.Fatal("publisher preparation accepted missing or foreign source")
			}
			if _, err := f.database.StartServiceRun(ctx, f.service.ID, f.prep.RunID, f.prep.RunNumber, f.publisher, f.now); err == nil {
				t.Fatal("publisher start recovery accepted missing or foreign source")
			}
			if _, err := f.database.HeartbeatServiceRun(ctx, f.service.ID, f.run.RunID, f.run.Token, f.now,
				ServiceRunHealth{Healthy: true, StreamCapacity: 32}); err == nil {
				t.Fatal("run-token heartbeat accepted missing or foreign source")
			}
			if _, err := f.database.ReadPublisherVisitorPolicy(ctx, scope, f.run.RunID, f.run.RunNumber, f.run.Token, 0, f.now); err == nil {
				t.Fatal("run-token policy accepted missing or foreign source")
			}
			if err := f.database.MarkServiceCertificateInstalled(ctx, f.service.ID, f.run.RunID, f.run.Token,
				"unissued", f.run.RunNumber, f.now.Add(time.Hour), f.now); err == nil {
				t.Fatal("certificate acknowledgement accepted missing or foreign source")
			}
			if err := f.database.CloseServiceRun(ctx, f.service.ID, f.run.RunID, f.run.Token, f.now); err == nil {
				t.Fatal("run-token close accepted missing or foreign source")
			}
			slot := f.run.Connections[0]
			// the control request context must not replace the publisher peer
			// independently observed by the authenticated relay.
			if _, err := f.database.ClaimServicePublisherConnection(f.ctx, slot.PublisherConnectionID, f.service.ID,
				f.run.RunID, f.run.RunNumber, slot.Revision, slot.Credential, source,
				f.leases[slot.RelayServiceID].RelayLeaseIdentity, f.now); err == nil {
				t.Fatal("relay claim accepted missing or foreign publisher source")
			}
		})
	}
	if after := f.stored(t); !reflect.DeepEqual(before, after) {
		t.Fatal("rejected source changed trial authority")
	}
	foreign := guestCredentialForTest(guest)
	foreign.SourceIP = netip.MustParseAddr("192.0.2.8")
	request := f.allocation
	request.Credential = foreign
	if _, err := f.database.AllocateGuestDemoService(t.Context(), request); !errors.Is(err, authorization.ErrGuestIPChanged) {
		t.Fatalf("foreign source recovered allocation: %v", err)
	}
	if err := f.database.DeleteService(WithGuestServiceCredential(t.Context(), foreign), f.service.ID, "", f.now); !errors.Is(err, authorization.ErrGuestIPChanged) {
		t.Fatalf("foreign source deleted allocation: %v", err)
	}
	if err := f.database.DeleteService(t.Context(), f.service.ID, guest.ID, f.now); !errors.Is(err, ErrServiceAccess) {
		t.Fatalf("guest ID was treated as a person: %v", err)
	}
	f.ready(t, f.now)
	// trial ownership and publisher source are not visitor permission.
	if _, err := f.database.IssueVisitorToken(t.Context(), testVisitorIssuer, scope, BrowserTokenSource{}, f.now); !errors.Is(err, ErrVisitorPermission) {
		t.Fatalf("publication granted an unshared visitor access: %v", err)
	}
}

func TestIntegrationGuestCredentialDistinguishesUnknownBearerAndChangedSource(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "guest_credential_source")
	guest := newGuestTrialForTest(t, d, now)
	now = guestOperationTime(guest)
	request := AllocateGuestDemoServiceRequest{
		Credential: guestCredentialForTest(guest), IdempotencyKey: "original", Target: guestLoopbackTarget(t), Now: now,
	}
	service, err := d.AllocateGuestDemoService(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	unknown, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	lookup, _, _ := strings.Cut(guest.Token.String(), ".")
	_, wrongSecret, _ := strings.Cut(unknown.String(), ".")
	wrongHash := credentials.AccessToken(lookup + "." + wrongSecret)
	id, hash, err := credentials.ParseAccessToken(wrongHash)
	if err != nil || id != guest.CredentialID || hash == guest.Hash {
		t.Fatal("wrong-secret fixture did not retain the real credential lookup")
	}
	before, err := controlstatedb.New(d.pool).GetGuestTrialByID(t.Context(), guest.ID)
	if err != nil {
		t.Fatal(err)
	}
	changedSource := netip.MustParseAddr("192.0.2.8")
	for _, test := range []struct {
		name   string
		token  credentials.AccessToken
		source netip.Addr
		at     time.Time
		want   error
	}{
		{"malformed-bearer", "malformed", guest.SourceIP, now, ErrGuestUnknown},
		{"unknown-bearer", unknown, guest.SourceIP, now, ErrGuestUnknown},
		{"wrong-secret", wrongHash, guest.SourceIP, now, ErrGuestUnknown},
		{"wrong-secret-changed-source", wrongHash, changedSource, now, ErrGuestUnknown},
		{"authenticated-changed-source", guest.Token, changedSource, now, authorization.ErrGuestIPChanged},
		{"missing-source", guest.Token, netip.Addr{}, now, ErrGuestUnknown},
		{"unspecified-source", guest.Token, netip.IPv4Unspecified(), now, ErrGuestUnknown},
		{"mapped-unspecified-source", guest.Token, netip.MustParseAddr("::ffff:0.0.0.0"), now, ErrGuestUnknown},
		{"zoned-source", guest.Token, netip.MustParseAddr("fe80::1%en0"), now, ErrGuestUnknown},
		{"expired-before-source-check", guest.Token, changedSource, guest.ExpiresAt, ErrGuestTrialSpent},
	} {
		t.Run(test.name, func(t *testing.T) {
			retry := request
			retry.Credential = GuestCredential{Token: test.token, SourceIP: test.source}
			retry.Now = test.at
			_, err := d.AllocateGuestDemoService(t.Context(), retry)
			if !errors.Is(err, test.want) ||
				test.want != authorization.ErrGuestIPChanged && errors.Is(err, authorization.ErrGuestIPChanged) ||
				test.want != ErrGuestUnknown && errors.Is(err, ErrGuestUnknown) {
				t.Fatalf("credential/source rejection = %v, want %v", err, test.want)
			}
		})
	}
	recovered, err := d.AllocateGuestDemoService(t.Context(), request)
	if err != nil || recovered.ID != service.ID {
		t.Fatalf("valid original bearer/source did not recover the allocation: %+v, %v", recovered, err)
	}
	after, err := controlstatedb.New(d.pool).GetGuestTrialByID(t.Context(), guest.ID)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("credential/source checks changed trial authority: %v", err)
	}
}

func TestIntegrationGuestServiceAllocationSerializesRecoveryAndOneCurrentService(t *testing.T) {
	for _, sameKey := range []bool{true, false} {
		t.Run(map[bool]string{true: "same-allocation", false: "competing-allocations"}[sameKey], func(t *testing.T) {
			d, now := newControlStateIntegrationDatabase(t, "guest_allocation_race")
			guest := newGuestTrialForTest(t, d, now)
			now = guestOperationTime(guest)
			target := guestLoopbackTarget(t)
			const callers = 8
			type result struct {
				service ServiceRecord
				err     error
			}
			results := make(chan result, callers)
			var workers sync.WaitGroup
			for index := range callers {
				workers.Go(func() {
					key := "original"
					if !sameKey {
						key = []string{"a", "b", "c", "d", "e", "f", "g", "h"}[index]
					}
					service, err := d.AllocateGuestDemoService(t.Context(), AllocateGuestDemoServiceRequest{
						Credential: guestCredentialForTest(guest), IdempotencyKey: key, Target: target, Now: now})
					results <- result{service, err}
				})
			}
			workers.Wait()
			var winner string
			allowed := 0
			for range callers {
				result := <-results
				if result.err != nil {
					if sameKey || !errors.Is(result.err, ErrServiceConflict) {
						t.Fatal(result.err)
					}
					continue
				}
				allowed++
				if winner != "" && winner != result.service.ID {
					t.Fatal("response-loss recovery returned multiple services")
				}
				winner = result.service.ID
			}
			want := 1
			if sameKey {
				want = callers
			}
			if allowed != want {
				t.Fatalf("successful allocations = %d, want %d", allowed, want)
			}
			var services, number int64
			if err := d.pool.QueryRow(t.Context(), `SELECT last_demo_number,
				(SELECT count(*) FROM control.services WHERE guest_id=$1) FROM control.guest_trials WHERE id=$1`,
				guest.ID).Scan(&number, &services); err != nil || number != 1 || services != 1 {
				t.Fatalf("races advanced allocation numbering: %d/%d, %v", number, services, err)
			}
		})
	}
}

func TestIntegrationGuestTrialReturnsSavedLifetimeAfterBootstrapWait(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "guest_bootstrap_wait")
	enableGuestTestIngress(t, d)
	guest, err := NewGuestTrialCredential(netip.MustParseAddr("192.0.2.7"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	workers := newIntegrationWorkers(t, cancel)
	gate, err := d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	defer workers.stop()
	if err := controlstatedb.New(gate).LockIdentityBootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	entered := make(chan time.Time, 1)
	var created GuestTrial
	workers.Go(func() {
		entered <- time.Now()
		var err error
		created, err = d.CreateGuestTrial(ctx, guest, "routes.example.test", now)
		done <- err
	})
	waitForPostgresBlock(t, ctx, d, int32(gate.Conn().PgConn().PID()), done)
	started := awaitIntegrationResult(t, ctx, entered)
	timer := time.NewTimer(max(0, time.Until(started.Add(250*time.Millisecond))))
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		t.Fatal(context.Cause(ctx))
	}
	if err := gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := awaitIntegrationResult(t, ctx, done); err != nil {
		t.Fatal(err)
	}
	row, err := controlstatedb.New(d.pool).GetGuestTrialByID(ctx, guest.ID)
	if err != nil || !row.ExpiresAt.Time.Equal(row.CreatedAt.Time.Add(GuestLifetime)) ||
		!created.ExpiresAt.Equal(row.ExpiresAt.Time) || row.CreatedAt.Time.Before(now.Add(250*time.Millisecond)) {
		t.Fatalf("bootstrap returned request-time rather than saved lifetime: %+v, %+v, %v", created, row, err)
	}
}

func TestIntegrationGuestServiceDatabaseRejectsMismatchedAuthority(t *testing.T) {
	f, guest := guestAuthorityFixture(t, false)
	d := f.database
	other := newGuestTrialForTest(t, d, f.now.Add(-time.Second))
	otherService, err := d.AllocateGuestDemoService(t.Context(), AllocateGuestDemoServiceRequest{
		Credential: guestCredentialForTest(other), IdempotencyKey: "other", Target: guestLoopbackTarget(t), Now: f.now})
	if err != nil {
		t.Fatal(err)
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("grant-service", func(t *testing.T) {
		// leave the destination unenrolled so its one-grant index cannot hide
		// the owner-matching foreign-key assertion.
		_, err := d.pool.Exec(t.Context(), `UPDATE control.publisher_grants SET service_id=$2 WHERE id=$1`, f.publisher.GrantID, otherService.ID)
		var constraint *pgconn.PgError
		if !errors.As(err, &constraint) || constraint.Code != "23503" {
			t.Fatalf("grant crossed its stored service owner: %v", err)
		}
	})
	otherPublisher, err := d.EnrollGuestPublisher(t.Context(), guestCredentialForTest(other), otherService.ID, public, f.now)
	if err != nil {
		t.Fatal(err)
	}
	session, err := createTestControlSession(t.Context(), d, "routes.example.test", time.Hour, 24*time.Hour, f.now)
	if err != nil {
		t.Fatal(err)
	}
	team := session.Identity.PersonalTeamID
	digest := sha256.Sum256([]byte("invalid-owner"))
	for _, owners := range [][2]any{{nil, nil}, {team, guest.ID}} {
		_, err := d.pool.Exec(t.Context(), `INSERT INTO control.services
			(id,team_id,guest_id,name,protocol,ephemeral,public,service_port,domain_id,ingress_pool_id,
			certificate_hostname,certificate_scope,expires_at,idempotency_key,request_digest,created_at,updated_at)
			SELECT $1,$2,$3,'invalid','http',true,true,443,domain_id,ingress_pool_id,
			'invalid.example.test','invalid.example.test',expires_at,$1,$4,created_at,updated_at
			FROM control.services WHERE id=$5`, mustOpaqueID(t, opaqueid.ServicePrefix), owners[0], owners[1], digest[:], f.service.ID)
		var constraint *pgconn.PgError
		if !errors.As(err, &constraint) || constraint.Code != "23514" {
			t.Fatalf("database accepted missing or mixed ownership: %v", err)
		}
	}
	for _, test := range []struct {
		name, query string
		args        []any
	}{
		{"service-owner", `UPDATE control.services SET guest_id=$2 WHERE id=$1`, []any{f.service.ID, other.ID}},
		{"publisher-owner", `UPDATE control.publisher_identities SET guest_id=$2 WHERE id=$1`, []any{f.publisher.ID, other.ID}},
		{"grant-owner", `UPDATE control.publisher_grants SET guest_id=$2 WHERE id=$1`, []any{f.publisher.GrantID, other.ID}},
		{"run-owner", `UPDATE control.service_runs SET guest_id=$2 WHERE id=$1`, []any{f.run.RunID, other.ID}},
		{"run-publisher", `UPDATE control.service_runs SET publisher_identity_id=$2 WHERE id=$1`, []any{f.run.RunID, otherPublisher.ID}},
		{"run-grant", `UPDATE control.service_runs SET publisher_grant_id=$2 WHERE id=$1`, []any{f.run.RunID, otherPublisher.GrantID}},
		{"run-key", `UPDATE control.service_runs SET publisher_key_id=$2 WHERE id=$1`, []any{f.run.RunID, otherPublisher.KeyID}},
		{"active-run", `UPDATE control.guest_trials SET active_service_run_id=$2 WHERE id=$1`, []any{other.ID, f.run.RunID}},
		{"service-expiry", `UPDATE control.services SET expires_at=expires_at+interval '1 second' WHERE id=$1`, []any{f.service.ID}},
		{"grant-expiry", `UPDATE control.publisher_grants SET expires_at=expires_at+interval '1 second' WHERE id=$1`, []any{f.publisher.GrantID}},
		{"trial-expiry", `UPDATE control.guest_trials SET expires_at=expires_at+interval '1 second' WHERE id=$1`, []any{guest.ID}},
		{"trial-pool", `UPDATE control.guest_trials SET ingress_pool_id='other' WHERE id=$1`, []any{guest.ID}},
		{"guest-pool", `UPDATE control.services SET publisher_pool=true WHERE id=$1`, []any{f.service.ID}},
		{"guest-protocol", `UPDATE control.services SET protocol='tcp' WHERE id=$1`, []any{f.service.ID}},
		{"guest-nonpublic", `UPDATE control.services SET public=false WHERE id=$1`, []any{f.service.ID}},
		{"guest-nonephemeral", `UPDATE control.services SET ephemeral=false WHERE id=$1`, []any{f.service.ID}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := d.pool.Exec(t.Context(), test.query, test.args...)
			var constraint *pgconn.PgError
			if !errors.As(err, &constraint) || constraint.Code != "23503" && constraint.Code != "23514" {
				t.Fatalf("database accepted mismatched or extended authority: %v", err)
			}
		})
	}
	for _, credential := range []GuestCredential{guestCredentialForTest(other), {Token: credentials.AccessToken("invalid"), SourceIP: guest.SourceIP}} {
		if _, err := d.EnrollGuestPublisher(t.Context(), credential, f.service.ID, public, f.now); err == nil {
			t.Fatal("unrelated trial enrolled a publisher")
		}
		if err := d.DeleteService(WithGuestServiceCredential(t.Context(), credential), f.service.ID, "", f.now); err == nil {
			t.Fatal("unrelated trial deleted a service")
		}
	}
	if err := d.DeleteService(WithGuestServiceCredential(t.Context(), guestCredentialForTest(guest)), f.service.ID, "", f.now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	replacement, err := d.AllocateGuestDemoService(t.Context(), AllocateGuestDemoServiceRequest{
		Credential: guestCredentialForTest(guest), IdempotencyKey: "replacement", Target: guestLoopbackTarget(t), Now: f.now.Add(2 * time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	replacementPublisher, err := d.EnrollGuestPublisher(t.Context(), guestCredentialForTest(guest), replacement.ID, public, f.now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	// matching trial ownership alone must not let another service's exact grant
	// or key replace the run's captured publisher tuple.
	_, err = d.pool.Exec(t.Context(), `UPDATE control.service_runs SET
		publisher_identity_id=$2,publisher_grant_id=$3,publisher_key_id=$4 WHERE id=$1`,
		f.run.RunID, replacementPublisher.ID, replacementPublisher.GrantID, replacementPublisher.KeyID)
	var constraint *pgconn.PgError
	if !errors.As(err, &constraint) || constraint.Code != "23503" {
		t.Fatalf("same-trial grant crossed its exact service: %v", err)
	}
	forged := f.publisher
	forged.Scope.ServiceID = replacement.ID
	if _, err := d.PrepareServiceRun(f.ctx, replacement.ID, forged, "wrong-service", f.now.Add(2*time.Second),
		ServiceRunRequest{Metadata: replacement.ServiceMetadata}); !errors.Is(err, ErrServiceAccess) {
		t.Fatalf("publisher selection crossed its stored exact service: %v", err)
	}
}

func TestIntegrationGuestShareDoesNotGrantConnectorPermission(t *testing.T) {
	f, guest := guestAuthorityFixture(t, true)
	d := f.database
	raw := bytes.Repeat([]byte{7}, 32)
	share, err := d.CreateGuestShare(t.Context(), guestCredentialForTest(guest), f.service.ID, "review", "",
		sha256.Sum256(raw), guest.ExpiresAt, f.now)
	if err != nil {
		t.Fatal(err)
	}
	scope := visitorscope.Scope{Kind: visitorscope.Service, ID: f.service.ID}
	source := ShareTokenSource{ShareID: share.ID, Secret: base64.RawURLEncoding.EncodeToString(raw)}
	if _, err := d.IssueVisitorToken(t.Context(), testVisitorIssuer, scope, source, f.now); err != nil {
		t.Fatal("separately shared HTTP visitor was denied", err)
	}
	session, err := createTestControlSession(t.Context(), d, "routes.example.test", time.Hour, 24*time.Hour, f.now)
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	device, err := d.EnrollVisitorDevice(t.Context(), session.Identity.Identity.ID, public, f.now)
	if err != nil {
		t.Fatal(err)
	}
	request := ConnectorPeerPairRequest{
		ServiceID: f.service.ID, ServiceRunID: f.run.RunID, RunNumber: f.run.RunNumber, PublisherIdentityID: f.publisher.ID,
		Subject: VisitorSubject{Kind: tunnelv1.VisitorHumanDevice, IdentityID: session.Identity.Identity.ID, DeviceID: device.ID},
		Source:  DeviceTokenSource{DeviceID: device.ID}, IdempotencyKey: "not-shared", Action: "create", RequestedAt: f.now,
		ExpectedRelays: testConnectorPairRelays(f.run, f.leases),
	}
	signConnectorPairRequest(t, &request, private)
	ctx := WithControlPrincipal(t.Context(), companyTestPrincipal(t, d, session, f.now))
	if _, err := d.PrepareConnectorPeerPair(ctx, request, f.now); !errors.Is(err, ErrVisitorPermission) && !errors.Is(err, ErrServiceAccess) {
		t.Fatalf("HTTP share or browser identity granted connector permission: %v", err)
	}
	if _, err := d.RevokeGuestShare(t.Context(), guestCredentialForTest(guest), share.ID, f.now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.IssueVisitorToken(t.Context(), testVisitorIssuer, scope, source, f.now.Add(time.Second)); !errors.Is(err, ErrVisitorPermission) {
		t.Fatalf("revoked trial share issued visitor permission: %v", err)
	}
}

func TestIntegrationGuestServiceRejectsExpiryDuringDatabaseWait(t *testing.T) {
	for _, operation := range []string{"allocate", "recover", "enroll", "prepare", "start", "heartbeat", "claim"} {
		for _, boundary := range []string{"admission", "write", "deferred"} {
			if operation == "recover" && boundary != "admission" {
				continue
			}
			t.Run(operation+"/"+boundary, func(t *testing.T) {
				// each case owns its database and fixed expiry.
				t.Parallel()
				f, guest := guestAuthorityFixture(t, false)
				d := f.database
				ctx, cancel := context.WithTimeout(f.ctx, 15*time.Second)
				workers := newIntegrationWorkers(t, cancel)
				const admissionBudget = 2 * time.Second
				at := guest.ExpiresAt.Add(-admissionBudget)
				setupAt := at.Add(-10 * time.Second)
				request := f.allocation
				request.Now = setupAt
				if operation != "recover" {
					if err := d.CloseServiceRun(f.ctx, f.service.ID, f.run.RunID, f.run.Token, f.now); err != nil {
						t.Fatal(err)
					}
				}
				if operation == "allocate" || operation == "enroll" {
					if err := d.DeleteService(WithGuestServiceCredential(t.Context(), request.Credential), f.service.ID, "", f.now); err != nil {
						t.Fatal(err)
					}
					request.IdempotencyKey = "next"
					if operation == "enroll" {
						var err error
						f.service, err = d.AllocateGuestDemoService(t.Context(), request)
						if err != nil {
							t.Fatal(err)
						}
					}
				}
				if operation == "start" || operation == "heartbeat" || operation == "claim" {
					f.leases = map[string]RelayLease{}
					for slot := range 2 {
						lease, err := d.RegisterRelay(ctx, relayLifecycleRegistration(fmt.Sprintf("near-expiry-%d", slot)), setupAt, time.Hour)
						if err != nil {
							t.Fatal(err)
						}
						f.leases[lease.RelayServiceID] = lease
					}
					var err error
					f.prep, err = d.PrepareServiceRun(f.ctx, f.service.ID, f.publisher, "near-expiry", setupAt,
						ServiceRunRequest{Metadata: f.service.ServiceMetadata})
					if err != nil {
						t.Fatal(err)
					}
					if operation != "start" {
						f.run, err = d.StartServiceRun(f.ctx, f.service.ID, f.prep.RunID, f.prep.RunNumber, f.publisher, setupAt)
						if err != nil {
							t.Fatal(err)
						}
					}
				}
				snapshot := func() []byte {
					t.Helper()
					var data []byte
					if err := d.pool.QueryRow(ctx, `SELECT jsonb_build_object(
						'trial',to_jsonb(guest),
						'services',(SELECT jsonb_agg(to_jsonb(service) ORDER BY id) FROM control.services service WHERE guest_id=guest.id),
						'runs',(SELECT jsonb_agg(to_jsonb(run) ORDER BY id) FROM control.service_runs run WHERE guest_id=guest.id),
						'publishers',(SELECT jsonb_agg(to_jsonb(publisher) ORDER BY id) FROM control.publisher_identities publisher WHERE guest_id=guest.id),
						'slots',(SELECT jsonb_agg(to_jsonb(slot) ORDER BY publisher_connection_id) FROM control.service_connection_slots slot
							JOIN control.services service ON service.id=slot.service_id WHERE service.guest_id=guest.id))
						FROM control.guest_trials guest WHERE id=$1`, guest.ID).Scan(&data); err != nil {
						t.Fatal(err)
					}
					return data
				}
				before := snapshot()
				gate, err := d.pool.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer rollbackTestTransaction(t, gate)
				defer workers.stop()
				if boundary == "admission" {
					_, err = controlstatedb.New(gate).LockGuestTrialByID(ctx, guest.ID)
				} else {
					_, err = gate.Exec(ctx, `SELECT pg_advisory_xact_lock(7487)`)
					if err == nil {
						table := "service_runs"
						if operation == "allocate" {
							table = "services"
						} else if operation == "enroll" {
							table = "publisher_identities"
						} else if operation == "claim" {
							table = "service_connection_slots"
						}
						trigger := "CREATE TRIGGER guest_deadline_wait BEFORE INSERT OR UPDATE ON control." + table
						if boundary == "deferred" {
							trigger = "CREATE CONSTRAINT TRIGGER guest_deadline_wait AFTER INSERT OR UPDATE ON control." + table + " DEFERRABLE INITIALLY DEFERRED"
						}
						_, err = d.pool.Exec(ctx, `CREATE FUNCTION control.guest_deadline_wait() RETURNS trigger LANGUAGE plpgsql AS $$
							BEGIN PERFORM pg_advisory_xact_lock(7487); RETURN NEW; END $$; `+trigger+` FOR EACH ROW EXECUTE FUNCTION control.guest_deadline_wait()`)
					}
				}
				if err != nil {
					t.Fatal(err)
				}
				done := make(chan error, 1)
				entered := make(chan time.Time, 1)
				request.Now = at
				workers.Go(func() {
					entered <- time.Now()
					switch operation {
					case "allocate", "recover":
						_, err := d.AllocateGuestDemoService(ctx, request)
						done <- err
					case "enroll":
						_, err := d.EnrollGuestPublisher(ctx, request.Credential, f.service.ID, f.private.Public().(ed25519.PublicKey), at)
						done <- err
					case "prepare":
						_, err := d.PrepareServiceRun(ctx, f.service.ID, f.publisher, "near-expiry", at, ServiceRunRequest{Metadata: f.service.ServiceMetadata})
						done <- err
					case "start":
						_, err := d.StartServiceRun(ctx, f.service.ID, f.prep.RunID, f.prep.RunNumber, f.publisher, at)
						done <- err
					case "heartbeat":
						_, err := d.HeartbeatServiceRun(ctx, f.service.ID, f.run.RunID, f.run.Token, at, ServiceRunHealth{Healthy: true, StreamCapacity: 32})
						done <- err
					case "claim":
						slot := f.run.Connections[0]
						_, err := d.ClaimServicePublisherConnection(ctx, slot.PublisherConnectionID, f.service.ID, f.run.RunID,
							f.run.RunNumber, slot.Revision, slot.Credential, guest.SourceIP, f.leases[slot.RelayServiceID].RelayLeaseIdentity, at)
						done <- err
					}
				})
				waitForPostgresBlock(t, ctx, d, int32(gate.Conn().PgConn().PID()), done)
				started := awaitIntegrationResult(t, ctx, entered)
				// readiness is synchronized by PostgreSQL's wait graph above.
				// this timer crosses the fixed expiry, not a scheduling guess.
				timer := time.NewTimer(max(0, time.Until(started.Add(admissionBudget+50*time.Millisecond))))
				defer timer.Stop()
				select {
				case <-timer.C:
				case <-ctx.Done():
					t.Fatal(context.Cause(ctx))
				}
				if err := gate.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				if err := awaitIntegrationResult(t, ctx, done); err == nil {
					t.Fatal("database wait extended fixed guest expiry")
				}
				if !bytes.Equal(before, snapshot()) {
					t.Fatal("expired operation committed allocation, numbering, publisher, run, or connection authority")
				}
			})
		}
	}
}
