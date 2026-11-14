package public

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	relayapi "github.com/tnldotdev/tnl/internal/control/api/private/relay"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
	"github.com/tnldotdev/tnl/internal/testutil/managedcert"
	relayv1 "github.com/tnldotdev/tnl/pkg/api/control/private/relay/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestIntegrationPublicURLConnectorHTTPKeepsTypedNativeAndPublisherAuthority(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	ctx := t.Context()
	databaseURL := testutil.NewDisposablePostgresDatabaseURL(t, "public_url_connector_http")
	if err := controlstate.Migrate(ctx, databaseURL); err != nil {
		t.Fatal(err)
	}
	d, err := controlstate.Open(ctx, databaseURL, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "", naming.ManagedURLModeGenerated)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	now := time.Now().UTC().Truncate(time.Microsecond)
	session, err := controltest.Session(ctx, d, "example.test", time.Hour, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	identity, member := session.Identity.Identity.ID, session.Identity.Memberships[0]
	domains, err := d.ListTeamDomains(ctx, identity, member.TeamID)
	if err != nil || len(domains) == 0 {
		t.Fatal("missing public URL domain", err)
	}
	url, err := d.CreatePublicURL(ctx, controlstate.CreatePublicURLRequest{TeamID: member.TeamID, DomainID: domains[0].ID,
		MembershipID: member.ID, ActingIdentityID: identity, IdempotencyKey: "connector-http",
		RequestDigest: sha256.Sum256([]byte("connector-http")), CanonicalHostname: "connector." + member.ManagedLabel + ".example.test",
		Target: "http://127.0.0.1:3000", PublicURLScope: controlstate.PublicURLScopeMember,
		Purpose: controlstate.PublicURLPurposeApp, DNSState: controlstate.PublicURLDNSUnmanaged}, now)
	if err != nil {
		t.Fatal(err)
	}
	team, err := d.GetTeam(ctx, identity, member.TeamID)
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := d.IssuePublisherEnrollment(ctx, controlstate.CreatePublisherEnrollmentRequest{
		Scope: controlstate.PublisherScope{TeamID: member.TeamID, Kind: "saved_public_url", PublicURLID: url.ID},
		Name:  "connector-http", Kind: "installed", EditorID: identity, EditorMembershipID: member.ID,
		PolicyRevision: uint64(team.PolicyRevision), Now: now})
	if err != nil {
		t.Fatal(err)
	}
	publisherKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x51}, ed25519.SeedSize))
	publisher, err := d.RedeemPublisherEnrollment(ctx, enrollment.Key, publisherKey.Public().(ed25519.PublicKey), now)
	if err != nil {
		t.Fatal(err)
	}
	leases := map[string]controlstate.RelayLease{}
	relayKeys := map[string]ed25519.PrivateKey{}
	for slot := range 2 {
		id := fmt.Sprintf("connector-http-%d", slot)
		runID, err := opaqueid.New(opaqueid.RelayRunPrefix)
		if err != nil {
			t.Fatal(err)
		}
		seed := sha256.Sum256([]byte(runID))
		key := ed25519.NewKeyFromSeed(seed[:])
		lease, err := d.RegisterRelay(ctx, controlstate.RelayRegistration{RelayServiceID: id, RelayID: id, RelayRunID: runID,
			ProtocolVersion: tunnelv1.Version, RelayAddress: id + ".example.test:443", TLSServerName: id + ".example.test",
			InternalRelayAddress: "127.0.0.1:8443", ConnectionCapacity: 20, StreamCapacity: 20,
			PeerSigningPublicKey: key.Public().(ed25519.PublicKey)}, now, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		leases[id], relayKeys[id] = lease, key
	}
	plan, err := d.PublisherRunPlan(ctx, publisher, url, false)
	if err != nil {
		t.Fatal(err)
	}
	runProof, err := publisherproof.SignRun(publisherKey, url.ID, "connector-http-run")
	if err != nil {
		t.Fatal(err)
	}
	run, err := d.CreatePublishRun(ctx, controlstate.PublishRunRequest{PublicURLID: url.ID, TeamID: url.TeamID,
		MembershipID: url.MembershipID, ActingIdentityID: identity, IdempotencyKey: "connector-http-run",
		RequestDigest: sha256.Sum256([]byte("connector-http-run")), PolicyRevision: uint64(url.PolicyRevision),
		ExpectedMutationRevision: url.MutationRevision, PublisherIdentityID: publisher.ID, PublisherGrantID: publisher.GrantID,
		PublisherKeyID: publisher.KeyID, PublisherRunProof: runProof, CertificateCacheKey: plan.CacheKey,
		CertificateScope: plan.Scope, CertificateIdentifiers: plan.Identifiers, CertificateChallenge: plan.ChallengeMethod}, now, time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	auth := controlstate.PublishRunAuthentication{PublicURLID: url.ID, PublishRunID: run.PublishRunID,
		PublishRunNumber: run.PublishRunNumber, PublishRunToken: run.PublishRunToken}
	managedcert.InstallPublicURL(t, d, auth, plan.Identifiers, now)
	relays := make([]controlv1.ConnectorPeerPairRelay, 2)
	for slot, assignment := range run.PublisherConnections {
		digest, err := credentials.ParsePublisherConnectionCredential(assignment.PublisherConnectionCredential)
		if err != nil {
			t.Fatal(err)
		}
		lease := leases[assignment.RelayServiceID]
		claim := controlstate.PublisherConnectionClaimRequest{ConnectionAssignmentIdentity: assignment.ConnectionAssignmentIdentity,
			RelayLeaseIdentity: lease.RelayLeaseIdentity, ClaimID: fmt.Sprintf("http-slot-%d", slot), CredentialDigest: [32]byte(digest)}
		if _, err := d.ClaimPublisherConnection(ctx, claim, now); err != nil {
			t.Fatal(err)
		}
		if _, err := d.MarkPublisherConnectionReady(ctx, claim, now); err != nil {
			t.Fatal(err)
		}
		relays[slot] = controlv1.ConnectorPeerPairRelay{PublisherConnectionId: assignment.PublisherConnectionID,
			AssignmentRevision: int64(assignment.ConnectionAssignmentRevision), RelayAddress: assignment.RelayAddress,
			TlsServerName: assignment.TLSServerName, RelayLease: controlv1.ConnectorPeerRelayLease{RelayServiceId: lease.RelayServiceID,
				RelayId: lease.RelayID, RelayRunId: lease.RelayRunID, RelayLeaseRevision: int64(lease.RelayLeaseRevision)}}
	}
	// simulate ingress policy installation through its real observation API.
	// certificate and publisher connections alone do not make a run ready.
	if _, err := d.MarkPublishRunReady(ctx, auth, now); !errors.Is(err, controlstate.ErrPublishRunNotReady) {
		t.Fatal("public URL fixture did not publish its preparation barrier", err)
	}
	conn, err := pgx.Connect(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(ctx) })
	var ingressPool string
	if err := conn.QueryRow(ctx, `SELECT ingress_pool_id FROM control.public_urls WHERE id=$1`, url.ID).Scan(&ingressPool); err != nil {
		t.Fatal(err)
	}
	ingress, err := d.RegisterIngress(ctx, controlstate.IngressRegistration{IngressID: "connector-http-ingress",
		IngressRunID: "connector-http-ingress-process", ProtocolVersion: tunnelv1.Version, ConnectionCapacity: 20, IngressPoolID: ingressPool}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := d.ReadIngressRoutingTableSnapshot(ctx, ingress.IngressLeaseIdentity, now)
	if err != nil {
		t.Fatal(err)
	}
	var observations []controlstate.IngressPublicRunObservation
	for _, entry := range snapshot.Entries {
		if entry.Projection.PublishRunID == run.PublishRunID {
			observations = append(observations, controlstate.IngressPublicRunObservation{PublishRunID: run.PublishRunID,
				PublishRunNumber: int64(run.PublishRunNumber), EntryRevision: int64(entry.EntryRevision),
				ValidUntil: entry.Projection.PublicUrlExpiresAt})
		}
	}
	if len(observations) != 1 {
		t.Fatal("public URL fixture lacks an ingress preparation projection")
	}
	if _, err := d.RenewIngress(ctx, controlstate.IngressRenewal{IngressLeaseIdentity: ingress.IngressLeaseIdentity,
		RoutingTableRevision: snapshot.RoutingTableRevision, PreparedPublicRuns: observations}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := d.MarkPublishRunReady(ctx, auth, now); err != nil {
		t.Fatal("acknowledge public URL serving readiness", err)
	}
	deviceKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x52}, ed25519.SeedSize))
	device, err := d.EnrollVisitorDevice(ctx, identity, deviceKey.Public().(ed25519.PublicKey), now)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(Config{ControlURL: "https://control.example.test"}, DatabaseStores(d), d, nil)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	client, err := clientcontrol.New(server.URL, server.Client(), session.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	request := controlv1.PublicURLConnectorPeerPairRequest{PublishRunId: run.PublishRunID, PublishRunNumber: int64(run.PublishRunNumber),
		PublisherIdentityId: publisher.ID, Subject: controlv1.VisitorSubject{Kind: controlv1.VisitorSubjectKind(tunnelv1.VisitorHumanDevice),
			IdentityId: &identity, DeviceId: &device.ID}, Source: controlv1.VisitorTokenDeviceSource{Kind: controlv1.VisitorTokenDevice, DeviceId: device.ID},
		Action: "create", IdempotencyKey: "retained-http-owner", RequestedAt: time.Now().UTC().Truncate(time.Microsecond), ExpectedRelays: relays}
	sign := func(body *controlv1.PublicURLConnectorPeerPairRequest) {
		t.Helper()
		message, err := controlv1.PublicURLConnectorPeerPairProofMessage(url.ID, *body)
		if err != nil {
			t.Fatal(err)
		}
		body.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(deviceKey, message))
	}
	sign(&request)
	pair, err := client.PreparePublicURLConnectorPeerPair(ctx, url.ID, request)
	if err != nil || pair.Key == "" || pair.SessionKey == "" || pair.PublicUrlId != url.ID ||
		pair.PublishRunId != run.PublishRunID || pair.PublishRunNumber != int64(run.PublishRunNumber) {
		t.Fatal("prepare typed public URL pair", err)
	}
	replay, err := client.PreparePublicURLConnectorPeerPair(ctx, url.ID, request)
	if err != nil || replay.PairId != pair.PairId || replay.Key != pair.Key || replay.SessionKey != pair.SessionKey {
		t.Fatal("HTTP retry replaced the retained public URL owner", err)
	}
	page, err := client.ListPublicURLConnectorPeerPairs(ctx, run.PublishRunID, run.PublishRunNumber, "", run.PublishRunToken)
	if err != nil || len(page.Items) != 1 || page.Items[0].PairId != pair.PairId || page.Items[0].OwnerAuthority != nil {
		t.Fatal("publisher client lost hint-only candidate", err)
	}
	if _, err := client.DeliverPublicURLConnectorPeerPair(ctx, run.PublishRunID, run.PublishRunNumber, pair.PairId, pair.DeliveryGeneration, run.PublishRunToken); err == nil {
		t.Fatal("delivery API ignored missing relay claims")
	}
	call := func(method, path, bearer string, value any) *httptest.ResponseRecorder {
		t.Helper()
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(method, path, bytes.NewReader(raw))
		if bearer != "" {
			r.Header.Set("Authorization", "Bearer "+bearer)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("connector HTTP response may be cached")
		}
		return w
	}
	pairPath := "/v1/public-urls/" + url.ID + "/connector-peer-pairs"
	for _, bearer := range []string{"", "not-a-control-session", run.PublishRunToken.String()} {
		w := call(http.MethodPost, pairPath, bearer, request)
		if w.Code < 400 || bytes.Contains(w.Body.Bytes(), []byte(pair.Key)) {
			t.Fatal("non-native credential recovered a public URL pair", w.Code)
		}
	}
	raw, _ := json.Marshal(request)
	var mixed map[string]json.RawMessage
	if err := json.Unmarshal(raw, &mixed); err != nil {
		t.Fatal(err)
	}
	mixed["service_run_id"] = json.RawMessage(`"srun_1234567890123456789012"`)
	if w := call(http.MethodPost, pairPath, session.AccessToken.String(), mixed); w.Code != 400 {
		t.Fatal("mixed HTTP publication families reached state", w.Code)
	}
	discoveryPath := "/v1/publish-runs/" + run.PublishRunID + "/connector-peer-pairs?publish_run_number=" + strconv.FormatUint(run.PublishRunNumber, 10)
	for _, bearer := range []string{"", "not-a-run-token", session.AccessToken.String()} {
		if w := call(http.MethodGet, discoveryPath, bearer, nil); w.Code < 400 || bytes.Contains(w.Body.Bytes(), []byte(pair.PairId)) {
			t.Fatal("control or absent credentials discovered publisher owners", w.Code)
		}
	}
	direct, err := relayapi.NewDirectClient(relayapi.DirectConfig{Store: d, LeaseDuration: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	source := netip.MustParseAddr("192.0.2.9")
	for slot, relay := range pair.Relays {
		proof := tunnelv1.ConnectorPairLegProof{PairID: pair.PairId, DeliveryGeneration: pair.DeliveryGeneration,
			PublicURLID: pair.PublicUrlId, PublishRunID: pair.PublishRunId, PublishRunNumber: pair.PublishRunNumber,
			PublisherIdentityID: pair.PublisherIdentityId, ConnectionSlot: slot, PublisherConnectionID: relay.PublisherConnectionId,
			AssignmentRevision: relay.AssignmentRevision, RelayServiceID: relay.RelayLease.RelayServiceId, RelayID: relay.RelayLease.RelayId,
			RelayRunID: relay.RelayLease.RelayRunId, RelayLeaseRevision: uint64(relay.RelayLease.RelayLeaseRevision),
			RequestedAt: time.Now().UTC().Truncate(time.Microsecond), Nonce: bytes.Repeat([]byte{byte(slot + 1)}, 32)}
		message, err := proof.Message()
		if err != nil {
			t.Fatal(err)
		}
		proof.Signature = ed25519.Sign(deviceKey, message)
		message, err = proof.RelayClaimMessage(source)
		if err != nil {
			t.Fatal(err)
		}
		signature := ed25519.Sign(relayKeys[proof.RelayServiceID], message)
		lease := leases[proof.RelayServiceID]
		claim, err := direct.ClaimConnectorPeerPairLegFromAcceptedSocket(ctx, relayv1.RelayLease{RelayServiceId: lease.RelayServiceID,
			RelayId: lease.RelayID, RelayRunId: lease.RelayRunID, RelayLeaseRevision: int64(lease.RelayLeaseRevision)}, source, proof, signature)
		if err != nil || claim.Key != pair.Key {
			t.Fatal("relay adapter lost exact public URL proof fields", err)
		}
	}
	delivery, err := client.DeliverPublicURLConnectorPeerPair(ctx, run.PublishRunID, run.PublishRunNumber, pair.PairId, pair.DeliveryGeneration, run.PublishRunToken)
	if err != nil || delivery.Key != pair.Key || delivery.SessionKey != pair.SessionKey || delivery.SourceIp != source.String() ||
		delivery.PublicUrlId != url.ID || delivery.PublishRunId != run.PublishRunID {
		t.Fatal("publisher API changed delivery scope or endpoint material", err)
	}
	prepared := controlv1.ConnectorPeerPairPrepared{Phase: controlv1.ConnectorPeerPairPreparedInstalled, DeliveryId: delivery.DeliveryId,
		DeliveryGeneration: delivery.DeliveryGeneration, BindingExpiresAt: delivery.ExpiresAt}
	if err := client.ConfirmPublicURLConnectorPeerPairPrepared(ctx, run.PublishRunID, run.PublishRunNumber, pair.PairId, prepared, run.PublishRunToken); err != nil {
		t.Fatal("publisher API rejected its exact installed binding", err)
	}
	renewal := request
	renewal.Action, renewal.PreviousPairId, renewal.PreviousGeneration = "renew", &pair.PairId, &pair.DeliveryGeneration
	renewal.RequestedAt = time.Now().UTC().Truncate(time.Microsecond)
	sign(&renewal)
	renewed, err := client.RenewPublicURLConnectorPeerPair(ctx, url.ID, pair.PairId, renewal)
	if err != nil || renewed.Pair.PairId != pair.PairId || renewed.Pair.SessionKey != pair.SessionKey ||
		renewed.VisitorPermission.Resource.Kind != "public_url" || renewed.VisitorPermission.Resource.Id != url.ID ||
		renewed.Endpoint.Port != renewed.VisitorPermission.Port || renewed.Protocol != "http" {
		t.Fatal("public URL HTTP renewal substituted service permission or another owner", err)
	}
	rebind := controlv1.PublicURLConnectorPeerPairRebindRequest{Phase: "inspect", IdempotencyKey: request.IdempotencyKey,
		ExpectedGeneration: pair.DeliveryGeneration, RequestedAt: time.Now().UTC().Truncate(time.Microsecond),
		PublishRunId: pair.PublishRunId, PublishRunNumber: pair.PublishRunNumber, PublisherIdentityId: pair.PublisherIdentityId,
		TrustRevision: pair.TrustRevision, Subject: request.Subject, Source: request.Source,
		ExpectedRelays: []controlv1.ConnectorPeerPairRelay{}, PathProofs: []controlv1.ConnectorPeerPairPathProof{}}
	signRebind := func() {
		t.Helper()
		message, err := controlv1.PublicURLConnectorPeerPairRebindProofMessage(url.ID, pair.PairId, rebind)
		if err != nil {
			t.Fatal(err)
		}
		rebind.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(deviceKey, message))
	}
	signRebind()
	state, err := client.RebindPublicURLConnectorPeerPair(ctx, url.ID, pair.PairId, rebind)
	if err != nil || state.Active == nil || state.Active.SessionKey != pair.SessionKey || state.Active.PublishRunId != run.PublishRunID {
		t.Fatal("HTTP inspection changed retained publication identity", err)
	}
	operation, err := opaqueid.New(opaqueid.IdempotencyPrefix)
	if err != nil {
		t.Fatal(err)
	}
	rebind.Phase, rebind.OperationId, rebind.ExpectedRelays = "prepare", operation, relays
	rebind.RequestedAt = time.Now().UTC().Truncate(time.Microsecond)
	signRebind()
	state, err = client.RebindPublicURLConnectorPeerPair(ctx, url.ID, pair.PairId, rebind)
	if err != nil || state.Pending == nil || state.Pending.SessionKey != pair.SessionKey {
		t.Fatal("HTTP preparation replaced the endpoint session", err)
	}
	rebind.Phase, rebind.ExpectedGeneration, rebind.ExpectedRelays = "abort", state.Pending.DeliveryGeneration, []controlv1.ConnectorPeerPairRelay{}
	rebind.RequestedAt = time.Now().UTC().Truncate(time.Microsecond)
	signRebind()
	state, err = client.RebindPublicURLConnectorPeerPair(ctx, url.ID, pair.PairId, rebind)
	if err != nil || state.Active == nil || state.Pending != nil || state.Active.SessionKey != pair.SessionKey {
		t.Fatal("HTTP abort changed the retained owner", err)
	}
	if err := d.RevokeVisitorDevice(ctx, identity, device.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	rejected, err := client.RebindPublicURLConnectorPeerPair(ctx, url.ID, pair.PairId, rebind)
	var denied *clientcontrol.ProblemError
	if !errors.As(err, &denied) || denied.Status != http.StatusForbidden || rejected.Active != nil {
		t.Fatal("revoked device recovered public URL binding material", err)
	}
}
