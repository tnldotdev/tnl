package public

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
	"github.com/tnldotdev/tnl/internal/testutil/managedcert"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestIntegrationNativePeerPairPublicDevice(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	ctx := t.Context()
	url := testutil.NewDisposablePostgresDatabaseURL(t, "native_pair_public")
	if err := controlstate.Migrate(ctx, url); err != nil {
		t.Fatal(err)
	}
	d, err := controlstate.Open(ctx, url, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	now := time.Now().UTC().Truncate(time.Microsecond)
	owner, err := controltest.Session(ctx, d, "example.test", time.Hour, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	identity, member := owner.Identity.Identity.ID, owner.Identity.Memberships[0]
	team := member.TeamID
	service, err := d.CreateServiceAt(ctx, team, identity, "native-pair", "native-pair", controlstate.ServicePlacement{}, now, controlstate.ServiceMetadata{Protocol: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	currentTeam, err := d.GetTeam(ctx, identity, team)
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := d.IssuePublisherEnrollment(ctx, controlstate.CreatePublisherEnrollmentRequest{Scope: controlstate.PublisherScope{TeamID: team, Kind: "service", ServiceID: service.ID}, Name: "native-pair", Kind: "installed", EditorID: identity, EditorMembershipID: member.ID, PolicyRevision: uint64(currentTeam.PolicyRevision), Now: now})
	if err != nil {
		t.Fatal(err)
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := d.RedeemPublisherEnrollment(ctx, enrollment.Key, pub, now)
	if err != nil {
		t.Fatal(err)
	}
	leases := map[string]controlstate.RelayLease{}
	for _, id := range []string{"native-a", "native-b"} {
		runID, _ := opaqueid.New(opaqueid.RelayRunPrefix)
		seed := sha256.Sum256([]byte(runID))
		lease, err := d.RegisterRelay(ctx, controlstate.RelayRegistration{RelayServiceID: id, RelayID: id, RelayRunID: runID, ProtocolVersion: tunnelv1.Version, RelayAddress: id + ".example.test:443", TLSServerName: id + ".example.test", InternalRelayAddress: "127.0.0.1:8443", ConnectionCapacity: 20, StreamCapacity: 20, PeerSigningPublicKey: ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)}, now, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		leases[id] = lease
	}
	prepared, err := d.PrepareServiceRun(ctx, service.ID, publisher, "native-pair", now, controlstate.ServiceMetadata{Protocol: "tcp", TrustRevision: 1})
	if err != nil {
		t.Fatal(err)
	}
	run, err := d.StartServiceRun(ctx, service.ID, prepared.RunID, prepared.RunNumber, publisher, now)
	if err != nil {
		t.Fatal(err)
	}
	managedcert.Install(t, d, prepared, run, now)
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	device, err := d.EnrollVisitorDevice(ctx, identity, public, now)
	if err != nil {
		t.Fatal(err)
	}
	h, err := NewHandler(Config{}, d, d, nil)
	if err != nil {
		t.Fatal(err)
	}
	call := func(path, bearer string, value any) *httptest.ResponseRecorder {
		t.Helper()
		body, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		if bearer != "" {
			r.Header.Set("Authorization", "Bearer "+bearer)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("pair response may be cached", w.Code)
		}
		return w
	}
	selectionPath := "/v1/services/" + service.ID + "/select-run"
	selectRun := func() controlv1.ServiceSelection {
		t.Helper()
		w := call(selectionPath, owner.AccessToken.String(), map[string]string{"device_id": device.ID})
		if w.Code != 201 {
			t.Fatal("selection failed", w.Code, w.Body.String())
		}
		var selected controlv1.ServiceSelection
		if err := json.Unmarshal(w.Body.Bytes(), &selected); err != nil {
			t.Fatal(err)
		}
		return selected
	}
	if _, err := d.ClaimServicePublisherConnection(ctx, run.Connections[0].PublisherConnectionID, service.ID, run.RunID, run.RunNumber, run.Connections[0].Revision, run.Connections[0].Credential, leases[run.Connections[0].RelayServiceID].RelayLeaseIdentity, now); err != nil {
		t.Fatal(err)
	}
	if _, err := d.ReadyServicePublisherConnection(ctx, run.Connections[0].PublisherConnectionID, run.RunID, run.RunNumber, run.Connections[0].Revision, leases[run.Connections[0].RelayServiceID].RelayLeaseIdentity, now); err != nil {
		t.Fatal(err)
	}
	// first readiness still needs both slots.
	if s, err := d.SelectServiceRun(ctx, service.ID, identity, device.ID, time.Now()); err == nil && s.PairReady != nil {
		t.Fatal("one ready slot advertised a pair")
	}
	second := run.Connections[1]
	if _, err := d.ClaimServicePublisherConnection(ctx, second.PublisherConnectionID, service.ID, run.RunID, run.RunNumber, second.Revision, second.Credential, leases[second.RelayServiceID].RelayLeaseIdentity, now); err != nil {
		t.Fatal(err)
	}
	if _, err := d.ReadyServicePublisherConnection(ctx, second.PublisherConnectionID, run.RunID, run.RunNumber, second.Revision, leases[second.RelayServiceID].RelayLeaseIdentity, now); err != nil {
		t.Fatal(err)
	}
	if _, err := d.HeartbeatServiceRun(ctx, service.ID, run.RunID, run.Token, now, controlstate.ServiceRunHealth{Healthy: true, StreamCapacity: 20}); err != nil {
		t.Fatal(err)
	}
	selected := selectRun()
	if selected.PairReady == nil || selected.PairReady.PublisherIdentityId != publisher.ID || len(selected.PairReady.Relays) != 2 {
		t.Fatal("missing exact pair selection")
	}
	uncredentialed := httptest.NewRecorder()
	h.ServeHTTP(uncredentialed, httptest.NewRequest(http.MethodPost, selectionPath, bytes.NewBufferString(`{"device_id":"`+device.ID+`"}`)))
	if uncredentialed.Code != 401 || bytes.Contains(uncredentialed.Body.Bytes(), []byte(run.Connections[0].PublisherConnectionID)) {
		t.Fatal("uncredentialed selection exposed relay metadata", uncredentialed.Code)
	}
	for _, slot := range selected.PairReady.Relays {
		if slot.PublisherConnectionId == "" || slot.RelayLease.RelayLeaseRevision < 1 || slot.RelayLease.RelayServiceId == "" {
			t.Fatal("missing exact relay lease")
		}
	}
	if selected.PairReady.Relays[0].RelayLease.RelayServiceId == selected.PairReady.Relays[1].RelayLease.RelayServiceId {
		t.Fatal("pair selection reused a relay service")
	}
	selectionBytes, err := json.Marshal(selected)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(selectionBytes, []byte(run.Connections[0].Credential)) || bytes.Contains(selectionBytes, []byte(run.Connections[1].Credential)) || bytes.Contains(selectionBytes, []byte(`"key"`)) {
		t.Fatal("selection contains key material")
	}
	request := controlv1.NativePeerPairRequest{ServiceRunId: selected.ServiceRunId, RunNumber: selected.RunNumber, PublisherIdentityId: selected.PairReady.PublisherIdentityId, Subject: selected.Subject, Source: json.RawMessage(`{"kind":"device","device_id":"` + device.ID + `"}`), Action: "create", IdempotencyKey: "native-one", RequestedAt: time.Now().UTC().Truncate(time.Microsecond), ExpectedRelays: selected.PairReady.Relays}
	sign := func(r *controlv1.NativePeerPairRequest) {
		t.Helper()
		message, err := controlv1.NativePeerPairProofMessage(service.ID, *r)
		if err != nil {
			t.Fatal(err)
		}
		r.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, message))
	}
	path := "/v1/services/" + service.ID + "/native-peer-pairs"
	sign(&request)
	response := call(path, owner.AccessToken.String(), request)
	if response.Code != 200 {
		t.Fatal("create pair", response.Code, response.Body.String())
	}
	var pair controlv1.NativePeerPair
	if err := json.Unmarshal(response.Body.Bytes(), &pair); err != nil || pair.Key == "" || pair.PairId == "" {
		t.Fatal("missing pair", err)
	}
	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(ctx) })
	var saved []byte
	if err := conn.QueryRow(ctx, `SELECT delivery_id FROM control.native_peer_pairs WHERE id=$1`, pair.PairId).Scan(&saved); err != nil {
		t.Fatal(err)
	}
	decoded, err := tunnelv1.ParsePeerDeliveryIdentifier(pair.DeliveryId)
	if err != nil || !bytes.Equal(decoded[:], saved) {
		t.Fatal("public response changed the durable delivery header bytes", err)
	}
	if retry := call(path, owner.AccessToken.String(), request); retry.Code != 200 {
		t.Fatal("idempotent create failed", retry.Code)
	} else {
		var repeated controlv1.NativePeerPair
		if err := json.Unmarshal(retry.Body.Bytes(), &repeated); err != nil || repeated.ObservedAt.Before(pair.ObservedAt) || repeated.ObservedAt.IsZero() {
			t.Fatal("idempotent retry lost its current observation", err)
		}
		repeated.ObservedAt = pair.ObservedAt
		if !reflect.DeepEqual(repeated, pair) {
			t.Fatal("idempotent create changed the exact delivery")
		}
	}
	server := httptest.NewTLSServer(h)
	t.Cleanup(server.Close)
	t.Run("stable owner replacement", func(t *testing.T) {
		assertNativeHTTPStableOwners(t, d, conn, server, owner.AccessToken.String(), service.ID, run.Token, request, func(message []byte) []byte { return ed25519.Sign(key, message) })
	})
	if t.Failed() {
		return
	}
	api, err := clientcontrol.New(server.URL, server.Client(), owner.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if delivered, err := api.PrepareDeviceNativePeerPair(ctx, service.ID, device.ID, request); err != nil || delivered.PairId != pair.PairId || delivered.Key != pair.Key || delivered.DeliveryId != pair.DeliveryId {
		t.Fatal("device client lost signed delivery", err)
	}
	// candidates are discoverable before either relay claim, but contain no
	// key, subject or source. the delivery endpoint still denies preparation.
	discover := func(bearer, after string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, "/v1/services/"+service.ID+"/runs/"+run.RunID+"/native-peer-pairs"+after, nil)
		if bearer != "" {
			r.Header.Set("Authorization", "Bearer "+bearer)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("discovery may be cached")
		}
		return w
	}
	for _, bearer := range []string{"", "not-a-run-token", owner.AccessToken.String()} {
		if w := discover(bearer, ""); w.Code == 200 || bytes.Contains(w.Body.Bytes(), []byte(pair.PairId)) {
			t.Fatal("unauthorized discovery exposed a candidate", w.Code)
		}
	}
	if w := discover(run.Token, "?after=invalid"); w.Code != 400 {
		t.Fatal("invalid discovery cursor accepted", w.Code)
	}
	if w := discover(run.Token, ""); w.Code != 200 {
		t.Fatal("publisher discovery failed", w.Code, w.Body.String())
	} else {
		var page controlv1.NativePeerPairCandidates
		if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil || len(page.Items) != 1 || page.Items[0].PairId != pair.PairId || page.Items[0].DeliveryGeneration != pair.DeliveryGeneration || page.NextAfter != nil {
			t.Fatal("discovery lost the exact candidate", err)
		}
		for _, field := range []string{pair.Key, `"key"`, `"subject"`, `"source_ip"`, `"delivery_id"`} {
			if bytes.Contains(w.Body.Bytes(), []byte(field)) {
				t.Fatal("discovery disclosed delivery material")
			}
		}
	}
	if page, err := api.ListNativePeerPairs(ctx, service.ID, run.RunID, "", credentials.ServiceRunToken(run.Token)); err != nil || len(page.Items) != 1 || page.Items[0].PairId != pair.PairId {
		t.Fatal("run-token client lost discovery", err)
	}
	if page, err := api.ListNativePeerPairs(ctx, service.ID, run.RunID, pair.PairId, credentials.ServiceRunToken(run.Token)); err != nil || len(page.Items) != 0 {
		t.Fatal("run-token client lost the cursor", err)
	}
	deliveryPath := "/v1/services/" + service.ID + "/runs/" + run.RunID + "/native-peer-pairs/" + pair.PairId + "/delivery"
	deliver := func(bearer string, generation int64) *httptest.ResponseRecorder {
		t.Helper()
		return call(deliveryPath, bearer, map[string]int64{"delivery_generation": generation})
	}
	preparedPath := "/v1/services/" + service.ID + "/runs/" + run.RunID + "/native-peer-pairs/" + pair.PairId + "/prepared"
	report := controlv1.NativePeerPairPrepared{DeliveryId: pair.DeliveryId, DeliveryGeneration: pair.DeliveryGeneration, BindingExpiresAt: pair.ExpiresAt}
	assertDenied := func(bearer string, generation int64) {
		t.Helper()
		w := deliver(bearer, generation)
		if w.Code == 200 || bytes.Contains(w.Body.Bytes(), []byte(pair.Key)) {
			t.Fatal("unclaimed or unauthorized delivery exposed pair key", w.Code, w.Body.String())
		}
		body := report
		body.DeliveryGeneration = generation
		w = call(preparedPath, bearer, body)
		if w.Code < 400 || bytes.Contains(w.Body.Bytes(), []byte(pair.Key)) {
			t.Fatal("unclaimed or unauthorized preparation report succeeded", w.Code, w.Body.String())
		}
	}
	assertDenied(run.Token, pair.DeliveryGeneration) // no relay leg has claimed the pair
	assertDenied(owner.AccessToken.String(), pair.DeliveryGeneration)
	assertDenied("not-a-run-token", pair.DeliveryGeneration)
	assertDenied(run.Token, pair.DeliveryGeneration+1)
	otherService, err := d.CreateServiceAt(ctx, team, identity, "unrelated-pair", "unrelated-pair", controlstate.ServicePlacement{}, now, controlstate.ServiceMetadata{Protocol: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	otherEnrollment, err := d.IssuePublisherEnrollment(ctx, controlstate.CreatePublisherEnrollmentRequest{Scope: controlstate.PublisherScope{TeamID: team, Kind: "service", ServiceID: otherService.ID}, Name: "other-native-pair", Kind: "installed", EditorID: identity, EditorMembershipID: member.ID, PolicyRevision: uint64(currentTeam.PolicyRevision), Now: now})
	if err != nil {
		t.Fatal(err)
	}
	otherPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPublisher, err := d.RedeemPublisherEnrollment(ctx, otherEnrollment.Key, otherPublic, now)
	if err != nil {
		t.Fatal(err)
	}
	otherPrepared, err := d.PrepareServiceRun(ctx, otherService.ID, otherPublisher, "other-native-pair", now, controlstate.ServiceMetadata{Protocol: "tcp", TrustRevision: 1})
	if err != nil {
		t.Fatal(err)
	}
	otherRun, err := d.StartServiceRun(ctx, otherService.ID, otherPrepared.RunID, otherPrepared.RunNumber, otherPublisher, now)
	if err != nil {
		t.Fatal(err)
	}
	assertDenied(otherRun.Token, pair.DeliveryGeneration)
	if w := discover(otherRun.Token, ""); w.Code == 200 {
		t.Fatal("another run token discovered the publisher's pairs")
	}
	var before int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM control.native_peer_pairs`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	claim := func(slot int, source netip.Addr) {
		t.Helper()
		leg := pair.Relays[slot]
		proof := tunnelv1.NativePairLegProof{PairID: pair.PairId, DeliveryGeneration: pair.DeliveryGeneration,
			ServiceID: service.ID, ServiceRunID: run.RunID, RunNumber: run.RunNumber,
			PublisherIdentityID: publisher.ID, ConnectionSlot: slot, PublisherConnectionID: leg.PublisherConnectionId,
			AssignmentRevision: leg.AssignmentRevision, RelayServiceID: leg.RelayLease.RelayServiceId,
			RelayID: leg.RelayLease.RelayId, RelayRunID: leg.RelayLease.RelayRunId,
			RelayLeaseRevision: uint64(leg.RelayLease.RelayLeaseRevision), RequestedAt: time.Now().UTC().Truncate(time.Microsecond), Nonce: make([]byte, 32)}
		if _, err := rand.Read(proof.Nonce); err != nil {
			t.Fatal(err)
		}
		message, err := proof.Message()
		if err != nil {
			t.Fatal(err)
		}
		proof.Signature = ed25519.Sign(key, message)
		relayMessage, err := proof.RelayClaimMessage(source)
		if err != nil {
			t.Fatal(err)
		}
		seed := sha256.Sum256([]byte(proof.RelayRunID))
		if _, err := d.ClaimNativePeerPairLeg(ctx, leases[leg.RelayLease.RelayServiceId].RelayLeaseIdentity, source, proof, ed25519.Sign(ed25519.NewKeyFromSeed(seed[:]), relayMessage), time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	source := netip.MustParseAddr("192.0.2.10")
	claim(0, source)
	assertDenied(run.Token, pair.DeliveryGeneration) // one claim is insufficient
	claim(1, source)
	if w := deliver(run.Token, pair.DeliveryGeneration); w.Code != 200 {
		t.Fatal("two matching relay claims did not deliver", w.Code, w.Body.String())
	} else {
		var delivery controlv1.NativePeerPairDelivery
		if err := json.Unmarshal(w.Body.Bytes(), &delivery); err != nil || delivery.Key != pair.Key || delivery.DeliveryId != pair.DeliveryId || delivery.SourceIp != source.String() || delivery.ServiceRunId != run.RunID || delivery.PublisherIdentityId != publisher.ID || !reflect.DeepEqual(delivery.Subject, pair.Subject) || len(delivery.Relays) != 2 {
			t.Fatal("delivery did not bind the exact source and run", err)
		}
		formatted := controlstate.NativePeerPairDelivery{Key: pair.Key}
		if bytes.Contains([]byte(formatted.String()+formatted.GoString()), []byte(pair.Key)) {
			t.Fatal("delivery formatter leaked key")
		}
	}
	if delivered, err := api.DeliverNativePeerPair(ctx, service.ID, run.RunID, pair.PairId, pair.DeliveryGeneration, credentials.ServiceRunToken(run.Token)); err != nil || delivered.Key != pair.Key {
		t.Fatal("run-token client lost delivery", err)
	}
	for _, mutate := range []func(*controlv1.NativePeerPairPrepared){
		func(r *controlv1.NativePeerPairPrepared) { r.DeliveryId = "invalid" },
		func(r *controlv1.NativePeerPairPrepared) {
			r.DeliveryId = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 16))
		},
		func(r *controlv1.NativePeerPairPrepared) { r.DeliveryGeneration++ },
		func(r *controlv1.NativePeerPairPrepared) { r.BindingExpiresAt = pair.ExpiresAt.Add(time.Second) },
		func(r *controlv1.NativePeerPairPrepared) { r.BindingExpiresAt = now },
	} {
		body := report
		mutate(&body)
		if w := call(preparedPath, run.Token, body); w.Code < 400 {
			t.Fatal("invalid preparation report accepted", w.Code)
		}
	}
	if pair.PublisherPreparedUntil != nil {
		t.Fatal("pair was prepared before the publisher reported installation")
	}
	for range 2 {
		if err := api.ConfirmNativePeerPairPrepared(ctx, service.ID, run.RunID, pair.PairId, report, credentials.ServiceRunToken(run.Token)); err != nil {
			t.Fatal("run-token client could not confirm installed binding", err)
		}
	}
	if w := call(preparedPath, run.Token, report); w.Code != 204 || w.Body.Len() != 0 {
		t.Fatal("preparation report returned delivery material", w.Code)
	}
	if prepared, err := api.PrepareDeviceNativePeerPair(ctx, service.ID, device.ID, request); err != nil || prepared.PublisherPreparedUntil == nil || !prepared.PublisherPreparedUntil.Equal(report.BindingExpiresAt) || !prepared.ExpiresAt.Equal(pair.ExpiresAt) {
		t.Fatal("connector did not receive the bounded publisher barrier", err)
	}
	assertDenied(otherRun.Token, pair.DeliveryGeneration)
	assertDenied(owner.AccessToken.String(), pair.DeliveryGeneration)
	if _, err := conn.Exec(ctx, `UPDATE control.native_peer_pair_leg_claims SET source_ip='192.0.2.11' WHERE pair_id=$1 AND connection_slot=1`, pair.PairId); err != nil {
		t.Fatal(err)
	}
	assertDenied(run.Token, pair.DeliveryGeneration) // do not guess a shared origin
	if _, err := conn.Exec(ctx, `UPDATE control.native_peer_pair_leg_claims SET source_ip=$2 WHERE pair_id=$1 AND connection_slot=1`, pair.PairId, source); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `UPDATE control.service_connection_slots SET connection_assignment_revision=connection_assignment_revision+1 WHERE publisher_connection_id=$1`, run.Connections[0].PublisherConnectionID); err != nil {
		t.Fatal(err)
	}
	assertDenied(run.Token, pair.DeliveryGeneration)
	if _, err := conn.Exec(ctx, `UPDATE control.service_connection_slots SET connection_assignment_revision=connection_assignment_revision-1 WHERE publisher_connection_id=$1`, run.Connections[0].PublisherConnectionID); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `UPDATE control.relay_leases SET relay_lease_revision=relay_lease_revision+1 WHERE relay_id=$1`, pair.Relays[0].RelayLease.RelayId); err != nil {
		t.Fatal(err)
	}
	assertDenied(run.Token, pair.DeliveryGeneration)
	if _, err := conn.Exec(ctx, `UPDATE control.relay_leases SET relay_lease_revision=relay_lease_revision-1 WHERE relay_id=$1`, pair.Relays[0].RelayLease.RelayId); err != nil {
		t.Fatal(err)
	}
	var after int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM control.native_peer_pairs`).Scan(&after); err != nil || after != before {
		t.Fatal("delivery created another key", after, before, err)
	}
	if _, err := conn.Exec(ctx, `UPDATE control.control_sessions SET revoked_at=$2,revoked_by='test' WHERE id=(SELECT parent_control_session_id FROM control.native_peer_pairs WHERE id=$1)`, pair.PairId, time.Now()); err != nil {
		t.Fatal(err)
	}
	assertDenied(run.Token, pair.DeliveryGeneration)
	if _, err := conn.Exec(ctx, `UPDATE control.control_sessions SET revoked_at=NULL,revoked_by=NULL WHERE id=(SELECT parent_control_session_id FROM control.native_peer_pairs WHERE id=$1)`, pair.PairId); err != nil {
		t.Fatal(err)
	}
	if w := deliver(run.Token, pair.DeliveryGeneration); w.Code != 200 {
		t.Fatal("parent restoration did not restore delivery", w.Code)
	}
	if _, err := conn.Exec(ctx, `UPDATE control.native_peer_pairs SET expires_at=last_authorized_at+interval '1 microsecond' WHERE id=$1`, pair.PairId); err != nil {
		t.Fatal(err)
	}
	assertDenied(run.Token, pair.DeliveryGeneration)
	if _, err := conn.Exec(ctx, `UPDATE control.native_peer_pairs SET expires_at=$2 WHERE id=$1`, pair.PairId, pair.ExpiresAt); err != nil {
		t.Fatal(err)
	}
	bad := request
	bad.Signature = base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	if w := call(path, owner.AccessToken.String(), bad); w.Code != 403 || bytes.Contains(w.Body.Bytes(), []byte(pair.Key)) {
		t.Fatal("bad proof leaked pair", w.Code)
	}
	bad = request
	bad.Source = json.RawMessage(`{"kind":"device","device_id":"vdev_0123456789ABCDEFGHIJKL"}`)
	if w := call(path, owner.AccessToken.String(), bad); w.Code != 403 {
		t.Fatal("mismatched device accepted", w.Code)
	}
	if w := call(path, "", request); w.Code != 401 {
		t.Fatal("missing bearer accepted", w.Code)
	}
	if w := call(path, "wlc_wrong", request); w.Code != 401 {
		t.Fatal("workload bearer accepted as device", w.Code)
	}
	for _, source := range []string{`{"kind":"control_session"}`, `{"kind":"browser_session","secret":"` + string(bytes.Repeat([]byte("x"), 43)) + `"}`, `{"kind":"share","share_id":"shr_0123456789ABCDEFGHIJKL","secret":"` + string(bytes.Repeat([]byte("x"), 43)) + `"}`, `{"kind":"publisher"}`} {
		bad := request
		bad.Source = json.RawMessage(source)
		if w := call(path, owner.AccessToken.String(), bad); w.Code != 400 && w.Code != 403 || bytes.Contains(w.Body.Bytes(), []byte(pair.Key)) {
			t.Fatal("non-device source accepted or leaked pair", w.Code)
		}
	}
	bad = request
	bad.Action, bad.PreviousPairId, bad.PreviousGeneration, bad.RequestedAt = "renew", &pair.PairId, &pair.DeliveryGeneration, time.Now().UTC().Truncate(time.Microsecond).Add(time.Microsecond)
	sign(&bad)
	if w := call(path+"/"+pair.PairId+"/renew", owner.AccessToken.String(), bad); w.Code != 200 || !bytes.Contains(w.Body.Bytes(), []byte(pair.DeliveryId)) {
		t.Fatal("renew failed", w.Code, w.Body.String())
	}
	if delivered, err := api.RenewDeviceNativePeerPair(ctx, service.ID, pair.PairId, device.ID, bad); err != nil || delivered.PairId != pair.PairId || delivered.Key != pair.Key || delivered.DeliveryId != pair.DeliveryId {
		t.Fatal("device client renewal lost delivery", err)
	}
	bad.Action, bad.IdempotencyKey = "replace", request.IdempotencyKey
	bad.RequestedAt = time.Now().UTC().Truncate(time.Microsecond).Add(2 * time.Microsecond)
	sign(&bad)
	if w := call(path, owner.AccessToken.String(), bad); w.Code != 200 {
		t.Fatal("replace failed", w.Code, w.Body.String())
	} else {
		var replacement controlv1.NativePeerPair
		if err := json.Unmarshal(w.Body.Bytes(), &replacement); err != nil || replacement.DeliveryId == pair.DeliveryId {
			t.Fatal("replacement did not rotate delivery identifier", err)
		}
		if replacement.PublisherPreparedUntil != nil {
			t.Fatal("replacement inherited the old publisher barrier")
		}
		if err := conn.QueryRow(ctx, `SELECT delivery_id FROM control.native_peer_pairs WHERE id=$1`, replacement.PairId).Scan(&saved); err != nil {
			t.Fatal(err)
		}
		decoded, err := tunnelv1.ParsePeerDeliveryIdentifier(replacement.DeliveryId)
		if err != nil || !bytes.Equal(decoded[:], saved) {
			t.Fatal("replacement response changed durable header bytes", err)
		}
	}
	assertDenied(run.Token, pair.DeliveryGeneration) // replaced pair and claims cannot deliver
	if w := call(path, owner.AccessToken.String(), request); w.Code != 409 {
		t.Fatal("old delivery replay succeeded", w.Code)
	}
	if _, err := d.DisconnectServicePublisherConnection(ctx, second.PublisherConnectionID, run.RunID, run.RunNumber, second.Revision, leases[second.RelayServiceID].RelayLeaseIdentity, time.Now()); err != nil {
		t.Fatal(err)
	}
	if one := selectRun(); one.PairReady != nil {
		t.Fatal("one surviving ready slot advertised a pair")
	}
}
