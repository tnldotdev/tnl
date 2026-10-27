package public

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
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
		lease, err := d.RegisterRelay(ctx, controlstate.RelayRegistration{RelayServiceID: id, RelayID: id, RelayRunID: runID, ProtocolVersion: tunnelv1.Version, RelayAddress: id + ".example.test:443", TLSServerName: id + ".example.test", InternalRelayAddress: "127.0.0.1:8443", ConnectionCapacity: 20, StreamCapacity: 20}, now, time.Hour)
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
	if retry := call(path, owner.AccessToken.String(), request); retry.Code != 200 || !bytes.Equal(retry.Body.Bytes(), response.Body.Bytes()) {
		t.Fatal("idempotent create changed delivery", retry.Code)
	}
	server := httptest.NewTLSServer(h)
	t.Cleanup(server.Close)
	api, err := clientcontrol.New(server.URL, server.Client(), owner.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if delivered, err := api.PrepareDeviceNativePeerPair(ctx, service.ID, device.ID, request); err != nil || delivered.PairId != pair.PairId || delivered.Key != pair.Key {
		t.Fatal("device client lost signed delivery", err)
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
	if w := call(path+"/"+pair.PairId+"/renew", owner.AccessToken.String(), bad); w.Code != 200 {
		t.Fatal("renew failed", w.Code, w.Body.String())
	}
	if delivered, err := api.RenewDeviceNativePeerPair(ctx, service.ID, pair.PairId, device.ID, bad); err != nil || delivered.PairId != pair.PairId || delivered.Key != pair.Key {
		t.Fatal("device client renewal lost delivery", err)
	}
	bad.Action, bad.IdempotencyKey = "replace", "native-two"
	bad.RequestedAt = time.Now().UTC().Truncate(time.Microsecond).Add(2 * time.Microsecond)
	sign(&bad)
	if w := call(path, owner.AccessToken.String(), bad); w.Code != 200 {
		t.Fatal("replace failed", w.Code, w.Body.String())
	}
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
