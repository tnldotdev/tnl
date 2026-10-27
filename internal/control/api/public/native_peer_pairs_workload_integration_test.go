package public

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientworkload "github.com/tnldotdev/tnl/internal/connector/workload"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	"github.com/tnldotdev/tnl/internal/testutil/managedcert"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func exerciseWorkloadNativePeerPair(t *testing.T, d *controlstate.Database, job *clientworkload.Client, server *httptest.Server, actor, team, service, credential string) {
	t.Helper()
	ctx := t.Context()
	now := time.Now().UTC()
	enrollment, err := d.IssuePublisherGroupEnrollment(ctx, team, "example", "production", actor, 1, time.Hour, now)
	if err != nil {
		t.Fatal("group enrollment", err)
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	member, err := d.RedeemPublisherGroupEnrollment(ctx, enrollment.Key, pub, now)
	if err != nil {
		t.Fatal("redeem group", err)
	}
	leaseProof, err := publisherproof.Sign(member.PublisherIdentityID, member.KeyID, member.GroupID, server.URL+"/v1/publisher-groups/lease", key, now)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := d.AcquirePublisherGroupLease(ctx, member.PublisherIdentityID, member.GroupID, leaseProof, server.URL+"/v1/publisher-groups/lease", now)
	if err != nil {
		t.Fatal("group lease", err)
	}
	assignments, err := d.GetPublisherGroupAssignments(ctx, lease.AccessToken, now)
	if err != nil {
		t.Fatal("group assignments", err)
	}
	var grant controlstate.PublisherGroupServiceAssignment
	for _, candidate := range assignments.Services {
		if candidate.ServiceID == service {
			grant = candidate
		}
	}
	if grant.GrantID == "" {
		t.Fatal("missing workload service publisher assignment")
	}
	const audience = "https://control.example/v1/publisher-token"
	proof, err := publisherproof.Sign(member.PublisherIdentityID, member.KeyID, grant.GrantID, audience, key, now)
	if err != nil {
		t.Fatal(err)
	}
	access, err := d.ExchangePublisherAssertion(ctx, member.PublisherIdentityID, grant.GrantID, audience, proof, "", now)
	if err != nil {
		t.Fatal("exchange publisher assertion", err)
	}
	relays := map[string]controlstate.RelayLease{}
	for _, id := range []string{"workload-a", "workload-b"} {
		process, _ := opaqueid.New(opaqueid.RelayRunPrefix)
		relay, err := d.RegisterRelay(ctx, controlstate.RelayRegistration{RelayServiceID: id, RelayID: id, RelayRunID: process, ProtocolVersion: tunnelv1.Version, RelayAddress: id + ".example.test:443", TLSServerName: id + ".example.test", InternalRelayAddress: "127.0.0.1:8443", ConnectionCapacity: 20, StreamCapacity: 20}, now, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		relays[id] = relay
	}
	prep, err := d.PrepareServiceRun(ctx, service, access.PublisherIdentity, "workload-native-pair", now, controlstate.ServiceMetadata{Protocol: grant.Configuration.Protocol, PublisherPool: true, TrustRevision: grant.TrustRevision})
	if err != nil {
		t.Fatal("prepare service run", err)
	}
	run, err := d.StartServiceRun(ctx, service, prep.RunID, prep.RunNumber, access.PublisherIdentity, now)
	if err != nil {
		t.Fatal("start service run", err)
	}
	managedcert.Install(t, d, prep, run, now)
	for _, slot := range run.Connections {
		lease := relays[slot.RelayServiceID].RelayLeaseIdentity
		if _, err := d.ClaimServicePublisherConnection(ctx, slot.PublisherConnectionID, service, run.RunID, run.RunNumber, slot.Revision, slot.Credential, lease, now); err != nil {
			t.Fatal(err)
		}
		if _, err := d.ReadyServicePublisherConnection(ctx, slot.PublisherConnectionID, run.RunID, run.RunNumber, slot.Revision, lease, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := d.HeartbeatServiceRun(ctx, service, run.RunID, run.Token, now, controlstate.ServiceRunHealth{Healthy: true, StreamCapacity: 20}); err != nil {
		t.Fatal(err)
	}
	selected, err := job.SelectServiceRun(ctx, service)
	if err != nil || selected.PairReady == nil || len(selected.PairReady.Relays) != 2 || selected.PairReady.PublisherIdentityId != access.PublisherIdentity.ID {
		t.Fatal("workload selection missing ready pair", err)
	}
	// a credential-free response is a signing hint, never a pair key or a
	// publisher connection credential.
	selectionJSON, err := json.Marshal(selected)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(selectionJSON, []byte(`"key"`)) || bytes.Contains(selectionJSON, []byte(run.Connections[0].Credential)) {
		t.Fatal("selection disclosed key material")
	}
	request := controlv1.NativePeerPairRequest{ServiceRunId: selected.ServiceRunId, RunNumber: selected.RunNumber, PublisherIdentityId: selected.PairReady.PublisherIdentityId, Subject: selected.Subject, Source: json.RawMessage(`{"kind":"workload","credential":"` + credential + `"}`), Action: "create", IdempotencyKey: "workload-native-one", RequestedAt: time.Now().UTC().Truncate(time.Microsecond), ExpectedRelays: selected.PairReady.Relays}
	sign := func(body *controlv1.NativePeerPairRequest) {
		proof, err := controlv1.NativePeerPairProofMessage(service, *body)
		if err != nil {
			t.Fatal(err)
		}
		body.Signature = base64.RawURLEncoding.EncodeToString(job.Sign(proof))
	}
	sign(&request)
	path := "/v1/services/" + service + "/native-peer-pairs"
	call := func(body controlv1.NativePeerPairRequest, bearer string, renew string) (int, []byte) {
		payload, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r, err := http.NewRequestWithContext(ctx, "POST", server.URL+path+renew, bytes.NewReader(payload))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/json")
		if bearer != "" {
			r.Header.Set("Authorization", "Bearer "+bearer)
		}
		response, err := server.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		bodyBytes, err := io.ReadAll(response.Body)
		if err != nil || response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("pair response missing no-store", err)
		}
		return response.StatusCode, bodyBytes
	}
	code, data := call(request, "", "")
	if code != 200 {
		t.Fatal("workload pair", code, string(data))
	}
	var pair controlv1.NativePeerPair
	if err := json.Unmarshal(data, &pair); err != nil || pair.Key == "" || pair.Subject.WorkloadSessionId == nil {
		t.Fatal("invalid workload delivery", err)
	}
	if code, retry := call(request, "", ""); code != 200 || !bytes.Equal(retry, data) {
		t.Fatal("workload retry changed delivery", code)
	}
	api, err := clientcontrol.New(server.URL, server.Client(), "")
	if err != nil {
		t.Fatal(err)
	}
	if delivered, err := api.PrepareWorkloadNativePeerPair(ctx, service, credential, request); err != nil || delivered.PairId != pair.PairId || delivered.Key != pair.Key {
		t.Fatal("workload client lost signed delivery", err)
	}
	if code, denied := call(request, credential, ""); code != 403 || bytes.Contains(denied, []byte(pair.Key)) {
		t.Fatal("alternate bearer recovered pair", code)
	}
	bad := request
	bad.Source = json.RawMessage(`{"kind":"workload","credential":"wlc_wrong"}`)
	if code, denied := call(bad, "", ""); code != 403 || bytes.Contains(denied, []byte(pair.Key)) {
		t.Fatal("wrong workload recovered pair", code)
	}
	bad = request
	bad.Subject = controlv1.VisitorSubject{Kind: "workload_session", WorkloadSessionId: new("wls_0123456789ABCDEFGHIJKL")}
	if code, _ := call(bad, "", ""); code != 403 {
		t.Fatal("mismatched workload accepted", code)
	}
	bad = request
	bad.Signature = base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	if code, denied := call(bad, "", ""); code != 403 || bytes.Contains(denied, []byte(pair.Key)) {
		t.Fatal("wrong workload proof recovered pair", code)
	}
	renew := request
	renew.Action, renew.PreviousPairId, renew.PreviousGeneration, renew.RequestedAt = "renew", &pair.PairId, &pair.DeliveryGeneration, time.Now().UTC().Truncate(time.Microsecond).Add(time.Microsecond)
	sign(&renew)
	if code, data := call(renew, "", "/"+pair.PairId+"/renew"); code != 200 {
		t.Fatal("workload renewal", code, string(data))
	}
	if delivered, err := api.RenewWorkloadNativePeerPair(ctx, service, pair.PairId, credential, renew); err != nil || delivered.PairId != pair.PairId || delivered.Key != pair.Key {
		t.Fatal("workload client renewal lost delivery", err)
	}
	replace := renew
	replace.Action, replace.IdempotencyKey, replace.RequestedAt = "replace", "workload-native-two", time.Now().UTC().Truncate(time.Microsecond).Add(time.Millisecond)
	sign(&replace)
	code, replaced := call(replace, "", "")
	var next controlv1.NativePeerPair
	if code != 200 || json.Unmarshal(replaced, &next) != nil || next.Key == pair.Key || next.DeliveryGeneration <= pair.DeliveryGeneration {
		t.Fatal("workload replacement did not rotate delivery", code)
	}
	if code, denied := call(request, "", ""); code != 409 || bytes.Contains(denied, []byte(next.Key)) {
		t.Fatal("workload replay recovered replaced key", code)
	}
}
