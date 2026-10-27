package relay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	controlrelay "github.com/tnldotdev/tnl/internal/control/api/private/relay"
	controlpublic "github.com/tnldotdev/tnl/internal/control/api/public"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/serviceapi"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
	"github.com/tnldotdev/tnl/internal/testutil/managedcert"
	relayv1 "github.com/tnldotdev/tnl/pkg/api/control/private/relay/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

var _ NativePeerLegClaimClient = (*controlrelay.DirectClient)(nil)

func TestIntegrationNativePeerPairRelayClaimHTTPDirect(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	ctx, now := t.Context(), time.Now().UTC().Truncate(time.Microsecond)
	url := testutil.NewDisposablePostgresDatabaseURL(t, "native-peer-relay-claim")
	if err := controlstate.Migrate(ctx, url); err != nil {
		t.Fatal(err)
	}
	d, err := controlstate.Open(ctx, url, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	owner, err := controltest.Session(ctx, d, "example.test", time.Hour, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	identity, member := owner.Identity.Identity.ID, owner.Identity.Memberships[0]
	service, err := d.CreateServiceAt(ctx, member.TeamID, identity, "peer-claim", "peer-claim", controlstate.ServicePlacement{}, now, controlstate.ServiceMetadata{Protocol: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	team, err := d.GetTeam(ctx, identity, member.TeamID)
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := d.IssuePublisherEnrollment(ctx, controlstate.CreatePublisherEnrollmentRequest{
		Scope: controlstate.PublisherScope{TeamID: member.TeamID, Kind: "service", ServiceID: service.ID},
		Name:  "peer-claim", Kind: "installed", EditorID: identity, EditorMembershipID: member.ID,
		PolicyRevision: uint64(team.PolicyRevision), Now: now,
	})
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
	keys := map[string]ed25519.PrivateKey{}
	for _, id := range []string{"peer-a", "peer-b"} {
		runID, err := opaqueid.New(opaqueid.RelayRunPrefix)
		if err != nil {
			t.Fatal(err)
		}
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		lease, err := d.RegisterRelay(ctx, controlstate.RelayRegistration{RelayServiceID: id, RelayID: id, RelayRunID: runID,
			PeerSigningPublicKey: public, ProtocolVersion: tunnelv1.Version, RelayAddress: id + ".example.test:443",
			TLSServerName: id + ".example.test", InternalRelayAddress: "127.0.0.1:8443", ConnectionCapacity: 20, StreamCapacity: 20}, now, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		leases[id], keys[id] = lease, private
	}
	prepared, err := d.PrepareServiceRun(ctx, service.ID, publisher, "peer-claim", now, controlstate.ServiceMetadata{Protocol: "tcp", TrustRevision: 1})
	if err != nil {
		t.Fatal(err)
	}
	run, err := d.StartServiceRun(ctx, service.ID, prepared.RunID, prepared.RunNumber, publisher, now)
	if err != nil {
		t.Fatal(err)
	}
	managedcert.Install(t, d, prepared, run, now)
	for _, slot := range run.Connections {
		lease := leases[slot.RelayServiceID].RelayLeaseIdentity
		if _, err := d.ClaimServicePublisherConnection(ctx, slot.PublisherConnectionID, service.ID, run.RunID, run.RunNumber, slot.Revision, slot.Credential, lease, now); err != nil {
			t.Fatal(err)
		}
		if _, err := d.ReadyServicePublisherConnection(ctx, slot.PublisherConnectionID, run.RunID, run.RunNumber, slot.Revision, lease, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := d.HeartbeatServiceRun(ctx, service.ID, run.RunID, run.Token, now, controlstate.ServiceRunHealth{Healthy: true, StreamCapacity: 20}); err != nil {
		t.Fatal(err)
	}
	devicePublic, deviceKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	device, err := d.EnrollVisitorDevice(ctx, identity, devicePublic, now)
	if err != nil {
		t.Fatal(err)
	}
	relays := make([]controlv1.NativePeerPairRelay, 2)
	for i, slot := range run.Connections {
		lease := leases[slot.RelayServiceID]
		relays[i] = controlv1.NativePeerPairRelay{PublisherConnectionId: slot.PublisherConnectionID, AssignmentRevision: slot.Revision,
			RelayLease: controlv1.NativePeerRelayLease{RelayServiceId: lease.RelayServiceID, RelayId: lease.RelayID,
				RelayRunId: lease.RelayRunID, RelayLeaseRevision: int64(lease.RelayLeaseRevision)},
			RelayAddress: lease.RelayAddress, TlsServerName: lease.TLSServerName}
	}
	publicHandler, err := controlpublic.NewHandler(controlpublic.Config{}, d, d, nil)
	if err != nil {
		t.Fatal(err)
	}
	publicCall := func(path string, body any) *httptest.ResponseRecorder {
		t.Helper()
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(encoded))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+owner.AccessToken.String())
		w := httptest.NewRecorder()
		publicHandler.ServeHTTP(w, r)
		return w
	}
	selected := publicCall("/v1/services/"+service.ID+"/select-run", map[string]string{"device_id": device.ID})
	if selected.Code != http.StatusCreated {
		t.Fatalf("select pair run: %d %s", selected.Code, selected.Body.String())
	}
	var selection controlv1.ServiceSelection
	if err := json.Unmarshal(selected.Body.Bytes(), &selection); err != nil || selection.PairReady == nil {
		t.Fatal("missing pair selection", err)
	}
	request := controlv1.NativePeerPairRequest{ServiceRunId: run.RunID, RunNumber: run.RunNumber,
		PublisherIdentityId: publisher.ID, Subject: selection.Subject,
		Source: json.RawMessage(`{"kind":"device","device_id":"` + device.ID + `"}`),
		Action: "create", IdempotencyKey: "relay-claim", RequestedAt: now, ExpectedRelays: relays}
	message, err := controlv1.NativePeerPairProofMessage(service.ID, request)
	if err != nil {
		t.Fatal(err)
	}
	request.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(deviceKey, message))
	created := publicCall("/v1/services/"+service.ID+"/native-peer-pairs", request)
	if created.Code != http.StatusOK {
		t.Fatalf("prepare pair: %d %s", created.Code, created.Body.String())
	}
	var pair controlv1.NativePeerPair
	if err := json.Unmarshal(created.Body.Bytes(), &pair); err != nil || pair.Key == "" {
		t.Fatal("missing pair key", err)
	}
	secret := strings.Repeat("s", 32)
	secrets, err := serviceapi.NewBearerSecrets(secret, "")
	if err != nil {
		t.Fatal(err)
	}
	privateHandler, err := controlrelay.NewHandler(controlrelay.Config{Store: d, ClusterSecrets: secrets, LeaseDuration: time.Hour, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(privateHandler)
	t.Cleanup(server.Close)
	generated, err := relayv1.NewClientWithResponses(server.URL, relayv1.WithHTTPClient(server.Client()), relayv1.WithRequestEditorFn(func(_ context.Context, r *http.Request) error {
		r.Header.Set("Authorization", "Bearer "+secret)
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	httpClient, err := NewHTTPControlClient(generated)
	if err != nil {
		t.Fatal(err)
	}
	direct, err := controlrelay.NewDirectClient(controlrelay.DirectConfig{Store: d, LeaseDuration: time.Hour, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	source := netip.MustParseAddr("192.0.2.10")
	proofFor := func(slot int) (relayv1.RelayLease, tunnelv1.NativePairLegProof, []byte) {
		t.Helper()
		leg := relays[slot]
		assigned := leases[leg.RelayLease.RelayServiceId]
		proof := tunnelv1.NativePairLegProof{PairID: pair.PairId, DeliveryGeneration: pair.DeliveryGeneration,
			ServiceID: service.ID, ServiceRunID: run.RunID, RunNumber: run.RunNumber,
			PublisherIdentityID: publisher.ID, ConnectionSlot: slot,
			PublisherConnectionID: leg.PublisherConnectionId, AssignmentRevision: leg.AssignmentRevision,
			RelayServiceID: assigned.RelayServiceID, RelayID: assigned.RelayID,
			RelayRunID: assigned.RelayRunID, RelayLeaseRevision: assigned.RelayLeaseRevision,
			RequestedAt: now, Nonce: make([]byte, 32)}
		if _, err := rand.Read(proof.Nonce); err != nil {
			t.Fatal(err)
		}
		message, err := proof.Message()
		if err != nil {
			t.Fatal(err)
		}
		proof.Signature = ed25519.Sign(deviceKey, message)
		claimMessage, err := proof.RelayClaimMessage(source)
		if err != nil {
			t.Fatal(err)
		}
		wireLease := relayv1.RelayLease{RelayServiceId: assigned.RelayServiceID, RelayId: assigned.RelayID,
			RelayRunId: assigned.RelayRunID, RelayLeaseRevision: int64(assigned.RelayLeaseRevision), LeaseExpiresAt: assigned.LeaseExpiresAt}
		return wireLease, proof, ed25519.Sign(keys[assigned.RelayServiceID], claimMessage)
	}
	lease0, proof0, signed0 := proofFor(0)
	claimBody, err := relayv1.NewNativePeerPairLegClaimRequest(lease0, source, proof0, signed0)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := base64.RawURLEncoding.Strict().DecodeString(claimBody.ProofFrame)
	if err != nil {
		t.Fatal(err)
	}
	var written bytes.Buffer
	if err := tunnelv1.WriteNativePairLegProof(&written, proof0); err != nil || !bytes.Equal(frame, written.Bytes()) {
		t.Fatal("client did not send the exact handwritten proof frame", err)
	}
	path := func(pairID string, slot int) string {
		return fmt.Sprintf("/internal/v1/native-peer-pairs/%s/legs/%d/claim", pairID, slot)
	}
	call := func(pairID string, slot int, body any, bearer string) *httptest.ResponseRecorder {
		t.Helper()
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(http.MethodPost, path(pairID, slot), bytes.NewReader(encoded))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+bearer)
		r.Header.Set("X-Forwarded-For", source.String())
		w := httptest.NewRecorder()
		privateHandler.ServeHTTP(w, r)
		if w.Header().Get("Cache-Control") != "no-store" || bytes.Contains(w.Body.Bytes(), []byte(pair.Key)) && w.Code != http.StatusOK {
			t.Fatal("private response cache or key exposure", w.Code)
		}
		return w
	}
	assertRejected := func(name string, slot int, body relayv1.NativePeerPairLegClaimRequest, bearer string, expected int) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			w := call(pair.PairId, slot, body, bearer)
			if w.Code != expected {
				t.Fatalf("claim status = %d, want %d: %s", w.Code, expected, w.Body.String())
			}
		})
	}
	assertRejected("wrong bearer", 0, claimBody, "wrong", http.StatusUnauthorized)
	assertRejected("wrong path slot", 1, claimBody, secret, http.StatusBadRequest)
	if w := call("npp_0123456789ABCDEFGHIJKL", 0, claimBody, secret); w.Code != http.StatusBadRequest {
		t.Fatal("wrong path pair reached state", w.Code)
	}
	bad := claimBody
	bad.RelayLease.RelayLeaseRevision++
	assertRejected("wrong lease", 0, bad, secret, http.StatusBadRequest)
	staleProof := proof0
	staleProof.RelayLeaseRevision++
	message, err = staleProof.Message()
	if err != nil {
		t.Fatal(err)
	}
	staleProof.Signature = ed25519.Sign(deviceKey, message)
	staleMessage, err := staleProof.RelayClaimMessage(source)
	if err != nil {
		t.Fatal(err)
	}
	staleLease := lease0
	staleLease.RelayLeaseRevision++
	staleBody, err := relayv1.NewNativePeerPairLegClaimRequest(staleLease, source, staleProof, ed25519.Sign(keys[lease0.RelayServiceId], staleMessage))
	if err != nil {
		t.Fatal(err)
	}
	assertRejected("signed stale lease", 0, staleBody, secret, http.StatusConflict)
	assertParity := func(name string, lease relayv1.RelayLease, proof tunnelv1.NativePairLegProof, signature []byte) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			_, httpErr := httpClient.ClaimNativePeerPairLegFromAcceptedSocket(ctx, lease, source, proof, signature)
			_, directErr := direct.ClaimNativePeerPairLegFromAcceptedSocket(ctx, lease, source, proof, signature)
			var remote, local *serviceapi.ProblemError
			if !errors.As(httpErr, &remote) || !errors.As(directErr, &local) ||
				remote.Status != local.Status || remote.Code != local.Code || remote.Detail != local.Detail ||
				remote.Status != http.StatusConflict {
				t.Fatalf("HTTP/direct problems differ: %v, %v", httpErr, directErr)
			}
		})
	}
	assertParity("stale lease parity", staleLease, staleProof, ed25519.Sign(keys[lease0.RelayServiceId], staleMessage))
	bad = claimBody
	otherID := "peer-a"
	if lease0.RelayServiceId == otherID {
		otherID = "peer-b"
	}
	relayMessage, err := proof0.RelayClaimMessage(source)
	if err != nil {
		t.Fatal(err)
	}
	bad.RelaySignature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(keys[otherID], relayMessage))
	assertRejected("wrong process signature", 0, bad, secret, http.StatusConflict)
	assertParity("wrong process parity", lease0, proof0, ed25519.Sign(keys[otherID], relayMessage))
	bad = claimBody
	bad.ObservedSourceIp = "192.0.2.11"
	assertRejected("spoofed source with forwarded header", 0, bad, secret, http.StatusConflict)
	bad.ObservedSourceIp = "192.0.2.10%eth0"
	assertRejected("zoned source", 0, bad, secret, http.StatusBadRequest)
	bad.ObservedSourceIp = "192.0.2.10:80"
	assertRejected("source port", 0, bad, secret, http.StatusBadRequest)
	badProof := proof0
	badProof.Signature = make([]byte, ed25519.SignatureSize)
	badMessage, err := badProof.RelayClaimMessage(source)
	if err != nil {
		t.Fatal(err)
	}
	bad, err = relayv1.NewNativePeerPairLegClaimRequest(lease0, source, badProof, ed25519.Sign(keys[lease0.RelayServiceId], badMessage))
	if err != nil {
		t.Fatal(err)
	}
	assertRejected("tampered connector signature with valid process signature", 0, bad, secret, http.StatusConflict)
	bad = claimBody
	bad.ProofFrame = "invalid*base64"
	assertRejected("malformed proof encoding", 0, bad, secret, http.StatusBadRequest)
	bad.ProofFrame = base64.RawURLEncoding.EncodeToString(append(bytes.Clone(frame), 0))
	assertRejected("trailing framed bytes", 0, bad, secret, http.StatusBadRequest)
	bad.ProofFrame = base64.RawURLEncoding.EncodeToString([]byte{0, 0, 16, 1})
	assertRejected("oversized frame header", 0, bad, secret, http.StatusBadRequest)
	bad.ProofFrame = strings.Repeat("A", base64.RawURLEncoding.EncodedLen(tunnelv1.MaxNativePairLegProofBytes+4)+1)
	assertRejected("oversized proof encoding", 0, bad, secret, http.StatusBadRequest)
	var injected map[string]json.RawMessage
	if err := json.Unmarshal(frame[4:], &injected); err != nil {
		t.Fatal(err)
	}
	injected["observed_source_ip"] = json.RawMessage(`"192.0.2.10"`)
	payload, err := json.Marshal(injected)
	if err != nil {
		t.Fatal(err)
	}
	spoofed := make([]byte, 4, 4+len(payload))
	binary.BigEndian.PutUint32(spoofed, uint32(len(payload)))
	spoofed = append(spoofed, payload...)
	bad.ProofFrame = base64.RawURLEncoding.EncodeToString(spoofed)
	assertRejected("source injected into framed proof", 0, bad, secret, http.StatusBadRequest)
	encoded, err := json.Marshal(claimBody)
	if err != nil {
		t.Fatal(err)
	}
	tooLarge := httptest.NewRequest(http.MethodPost, path(pair.PairId, 0), strings.NewReader(strings.Repeat(" ", base64.RawURLEncoding.EncodedLen(tunnelv1.MaxNativePairLegProofBytes+4)+2048)+string(encoded)))
	tooLarge.Header.Set("Content-Type", "application/json")
	tooLarge.Header.Set("Authorization", "Bearer "+secret)
	tooLargeResponse := httptest.NewRecorder()
	privateHandler.ServeHTTP(tooLargeResponse, tooLarge)
	if tooLargeResponse.Code != http.StatusBadRequest || tooLargeResponse.Header().Get("Cache-Control") != "no-store" || bytes.Contains(tooLargeResponse.Body.Bytes(), []byte(pair.Key)) {
		t.Fatal("oversized claim reached state or exposed the key", tooLargeResponse.Code)
	}
	first, err := httpClient.ClaimNativePeerPairLegFromAcceptedSocket(ctx, lease0, source, proof0, signed0)
	if err != nil || first.Key != pair.Key || first.SourceIp != source.String() || first.ExpiresAt.After(pair.ExpiresAt) {
		t.Fatal("HTTP leg claim failed", err)
	}
	if first.String() == pair.Key || strings.Contains(fmt.Sprintf("%#v", first), pair.Key) {
		t.Fatal("claim formatting exposed key")
	}
	if _, err := direct.ClaimNativePeerPairLegFromAcceptedSocket(ctx, lease0, source, proof0, signed0); err == nil {
		t.Fatal("direct replay recovered key")
	}
	lease1, proof1, signed1 := proofFor(1)
	if _, err := direct.ClaimNativePeerPairLegFromAcceptedSocket(ctx, lease1, netip.MustParseAddr("192.0.2.11"), proof1, signed1); err == nil {
		t.Fatal("direct changed source recovered key")
	}
	second, err := direct.ClaimNativePeerPairLegFromAcceptedSocket(ctx, lease1, source, proof1, signed1)
	if err != nil || second.Key != first.Key || second.ConnectionSlot != 1 {
		t.Fatal("direct sibling relay claim failed", err)
	}
	assertRejected("HTTP replay", 0, claimBody, secret, http.StatusConflict)
	assertParity("replay parity", lease0, proof0, signed0)
	staleProof = proof0
	staleProof.DeliveryGeneration++
	message, err = staleProof.Message()
	if err != nil {
		t.Fatal(err)
	}
	staleProof.Signature = ed25519.Sign(deviceKey, message)
	staleMessage, err = staleProof.RelayClaimMessage(source)
	if err != nil {
		t.Fatal(err)
	}
	staleBody, err = relayv1.NewNativePeerPairLegClaimRequest(lease0, source, staleProof, ed25519.Sign(keys[lease0.RelayServiceId], staleMessage))
	if err != nil {
		t.Fatal(err)
	}
	assertRejected("signed stale pair generation", 0, staleBody, secret, http.StatusConflict)
	assertParity("stale pair parity", lease0, staleProof, ed25519.Sign(keys[lease0.RelayServiceId], staleMessage))
	if _, err := httpClient.ClaimNativePeerPairLegFromAcceptedSocket(ctx, lease1, source, proof1, signed1); err == nil {
		t.Fatal("HTTP sibling replay recovered key")
	}
	// replace the consumed pair with a new delivery generation for real
	// outer-session admission.
	request.Action = "replace"
	request.PreviousPairId = &pair.PairId
	request.PreviousGeneration = &pair.DeliveryGeneration
	request.IdempotencyKey = "accepted-socket"
	message, err = controlv1.NativePeerPairProofMessage(service.ID, request)
	if err != nil {
		t.Fatal(err)
	}
	request.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(deviceKey, message))
	created = publicCall("/v1/services/"+service.ID+"/native-peer-pairs", request)
	if created.Code != http.StatusOK || json.Unmarshal(created.Body.Bytes(), &pair) != nil || pair.Key == "" {
		t.Fatalf("prepare accepted-socket pair: %d %s", created.Code, created.Body.String())
	}
	lease0, proof0, _ = proofFor(0)
	lease1, proof1, _ = proofFor(1)
	wiredLease := func(lease relayv1.RelayLease) relayv1.RelayLease {
		key := base64.RawURLEncoding.EncodeToString(keys[lease.RelayServiceId].Public().(ed25519.PublicKey))
		lease.PeerSigningPublicKey = &key
		return lease
	}
	nativeOwner := &NativeConnectorAcceptor{SourceMode: NativeConnectorDirectSocket, CurrentLease: func() relayv1.RelayLease { return wiredLease(lease0) },
		SigningKey: keys[lease0.RelayServiceId], Claim: direct, Now: func() time.Time { return now }}
	acceptor, err := NewPublisherAcceptor(PublisherAcceptorConfig{Select: func(string) (PublisherConnectionController, *Registry, bool) {
		return nil, nil, false
	}, Native: nativeOwner})
	if err != nil {
		t.Fatal(err)
	}
	hello := tunnelv1.Message{Type: tunnelv1.Hello, ProtocolVersion: tunnelv1.Version, Role: tunnelv1.NativeConnector, NativePairLegProof: &proof0}
	for _, kind := range []string{"quic", "tls_yamux"} {
		t.Run("no source owner "+kind, func(t *testing.T) {
			previous := nativeOwner.SourceMode
			nativeOwner.SourceMode = NativeConnectorNoSource
			defer func() { nativeOwner.SourceMode = previous }()
			dialErr, acceptErr := peerNativeDial(t, kind, acceptor, hello, false)
			peerNativeAssertDenied(t, dialErr, acceptErr)
		})
		t.Run("missing accepted peer "+kind, func(t *testing.T) {
			dialErr, acceptErr := peerNativeDial(t, kind, acceptor, hello, true)
			peerNativeAssertDenied(t, dialErr, acceptErr)
		})
	}
	t.Run("no configured native owner", func(t *testing.T) {
		ordinary, err := NewPublisherAcceptor(PublisherAcceptorConfig{Select: func(string) (PublisherConnectionController, *Registry, bool) { return nil, nil, false }})
		if err != nil {
			t.Fatal(err)
		}
		dialErr, acceptErr := peerNativeDial(t, "quic", ordinary, hello, false)
		peerNativeAssertDenied(t, dialErr, acceptErr)
	})
	t.Run("wrong source hint", func(t *testing.T) {
		_, acceptErr := peerNativeDial(t, "quic", acceptor, hello, false, "192.0.2.10")
		if acceptErr == nil || !strings.Contains(acceptErr.Error(), "unknown field") {
			t.Fatal("untrusted connector source hint reached claim")
		}
	})
	t.Run("stale relay process", func(t *testing.T) {
		nativeOwner.CurrentLease = func() relayv1.RelayLease { l := wiredLease(lease0); l.RelayRunId = "previous-run"; return l }
		defer func() { nativeOwner.CurrentLease = func() relayv1.RelayLease { return wiredLease(lease0) } }()
		dialErr, acceptErr := peerNativeDial(t, "quic", acceptor, hello, false)
		peerNativeAssertDenied(t, dialErr, acceptErr)
	})
	t.Run("wrong signing key", func(t *testing.T) {
		nativeOwner.SigningKey = keys[lease1.RelayServiceId]
		defer func() { nativeOwner.SigningKey = keys[lease0.RelayServiceId] }()
		dialErr, acceptErr := peerNativeDial(t, "tls_yamux", acceptor, hello, false)
		peerNativeAssertDenied(t, dialErr, acceptErr)
	})
	t.Run("wrong pair", func(t *testing.T) {
		bad := proof0
		bad.PairID = "npp_0123456789ABCDEFGHIJKL"
		msg, err := bad.Message()
		if err != nil {
			t.Fatal(err)
		}
		bad.Signature = ed25519.Sign(deviceKey, msg)
		dialErr, acceptErr := peerNativeDial(t, "quic", acceptor, tunnelv1.Message{Type: tunnelv1.Hello, ProtocolVersion: tunnelv1.Version, Role: tunnelv1.NativeConnector, NativePairLegProof: &bad}, false)
		peerNativeAssertDenied(t, dialErr, acceptErr)
	})
	for _, test := range []struct {
		kind  string
		lease relayv1.RelayLease
		proof tunnelv1.NativePairLegProof
	}{
		{"quic", lease0, proof0}, {"tls_yamux", lease1, proof1},
	} {
		t.Run("accepted "+test.kind, func(t *testing.T) {
			nativeOwner.CurrentLease = func() relayv1.RelayLease { return wiredLease(test.lease) }
			nativeOwner.SigningKey = keys[test.lease.RelayServiceId]
			leg := test.proof
			acceptedHello := tunnelv1.Message{Type: tunnelv1.Hello, ProtocolVersion: tunnelv1.Version, Role: tunnelv1.NativeConnector, NativePairLegProof: &leg}
			session, done, _ := peerNativeHold(t, test.kind, acceptor, acceptedHello)
			dialErr, acceptErr := peerNativeDial(t, test.kind, acceptor, acceptedHello, false)
			peerNativeAssertDenied(t, dialErr, acceptErr)
			select {
			case <-session.Done():
				t.Fatal("replay closed the accepted native session")
			default:
			}
			_ = session.Close()
			if err := relayAwait(t, done); err != nil {
				t.Fatal(err)
			}
		})
	}
}
