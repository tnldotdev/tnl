package stream

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/connector/workload"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/visitorsubject"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func pairHintFixture() *controlv1.NativePeerPairReady {
	return &controlv1.NativePeerPairReady{PublisherIdentityId: "pub_" + strings.Repeat("P", 22), Relays: []controlv1.NativePeerPairRelay{
		{PublisherConnectionId: "pc_" + strings.Repeat("A", 22), AssignmentRevision: 1, RelayAddress: "a.example.test:443", TlsServerName: "a.example.test", RelayLease: controlv1.NativePeerRelayLease{RelayServiceId: "relay-a", RelayId: "relay-1", RelayRunId: "run-1", RelayLeaseRevision: 2}},
		{PublisherConnectionId: "pc_" + strings.Repeat("B", 22), AssignmentRevision: 2, RelayAddress: "b.example.test:443", TlsServerName: "b.example.test", RelayLease: controlv1.NativePeerRelayLease{RelayServiceId: "relay-b", RelayId: "relay-2", RelayRunId: "run-2", RelayLeaseRevision: 3}},
	}}
}

func pairResponse(run Run, body controlv1.NativePeerPairRequest) controlv1.NativePeerPair {
	return controlv1.NativePeerPair{PairId: "npp_" + strings.Repeat("Q", 22), DeliveryId: base64.RawURLEncoding.EncodeToString([]byte("binary-header-16")),
		DeliveryGeneration: 1, Key: base64.RawURLEncoding.EncodeToString(slices.Repeat([]byte{42}, 32)),
		ServiceId: run.ServiceID, ServiceRunId: run.ServiceRunID, RunNumber: int64(run.RunNumber), PublisherIdentityId: run.PairReady.PublisherIdentityId,
		Subject: body.Subject, Relays: slices.Clone(body.ExpectedRelays), ExpiresAt: time.Now().Add(35 * time.Second)}
}

func TestDevicePeerPreparationRetriesLostHTTPResponseWithSameProof(t *testing.T) {
	identity, device := connectorID(t, opaqueid.IdentityPrefix), connectorID(t, opaqueid.VisitorDevicePrefix)
	config, selected := selectionFixture()
	selected.PairReady = pairHintFixture()
	selected.Subject = tunnelv1.VisitorSubject{Kind: tunnelv1.VisitorHumanDevice, IdentityID: identity, DeviceID: device}
	var first controlv1.NativePeerPairRequest
	var calls atomic.Int32
	var signer Signer
	control, _ := adapterFixture(t, identity, func(_ *clientstate.Store, w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/visitor-devices":
			var body controlv1.EnrollVisitorDeviceJSONRequestBody
			_ = json.NewDecoder(r.Body).Decode(&body)
			_ = json.NewEncoder(w).Encode(controlv1.VisitorDevice{Id: device, IdentityId: identity, PublicKey: body.PublicKey, CreatedAt: time.Now()})
		case strings.HasSuffix(r.URL.Path, "/select-run"):
			_ = json.NewEncoder(w).Encode(controlv1.ServiceSelection{ServiceId: selected.ServiceID, ServiceRunId: selected.ServiceRunID,
				RunNumber: int64(selected.RunNumber), Subject: visitorsubject.Wire(selected.Subject), PairReady: selected.PairReady,
				Protocol: controlv1.ServiceProtocol(selected.Protocol), TrustRevision: selected.TrustRevision, Endpoint: selected.Endpoint, ExpiresAt: selected.ValidUntil})
		case r.URL.Path == "/v1/visitor-tokens":
			_ = json.NewEncoder(w).Encode(selected.Permission)
		case strings.HasSuffix(r.URL.Path, "/native-peer-pairs"):
			var body controlv1.NativePeerPairRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			message, err := controlv1.NativePeerPairProofMessage(selected.ServiceID, body)
			signature, decodeErr := base64.RawURLEncoding.DecodeString(body.Signature)
			if err != nil || decodeErr != nil || !ed25519.Verify(signer.PublicKey, message, signature) ||
				body.Action != "create" || !visitorsubject.Equal(body.Subject, selected.Subject) ||
				!slices.Equal(body.ExpectedRelays, selected.PairReady.Relays) || !strings.Contains(string(body.Source), device) ||
				strings.Contains(string(body.Source), "credential") {
				t.Error("device pair request did not bind the exact signed source and slots")
			}
			if calls.Add(1) == 1 {
				first = body
				w.WriteHeader(http.StatusServiceUnavailable) // the pair was saved; its response was lost.
				_, _ = w.Write([]byte(`{"code":"unavailable","detail":"retry","status":503,"title":"unavailable"}`))
				return
			}
			if body.Signature != first.Signature || body.IdempotencyKey != first.IdempotencyKey || !body.RequestedAt.Equal(first.RequestedAt) {
				t.Error("uncertain create signed a different request")
			}
			_ = json.NewEncoder(w).Encode(pairResponse(selected, body))
		default:
			t.Error("unexpected control request", r.URL.Path)
		}
	})
	var err error
	signer, err = control.ConnectorSigner(t.Context(), identity)
	if err != nil {
		t.Fatal(err)
	}
	config.Control = control
	ctx, cancel := context.WithCancelCause(t.Context())
	defer cancel(nil)
	p, err := prepareSelection(ctx, config, cancel, &peerPreparation{signer: signer, call: control.(*controlAdapter).preparePeer})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if peer, err := p.peerCurrent(); err != nil || peer.pair.PairId == "" || calls.Load() != 2 {
		t.Fatal("device did not recover the same prepared pair", err)
	}
	for range 100 {
		if _, err := p.peerCurrent(); err != nil {
			t.Fatal(err)
		}
		if _, err := p.current(); !errors.Is(err, ErrServiceConnection) {
			t.Fatal("healthy pair admitted an ingress socket", err)
		}
	}
	if calls.Load() != 2 || fmt.Sprintf("%+v", p.peer) != "prepared native peer pair" {
		t.Fatal("socket read contacted control or printed the pair key")
	}
}

func TestWorkloadPeerPreparationKeepsCredentialInsideHTTPAdapter(t *testing.T) {
	config, run := selectionFixture()
	run.PairReady = pairHintFixture()
	id := "wls_" + strings.Repeat("W", 22)
	run.Subject = tunnelv1.VisitorSubject{Kind: tunnelv1.VisitorWorkloadSession, WorkloadSessionID: id}
	credential := "wlc_" + strings.Repeat("s", 43)
	var client *workload.Client
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/run") {
			if r.Header.Get("Authorization") != "Bearer "+credential {
				t.Error("selection lost workload source")
			}
			_ = json.NewEncoder(w).Encode(controlv1.ServiceSelection{ServiceId: run.ServiceID, ServiceRunId: run.ServiceRunID,
				RunNumber: int64(run.RunNumber), Subject: visitorsubject.Wire(run.Subject), PairReady: run.PairReady,
				Protocol: controlv1.ServiceProtocol(run.Protocol), TrustRevision: run.TrustRevision, Endpoint: run.Endpoint, ExpiresAt: run.ValidUntil})
			return
		}
		if r.URL.Path == "/v1/visitor-tokens" {
			_ = json.NewEncoder(w).Encode(run.Permission)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/native-peer-pairs") {
			calls.Add(1)
			var body controlv1.NativePeerPairRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			message, err := controlv1.NativePeerPairProofMessage(run.ServiceID, body)
			signature, decodeErr := base64.RawURLEncoding.DecodeString(body.Signature)
			if err != nil || decodeErr != nil || !ed25519.Verify(client.PublicKey(), message, signature) ||
				r.Header.Get("Authorization") != "" || !strings.Contains(string(body.Source), credential) ||
				!visitorsubject.Equal(body.Subject, run.Subject) {
				t.Error("workload pair lost its source or sent a control bearer")
			}
			_ = json.NewEncoder(w).Encode(pairResponse(run, body))
			return
		}
		_ = json.NewEncoder(w).Encode(authorityv1.WorkloadSession{Id: id, Subject: visitorsubject.Wire(run.Subject),
			Credential: credential, ServiceIds: []string{run.ServiceID}, Binding: strings.Repeat("b", 64),
			TeamId: "tm_" + strings.Repeat("T", 22), ProjectKey: "store", Workload: "storefront", Provider: controlv1.WorkloadFly,
			LeaseExpiresAt: time.Now().Add(90 * time.Second), ExpiresAt: time.Now().Add(time.Hour)})
	}))
	defer server.Close()
	var err error
	client, err = workload.New(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.Exchange(t.Context(), "tm_"+strings.Repeat("T", 22), "store", strings.Repeat("a", 64), "storefront", "assertion", nil); err != nil {
		t.Fatal(err)
	}
	owner := &workloadControl{client: client, subject: run.Subject}
	signer, err := owner.signer(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	config.Control = &selectionControl{resolve: func(ctx context.Context) (Run, error) { return owner.resolve(ctx, run.ServiceID) }}
	ctx, cancel := context.WithCancelCause(t.Context())
	defer cancel(nil)
	p, err := prepareSelection(ctx, config, cancel, &peerPreparation{signer: signer, call: owner.preparePeer})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if _, err := p.peerCurrent(); err != nil || calls.Load() != 1 {
		t.Fatal("workload pair was not prepared", err)
	}
	if _, err := p.current(); !errors.Is(err, ErrServiceConnection) || calls.Load() != 1 {
		t.Fatal("workload pair admitted ingress or contacted control on socket arrival", err)
	}
	if strings.Contains(fmt.Sprintf("%v %+v %#v", signer, p.peer, p), credential) || strings.Contains(fmt.Sprintf("%v", signer), base64.RawURLEncoding.EncodeToString(client.PublicKey())) {
		t.Fatal("workload credential leaked into preparation diagnostics")
	}
}

func TestPeerPreparationRejectsMalformedDeliveryAndFencesStaleSelection(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*controlv1.NativePeerPair)
	}{
		{"delivery id", func(p *controlv1.NativePeerPair) { p.DeliveryId = p.PairId }},
		{"key", func(p *controlv1.NativePeerPair) { p.Key = "not-a-32-byte-key" }},
		{"relays", func(p *controlv1.NativePeerPair) { p.Relays[0].AssignmentRevision++ }},
		{"subject", func(p *controlv1.NativePeerPair) { p.Subject.DeviceId = new("vdev_" + strings.Repeat("X", 22)) }},
		{"expiry", func(p *controlv1.NativePeerPair) { p.ExpiresAt = time.Now().Add(-time.Second) }},
		{"exceeds run lease", func(p *controlv1.NativePeerPair) { p.ExpiresAt = time.Now().Add(2 * time.Minute) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config, run, owner := peerUnitFixture(t)
			owner.call = func(_ context.Context, _ string, _ tunnelv1.VisitorSubject, body controlv1.NativePeerPairRequest) (controlv1.NativePeerPair, error) {
				pair := pairResponse(run, body)
				tc.change(&pair)
				return pair, nil
			}
			ctx, stop := context.WithCancelCause(t.Context())
			defer stop(nil)
			if p, err := prepareSelection(ctx, config, stop, owner); err == nil {
				p.Close()
				t.Fatal("malformed delivery became usable")
			}
		})
	}
	config, run, owner := peerUnitFixture(t)
	owner.call = func(_ context.Context, _ string, _ tunnelv1.VisitorSubject, body controlv1.NativePeerPairRequest) (controlv1.NativePeerPair, error) {
		return pairResponse(run, body), nil
	}
	ctx, stop := context.WithCancelCause(t.Context())
	defer stop(nil)
	p, err := prepareSelection(ctx, config, stop, owner)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	run.PairReady = clonePairHint(run.PairReady)
	run.PairReady.Relays[0].AssignmentRevision++
	config.Control = &selectionControl{resolve: func(context.Context) (Run, error) { return run, nil }}
	p.config.Control = config.Control
	if err := p.refresh(ctx); err == nil {
		t.Fatal("changed assignment retained old pair")
	}
	if _, err := p.peerCurrent(); err == nil {
		t.Fatal("stale pair remained usable")
	}
	if _, err := p.current(); err == nil {
		t.Fatal("required peer preparation fell back to ingress")
	}
}

func TestPeerPreparationRevokedDeviceDoesNotRetryOrFallBack(t *testing.T) {
	identity := connectorID(t, opaqueid.IdentityPrefix)
	device := connectorID(t, opaqueid.VisitorDevicePrefix)
	config, run := selectionFixture()
	run.PairReady = pairHintFixture()
	run.Subject = tunnelv1.VisitorSubject{Kind: tunnelv1.VisitorHumanDevice, IdentityID: identity, DeviceID: device}
	var calls atomic.Int32
	control, _ := adapterFixture(t, identity, func(_ *clientstate.Store, w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/visitor-devices" {
			var body controlv1.EnrollVisitorDeviceJSONRequestBody
			_ = json.NewDecoder(r.Body).Decode(&body)
			_ = json.NewEncoder(w).Encode(controlv1.VisitorDevice{Id: device, IdentityId: identity, PublicKey: body.PublicKey, CreatedAt: time.Now()})
			return
		}
		calls.Add(1)
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"code":"forbidden","detail":"revoked","status":403,"title":"forbidden"}`))
	})
	signer, err := control.ConnectorSigner(t.Context(), identity)
	if err != nil {
		t.Fatal(err)
	}
	config.Control = &selectionControl{resolve: func(context.Context) (Run, error) { return run, nil }}
	ctx, stop := context.WithCancelCause(t.Context())
	defer stop(nil)
	p, err := prepareSelection(ctx, config, stop, &peerPreparation{signer: signer, call: control.(*controlAdapter).preparePeer})
	if p != nil || err == nil || errors.Is(err, clientcontrol.ErrUnavailable) || calls.Load() != 1 {
		t.Fatal("revoked source retried or admitted an unprepared pair", err)
	}
}

func TestPeerPreparationRejectsHintWithDuplicateRelayOrMissingLease(t *testing.T) {
	for _, mutate := range []func(*controlv1.NativePeerPairReady){
		func(h *controlv1.NativePeerPairReady) {
			h.Relays[1].RelayLease.RelayServiceId = h.Relays[0].RelayLease.RelayServiceId
		},
		func(h *controlv1.NativePeerPairReady) { h.Relays[1].RelayLease.RelayLeaseRevision = 0 },
		func(h *controlv1.NativePeerPairReady) {
			h.Relays[1].PublisherConnectionId = h.Relays[0].PublisherConnectionId
		},
	} {
		config, run, owner := peerUnitFixture(t)
		mutate(run.PairReady)
		config.Control = &selectionControl{resolve: func(context.Context) (Run, error) { return run, nil }}
		var calls atomic.Int32
		owner.call = func(context.Context, string, tunnelv1.VisitorSubject, controlv1.NativePeerPairRequest) (controlv1.NativePeerPair, error) {
			calls.Add(1)
			return controlv1.NativePeerPair{}, nil
		}
		ctx, stop := context.WithCancelCause(t.Context())
		if p, err := prepareSelection(ctx, config, stop, owner); err == nil {
			p.Close()
			t.Fatal("invalid relay hint signed a pair")
		}
		stop(nil)
		if calls.Load() != 0 {
			t.Fatal("invalid hint reached control")
		}
	}
}

func peerUnitFixture(t *testing.T) (Config, Run, *peerPreparation) {
	t.Helper()
	config, run := selectionFixture()
	run.PairReady = pairHintFixture()
	run.Subject = tunnelv1.VisitorSubject{Kind: tunnelv1.VisitorHumanDevice, IdentityID: "ident_" + strings.Repeat("I", 22), DeviceID: "vdev_" + strings.Repeat("D", 22)}
	public, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	config.Control = &selectionControl{resolve: func(context.Context) (Run, error) { return run, nil }}
	return config, run, &peerPreparation{signer: Signer{Subject: run.Subject, PublicKey: public, Sign: func(message []byte) []byte { return ed25519.Sign(key, message) }}}
}

func TestPeerPreparationBackgroundRenewalAndJoinedCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		config, run, owner := peerUnitFixture(t)
		var calls atomic.Int32
		started, exited, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
		owner.call = func(ctx context.Context, _ string, _ tunnelv1.VisitorSubject, body controlv1.NativePeerPairRequest) (controlv1.NativePeerPair, error) {
			n := calls.Add(1)
			pair := pairResponse(run, body)
			pair.ExpiresAt = time.Now().Add(18 * time.Second)
			if n == 2 {
				if body.Action != "renew" || body.PreviousPairId == nil || *body.PreviousPairId != pair.PairId {
					t.Error("background work did not sign a renewal")
				}
				close(started)
				<-ctx.Done()
				close(exited)
				<-release
			}
			return pair, nil
		}
		ctx, stop := context.WithCancelCause(t.Context())
		defer stop(nil)
		p, err := prepareSelection(ctx, config, stop, owner)
		if err != nil {
			t.Fatal(err)
		}
		for range 100 {
			if _, err := p.peerCurrent(); err != nil {
				t.Fatal(err)
			}
		}
		if calls.Load() != 1 {
			t.Fatal("socket arrival called control")
		}
		time.Sleep(2*time.Second + time.Millisecond)
		synctest.Wait()
		if calls.Load() != 1 {
			t.Fatal("healthy pair was unnecessarily replaced")
		}
		time.Sleep(2 * time.Second)
		<-started
		closed := make(chan struct{})
		go func() { p.Close(); close(closed) }()
		<-exited
		synctest.Wait()
		select {
		case <-closed:
			t.Fatal("canceled worker was not joined")
		default:
		}
		close(release)
		<-closed
		if _, err := p.peerCurrent(); err == nil {
			t.Fatal("canceled worker revived the pair")
		}
	})
}

func TestPeerPreparationUncertainRenewalRetriesExactProof(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		config, run, owner := peerUnitFixture(t)
		var calls atomic.Int32
		var lost controlv1.NativePeerPairRequest
		owner.call = func(_ context.Context, _ string, _ tunnelv1.VisitorSubject, body controlv1.NativePeerPairRequest) (controlv1.NativePeerPair, error) {
			pair := pairResponse(run, body)
			pair.ExpiresAt = time.Now().Add(18 * time.Second)
			switch calls.Add(1) {
			case 1:
				if body.Action != "create" {
					t.Error("initial pair was not created")
				}
			case 2:
				lost = body
				return controlv1.NativePeerPair{}, clientcontrol.ErrUnavailable
			case 3:
				if body.Action != "renew" || body.IdempotencyKey != lost.IdempotencyKey || body.Signature != lost.Signature || !body.RequestedAt.Equal(lost.RequestedAt) {
					t.Error("uncertain renewal changed its signed request")
				}
			}
			return pair, nil
		}
		ctx, stop := context.WithCancelCause(t.Context())
		defer stop(nil)
		p, err := prepareSelection(ctx, config, stop, owner)
		if err != nil {
			t.Fatal(err)
		}
		defer p.Close()
		time.Sleep(4*time.Second + time.Millisecond)
		synctest.Wait()
		if calls.Load() != 2 {
			t.Fatal("renewal did not run in the background")
		}
		if _, err := p.peerCurrent(); err == nil {
			t.Fatal("failed renewal did not fence the old pair")
		}
		if _, err := p.current(); err == nil {
			t.Fatal("failed required renewal fell back to ingress")
		}
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if peer, err := p.peerCurrent(); err != nil || calls.Load() != 3 || peer.pair.PairId == "" {
			t.Fatal("exact retry did not recover the pair", err)
		}
	})
}

func TestPeerPreparationAcceptsNarrowerRenewalAndJoinsAtItsDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		config, run, owner := peerUnitFixture(t)
		var calls atomic.Int32
		var cached controlv1.NativePeerPair
		blocked, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
		owner.call = func(ctx context.Context, _ string, _ tunnelv1.VisitorSubject, body controlv1.NativePeerPairRequest) (controlv1.NativePeerPair, error) {
			pair := pairResponse(run, body)
			switch calls.Add(1) {
			case 1:
				pair.ExpiresAt = time.Now().Add(18 * time.Second)
				cached = pair
			case 2:
				if body.Action != "renew" || body.PreviousPairId == nil || *body.PreviousPairId != cached.PairId {
					t.Error("narrowing response did not follow a signed renewal")
				}
				pair.ExpiresAt = time.Now().Add(3 * time.Second)
			case 3:
				close(blocked)
				<-ctx.Done()
				close(canceled)
				<-release
				// a late stale response must not reinstall the original deadline.
				return cached, nil
			default:
				t.Error("worker made a request after the narrowed deadline")
			}
			return pair, nil
		}
		ctx, stop := context.WithCancelCause(t.Context())
		defer stop(nil)
		p, err := prepareSelection(ctx, config, stop, owner)
		if err != nil {
			t.Fatal(err)
		}
		original, err := p.peerCurrent()
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(4*time.Second + time.Millisecond)
		synctest.Wait()
		narrow, err := p.peerCurrent()
		if err != nil || calls.Load() != 2 || !narrow.until.Before(original.until) ||
			narrow.pair.PairId != original.pair.PairId || narrow.pair.DeliveryId != original.pair.DeliveryId ||
			narrow.pair.Key != original.pair.Key || narrow.pair.DeliveryGeneration != original.pair.DeliveryGeneration ||
			!visitorsubject.Same(narrow.pair.Subject, original.pair.Subject) || !slices.Equal(narrow.pair.Relays, original.pair.Relays) {
			t.Fatal("valid shorter authority deadline did not replace the cached pair", err)
		}
		for range 100 {
			if _, err := p.current(); !errors.Is(err, ErrServiceConnection) {
				t.Fatal("narrowed pair admitted an ingress socket", err)
			}
			if _, err := p.peerCurrent(); err != nil {
				t.Fatal(err)
			}
		}
		if calls.Load() != 2 {
			t.Fatal("socket reads contacted control")
		}
		time.Sleep(2 * time.Second)
		<-blocked
		time.Sleep(time.Second)
		<-canceled
		if !errors.Is(context.Cause(ctx), ErrSelectionExpired) || !original.until.After(time.Now()) {
			t.Fatal("narrowed deadline did not cancel the owner before its old deadline")
		}
		if _, err := p.current(); err == nil {
			t.Fatal("ingress read revived the expired pair")
		}
		if _, err := p.peerCurrent(); err == nil {
			t.Fatal("peer read revived the expired pair")
		}
		closed := make(chan struct{})
		go func() { p.Close(); close(closed) }()
		synctest.Wait()
		select {
		case <-closed:
			t.Fatal("close returned before the canceled worker finished")
		default:
		}
		close(release)
		<-closed
		if _, err := p.peerCurrent(); err == nil || calls.Load() != 3 {
			t.Fatal("late stale response revived closed preparation", err)
		}
	})
}

func TestPeerPreparationExpiredUncertainProofStopsWithoutRekey(t *testing.T) {
	for _, previouslyAdmitted := range []bool{false, true} {
		t.Run(fmt.Sprintf("prior-pair-%t", previouslyAdmitted), func(t *testing.T) {
			_, run, owner := peerUnitFixture(t)
			var calls atomic.Int32
			owner.call = func(context.Context, string, tunnelv1.VisitorSubject, controlv1.NativePeerPairRequest) (controlv1.NativePeerPair, error) {
				calls.Add(1)
				return controlv1.NativePeerPair{}, nil
			}
			pending := &controlv1.NativePeerPairRequest{ServiceRunId: run.ServiceRunID, RunNumber: int64(run.RunNumber),
				PublisherIdentityId: run.PairReady.PublisherIdentityId, ExpectedRelays: slices.Clone(run.PairReady.Relays),
				RequestedAt: time.Now().Add(-peerProofRetryWindow)}
			p := &preparedSelection{peerOwner: owner, pendingPeer: pending}
			if previouslyAdmitted {
				p.peer = &preparedPeer{runID: run.ServiceRunID, number: run.RunNumber, hint: clonePairHint(run.PairReady), until: run.ValidUntil}
			}
			for range 2 {
				if err := p.refreshPeer(t.Context(), run); !errors.Is(err, errPeerProofExpired) || selectionRetryable(err) {
					t.Fatal("expired uncertain proof was not a terminal stop", err)
				}
			}
			if calls.Load() != 0 || p.pendingPeer != pending || p.createKey != "" {
				t.Fatal("expired proof contacted control or minted a replacement key")
			}
		})
	}
}
