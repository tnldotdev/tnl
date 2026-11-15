package state

import (
	"bytes"
	"errors"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestIntegrationServiceRecovery(t *testing.T) {
	f, _ := guestAuthorityFixture(t, true)
	database, now := f.database, f.now
	metrics := observability.New("control")
	database.Instrument(metrics)
	ingress, err := database.RegisterIngress(t.Context(), IngressRegistration{
		IngressID: "recovery", IngressRunID: mustOpaqueID(t, opaqueid.IngressRunPrefix), ProtocolVersion: 1,
		HTTPS: true, ConnectionCapacity: 100, IngressPoolID: PrimaryIngressPoolID,
	}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	previous := f.run.Connections
	for index, slot := range previous {
		if _, err := database.DisconnectServicePublisherConnection(t.Context(), slot.PublisherConnectionID, f.run.RunID,
			f.run.RunNumber, slot.Revision, f.leases[slot.RelayServiceID].RelayLeaseIdentity, now.Add(time.Duration(index+1)*time.Second), true); err != nil {
			t.Fatal(err)
		}
	}
	var recoveryEpisodeID int64
	var openedAt time.Time
	if err := database.pool.QueryRow(t.Context(), `SELECT id, opened_at FROM control.service_recovery_episodes
		WHERE service_run_id=$1 AND state='open'`, f.run.RunID).Scan(&recoveryEpisodeID, &openedAt); err != nil {
		t.Fatal(err)
	}
	replenishAt := now.Add(3 * time.Second)
	replenished, err := f.heartbeat(replenishAt)
	if err != nil {
		t.Fatal(err)
	}
	for index, connection := range replenished.Connections {
		if connection.State != "assigned" ||
			connection.Revision != previous[index].Revision+1 ||
			connection.PublisherConnectionID == previous[index].PublisherConnectionID {
			t.Fatalf("replenished slot %d = %#v", index, connection)
		}
	}
	recoveredAt := replenishAt.Add(2 * time.Second)
	connection := replenished.Connections[0]
	lease := f.leases[connection.RelayServiceID].RelayLeaseIdentity
	if _, err := database.ClaimServicePublisherConnection(f.ctx, connection.PublisherConnectionID, f.service.ID, f.run.RunID,
		f.run.RunNumber, connection.Revision, connection.Credential, f.guest.SourceIP, lease, recoveredAt); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ReadyServicePublisherConnection(f.ctx, connection.PublisherConnectionID, f.run.RunID,
		f.run.RunNumber, connection.Revision, lease, recoveredAt); err != nil {
		t.Fatal(err)
	}
	visitor := mustOpaqueID(t, opaqueid.VisitorConnectionPrefix)
	admission, err := readIngressServiceRun(t.Context(), database, ingress.IngressLeaseIdentity, f.service.ID, f.run.RunID, recoveredAt)
	if err != nil || admission.RecoveryEpisodeID == nil || *admission.RecoveryEpisodeID != recoveryEpisodeID ||
		len(admission.Relays) != 1 || admission.RunID != f.run.RunID || admission.RunNumber != f.run.RunNumber {
		t.Fatalf("recovered service admission = %#v, %v", admission, err)
	}
	evidence := recoverySourceEvidence(t, admission, visitor, recoveredAt)
	observedAt := recoveredAt.Add(750 * time.Millisecond)
	wantSeconds := observedAt.Sub(openedAt).Seconds()
	ref := ServiceRunReference{ServiceID: f.service.ID, RunID: f.run.RunID, RunNumber: f.run.RunNumber}
	observation, err := database.ObserveServiceRecovery(t.Context(), ingress.IngressLeaseIdentity, ref, visitor, uint64(recoveryEpisodeID), observedAt, evidence, observedAt)
	if err != nil || observation.ObservedSeconds != wantSeconds {
		t.Fatalf("recovery observation = %#v, %v", observation, err)
	}
	repeated, err := database.ObserveServiceRecovery(t.Context(), ingress.IngressLeaseIdentity, ref, visitor, uint64(recoveryEpisodeID), observedAt, evidence, observedAt.Add(time.Second))
	if err != nil || !reflect.DeepEqual(repeated, observation) {
		t.Fatalf("observation replay = %#v, %v", repeated, err)
	}
	// several ingress deliveries may race, or retry after a committed reply was
	// lost. all return the original measurement without recounting it.
	concurrent := make(chan error, 4)
	for range 4 {
		go func() {
			got, err := database.ObserveServiceRecovery(t.Context(), ingress.IngressLeaseIdentity, ref, visitor,
				uint64(recoveryEpisodeID), observedAt, evidence, observedAt.Add(2*time.Second))
			if err == nil && !reflect.DeepEqual(got, observation) {
				err = errors.New("replay changed the committed recovery")
			}
			concurrent <- err
		}()
	}
	for range 4 {
		if err := <-concurrent; err != nil {
			t.Error(err)
		}
	}
	var count, half, one, ten, infinite int64
	var sum float64
	if err := database.pool.QueryRow(t.Context(), `
		SELECT observation_count, observation_sum_seconds, bucket_le_0_5, bucket_le_1, bucket_le_10, bucket_le_120
		FROM control.service_recovery_histogram WHERE id = 1
	`).Scan(&count, &sum, &half, &one, &ten, &infinite); err != nil {
		t.Fatal(err)
	}
	if count != 1 || sum != wantSeconds || half != 0 || one != 0 || ten != 1 || infinite != 1 {
		t.Fatalf("recovery histogram = %d/%f, buckets %d/%d/%d/%d", count, sum, half, one, ten, infinite)
	}
	families, err := metrics.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var recoveryCount uint64
	var replacements float64
	for _, family := range families {
		switch family.GetName() {
		case "tnl_control_service_recovery_duration_seconds":
			recoveryCount = family.Metric[0].GetHistogram().GetSampleCount()
		case "tnl_control_connection_assignments_replaced_total":
			for _, metric := range family.Metric {
				replacements += metric.GetCounter().GetValue()
			}
		}
	}
	if recoveryCount != 1 || replacements != 2 {
		t.Fatalf("committed recovery metrics: observations=%d replacements=%g", recoveryCount, replacements)
	}
	var visitors int
	if err := database.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.public_service_visitors WHERE service_id=$1`, f.service.ID).Scan(&visitors); err != nil || visitors != 0 {
		t.Fatal("HTTP recovery wrote visitor coordination rows", visitors, err)
	}
}

func TestIntegrationServiceRecoveryRequiresExactAdmissionAndCurrentLease(t *testing.T) {
	f, _ := guestAuthorityFixture(t, true)
	ctx := t.Context()
	ingress, err := f.database.RegisterIngress(ctx, IngressRegistration{
		IngressID: "recovery-binding", IngressRunID: mustOpaqueID(t, opaqueid.IngressRunPrefix),
		ProtocolVersion: 1, HTTPS: true, ConnectionCapacity: 100, IngressPoolID: PrimaryIngressPoolID,
	}, f.now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	slot := f.run.Connections[0]
	if _, err := f.database.DisconnectServicePublisherConnection(ctx, slot.PublisherConnectionID, f.run.RunID,
		f.run.RunNumber, slot.Revision, f.leases[slot.RelayServiceID].RelayLeaseIdentity, f.now.Add(time.Second), true); err != nil {
		t.Fatal(err)
	}
	visitor := mustOpaqueID(t, opaqueid.VisitorConnectionPrefix)
	at := f.now.Add(2 * time.Second)
	admission, err := readIngressServiceRun(ctx, f.database, ingress.IngressLeaseIdentity, f.service.ID, f.run.RunID, at)
	if err != nil || admission.RecoveryEpisodeID == nil {
		t.Fatal("surviving relay did not retain the open recovery episode", err)
	}
	evidence := recoverySourceEvidence(t, admission, visitor, at)
	ref := ServiceRunReference{ServiceID: f.service.ID, RunID: f.run.RunID, RunNumber: f.run.RunNumber}
	for _, field := range []string{"service", "run", "number", "visitor", "lease", "before-admission", "future", "expired-lease",
		"missing evidence", "malformed evidence", "source", "destination port", "proof signature", "source timestamp", "trailing application bytes", "oversized evidence"} {
		t.Run(field, func(t *testing.T) {
			run, connection, lease, observed, delivered := ref, visitor, ingress.IngressLeaseIdentity, at, at
			sourceEvidence := bytes.Clone(evidence)
			switch field {
			case "service":
				run.ServiceID = mustOpaqueID(t, opaqueid.ServicePrefix)
			case "run":
				run.RunID = mustOpaqueID(t, opaqueid.ServiceRunPrefix)
			case "number":
				run.RunNumber++
			case "visitor":
				connection = mustOpaqueID(t, opaqueid.VisitorConnectionPrefix)
			case "lease":
				lease.IngressLeaseRevision++
			case "before-admission":
				observed = at.Add(-time.Second)
			case "future":
				observed = at.Add(2 * time.Second)
			case "expired-lease":
				delivered = f.now.Add(2 * time.Minute)
			case "missing evidence":
				sourceEvidence = nil
			case "malformed evidence":
				sourceEvidence = []byte("not a PROXY header")
			case "trailing application bytes":
				sourceEvidence = append(sourceEvidence, []byte("GET /private HTTP/1.1\r\n\r\n")...)
			case "oversized evidence":
				sourceEvidence = make([]byte, 2049)
			case "source", "destination port", "proof signature", "source timestamp":
				metadata, _, err := proxyproto.Decode(bytes.NewReader(sourceEvidence))
				if err != nil {
					t.Fatal(err)
				}
				switch field {
				case "source":
					metadata.Source = netip.MustParseAddrPort("192.0.2.11:40000")
				case "destination port":
					metadata.Destination = netip.MustParseAddrPort("198.51.100.10:25443")
				default:
					proof, err := tunnelv1.ReadVisitorSourceProof([]byte(metadata.VisitorSourceProof))
					if err != nil {
						t.Fatal(err)
					}
					if field == "proof signature" {
						proof.MAC[0]++
					} else {
						proof.ObservedAt++
					}
					wire, err := proof.MarshalBinary()
					if err != nil {
						t.Fatal(err)
					}
					metadata.VisitorSourceProof = string(wire)
				}
				sourceEvidence, err = proxyproto.Encode(metadata)
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err := f.database.ObserveServiceRecovery(ctx, lease, run, connection,
				uint64(*admission.RecoveryEpisodeID), observed, sourceEvidence, delivered); err == nil {
				t.Fatal("recovery accepted another admission, run, timestamp, or expired sender")
			}
		})
	}
	if err := f.database.CloseServiceRun(f.ctx, ref.ServiceID, ref.RunID, f.run.Token, at.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.ObserveServiceRecovery(ctx, ingress.IngressLeaseIdentity, ref, visitor,
		uint64(*admission.RecoveryEpisodeID), at, evidence, at.Add(2*time.Second)); !errors.Is(err, ErrServiceRecoveryEpisodeStale) {
		t.Fatal("closed run completed its canceled recovery", err)
	}
	var canceled bool
	if err := f.database.pool.QueryRow(ctx, `SELECT state='canceled' AND canceled_at IS NOT NULL AND observed_at IS NULL
		FROM control.service_recovery_episodes WHERE id=$1`, *admission.RecoveryEpisodeID).Scan(&canceled); err != nil || !canceled {
		t.Fatal("run closure did not cancel its exact open recovery", canceled, err)
	}
}

func TestIntegrationHTTPRecoveryRetainsOriginalEvidenceAfterRoutingRefresh(t *testing.T) {
	f, _ := guestAuthorityFixture(t, true)
	ctx := t.Context()
	ingress, err := f.database.RegisterIngress(ctx, IngressRegistration{
		IngressID: "recovery-refresh", IngressRunID: mustOpaqueID(t, opaqueid.IngressRunPrefix),
		ProtocolVersion: 1, HTTPS: true, ConnectionCapacity: 100, IngressPoolID: PrimaryIngressPoolID,
	}, f.now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	slot := f.run.Connections[0]
	if _, err := f.database.DisconnectServicePublisherConnection(ctx, slot.PublisherConnectionID, f.run.RunID,
		f.run.RunNumber, slot.Revision, f.leases[slot.RelayServiceID].RelayLeaseIdentity, f.now.Add(time.Second), true); err != nil {
		t.Fatal(err)
	}
	at := f.now.Add(2 * time.Second)
	route, err := readIngressServiceRun(ctx, f.database, ingress.IngressLeaseIdentity, f.service.ID, f.run.RunID, at)
	if err != nil || route.RecoveryEpisodeID == nil {
		t.Fatal("routing omitted the open recovery", err)
	}
	visitor := mustOpaqueID(t, opaqueid.VisitorConnectionPrefix)
	evidence := recoverySourceEvidence(t, route, visitor, at)
	fresh, err := readIngressServiceRun(ctx, f.database, ingress.IngressLeaseIdentity, f.service.ID, f.run.RunID, at.Add(time.Second))
	if err != nil || bytes.Equal(route.SourceAuthority, fresh.SourceAuthority) {
		t.Fatal("routing refresh did not replace its short-lived delegation", err)
	}
	observed := route.ValidUntil.Add(time.Second)
	metadata, _, err := proxyproto.Decode(bytes.NewReader(evidence))
	if err != nil {
		t.Fatal(err)
	}
	proof, err := tunnelv1.ReadVisitorSourceProof([]byte(metadata.VisitorSourceProof))
	if err != nil {
		t.Fatal(err)
	}
	binding := tunnelv1.VisitorSourceBinding{ServiceID: f.service.ID, ServiceRunID: f.run.RunID, RunNumber: uint64(f.run.RunNumber),
		VisitorConnectionID: visitor, Source: metadata.Source, Destination: metadata.Destination}
	if err := visitortoken.VerifyVisitorSource(f.run.VisitorSourceKey, proof, binding, proof.Authority.VisitorPolicyRevision, observed); err == nil {
		t.Fatal("historical source evidence became current visitor setup authority")
	}
	ref := ServiceRunReference{ServiceID: f.service.ID, RunID: f.run.RunID, RunNumber: f.run.RunNumber}
	result, err := f.database.ObserveServiceRecovery(ctx, ingress.IngressLeaseIdentity, ref, visitor,
		uint64(*route.RecoveryEpisodeID), observed, evidence, observed)
	if err != nil || !result.ObservedAt.Equal(observed) || result.ObservedSeconds != observed.Sub(f.now.Add(time.Second)).Seconds() {
		t.Fatal("recovery lost its actual first-byte timestamp or original signed source observation", result, err)
	}
}

func TestIntegrationNativeRecoveryRetainsAdmissionReceiptScope(t *testing.T) {
	f := newNativeServiceAdmissionFixture(t)
	ctx := t.Context()
	ingress := registerNativeServiceAdmissionIngress(t, ctx, f, "native-recovery")
	slot := f.run.Connections[0]
	if _, err := f.database.DisconnectServicePublisherConnection(ctx, slot.PublisherConnectionID, f.run.RunID,
		f.run.RunNumber, slot.Revision, f.leases[slot.RelayServiceID].RelayLeaseIdentity, f.now.Add(time.Second), true); err != nil {
		t.Fatal(err)
	}
	at := f.now.Add(2 * time.Second)
	visitor := mustOpaqueID(t, opaqueid.VisitorConnectionPrefix)
	admission, err := f.database.AdmitPublicServiceVisitor(ctx, ingress.IngressLeaseIdentity, PrimaryIngressPoolID, visitor,
		f.service.Endpoint.Port, netip.MustParseAddr("192.0.2.10"), at)
	if err != nil || admission.RecoveryEpisodeID == nil {
		t.Fatal("native admission omitted the exact open recovery", err)
	}
	ref := ServiceRunReference{ServiceID: f.service.ID, RunID: f.run.RunID, RunNumber: f.run.RunNumber}
	for _, wrong := range []string{mustOpaqueID(t, opaqueid.VisitorConnectionPrefix), visitor} {
		reportedAt := at
		if wrong == visitor {
			reportedAt = at.Add(-time.Second)
		}
		if _, err := f.database.ObserveServiceRecovery(ctx, ingress.IngressLeaseIdentity, ref, wrong,
			uint64(*admission.RecoveryEpisodeID), reportedAt, nil, at); !errors.Is(err, ErrServiceRecoveryEpisodeStale) {
			t.Fatal("native recovery bypassed its exact visitor or original admission time", err)
		}
	}
	result, err := f.database.ObserveServiceRecovery(ctx, ingress.IngressLeaseIdentity, ref, visitor,
		uint64(*admission.RecoveryEpisodeID), at, nil, at)
	if err != nil || !result.ObservedAt.Equal(at) {
		t.Fatal("native recovery lost its control admission authority", result, err)
	}
}

func recoverySourceEvidence(t *testing.T, run IngressServiceRun, visitor string, at time.Time) []byte {
	t.Helper()
	authority, err := tunnelv1.ReadVisitorSourceAuthority(run.SourceAuthority)
	if err != nil {
		t.Fatal(err)
	}
	metadata := proxyproto.Header{Source: netip.MustParseAddrPort("192.0.2.10:40000"), Destination: netip.MustParseAddrPort("198.51.100.10:443")}
	proof, err := visitortoken.SignVisitorSource([32]byte(run.SourceKey), authority, 1, tunnelv1.VisitorSourceBinding{
		ServiceID: run.ServiceID, ServiceRunID: run.RunID, RunNumber: uint64(run.RunNumber), VisitorConnectionID: visitor,
		Source: metadata.Source, Destination: metadata.Destination,
	}, at)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := proof.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	metadata.VisitorSourceProof = string(wire)
	evidence, err := proxyproto.Encode(metadata)
	if err != nil {
		t.Fatal(err)
	}
	return evidence
}

func TestIntegrationServiceRecoveryIgnoresIntentionalAndNeverReadyDisconnects(t *testing.T) {
	for _, mode := range []string{"intentional", "never-ready", "relay-drain", "lease-loss"} {
		t.Run(mode, func(t *testing.T) {
			f, _ := guestAuthorityFixture(t, mode != "never-ready")
			slot := f.run.Connections[0]
			at := f.now.Add(time.Second)
			lease := f.leases[slot.RelayServiceID].RelayLeaseIdentity
			switch mode {
			case "never-ready":
				if _, err := f.database.ClaimServicePublisherConnection(f.ctx, slot.PublisherConnectionID, f.service.ID,
					f.run.RunID, f.run.RunNumber, slot.Revision, slot.Credential, f.guest.SourceIP, lease, at); err != nil {
					t.Fatal(err)
				}
				fallthrough
			case "intentional":
				if _, err := f.database.DisconnectServicePublisherConnection(t.Context(), slot.PublisherConnectionID,
					f.run.RunID, f.run.RunNumber, slot.Revision, lease, at, mode != "intentional"); err != nil {
					t.Fatal(err)
				}
			case "relay-drain":
				if _, err := f.database.BeginRelayDrain(t.Context(), lease, at, at.Add(time.Minute)); err != nil {
					t.Fatal(err)
				}
				if _, err := f.heartbeat(at); err != nil {
					t.Fatal(err)
				}
			case "lease-loss":
				if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.relay_leases SET lease_expires_at=$1
					WHERE relay_id=$2`, at, lease.RelayID); err != nil {
					t.Fatal(err)
				}
				if _, err := f.heartbeat(at.Add(time.Second)); err != nil {
					t.Fatal(err)
				}
			}
			var count int
			want := 0
			if mode == "lease-loss" {
				want = 1
			}
			if err := f.database.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.service_recovery_episodes
				WHERE service_run_id=$1`, f.run.RunID).Scan(&count); err != nil || count != want {
				t.Fatal("recovery did not distinguish unexpected loss from setup or intentional drain", count, err)
			}
		})
	}
}

// routing-table event lifecycle, cursor, tombstone, and retention assertions
// are retained at their canonical owners. this file owns service recovery.
