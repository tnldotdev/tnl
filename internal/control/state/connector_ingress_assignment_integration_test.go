package state

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/region"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestIntegrationPrivateIngressRegionalPreferenceAndFallback(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "regional_ingress")
	ctx := t.Context()
	request := oidcRouteRequest(t, d, now)
	service, err := d.CreateServiceAt(ctx, request.TeamID, request.ActingIdentityID, "db", "db", ServicePlacement{}, now, ServiceMetadata{Protocol: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	device, err := d.EnrollVisitorDevice(ctx, request.ActingIdentityID, public, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range []struct {
		id     string
		region region.Code
	}{
		{"a-iad", "iad"}, {"b-sjc", "sjc"}, {"c-sjc", "sjc"},
	} {
		if _, err := d.RegisterIngress(ctx, IngressRegistration{IngressID: entry.id, IngressRunID: entry.id + "-run", Region: entry.region,
			ProtocolVersion: tunnelv1.Version, ConnectionCapacity: 1, ConnectorAddress: entry.id + ".example.test:443", ConnectorTLSServerName: entry.id + ".example.test"}, now, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	first, err := d.CreateVisitorIngressAssignments(ctx, request.ActingIdentityID, device.ID, service.ID, "pair", now, "aws:us-west-1")
	if err != nil || len(first) != 2 || first[0].Region != "sjc" || first[1].Region != "sjc" || first[0].IngressID == first[1].IngressID || first[0].IngressAddress == first[1].IngressAddress {
		t.Fatal("preferred region lost independent process endpoints", first, err)
	}
	replayed, err := d.CreateVisitorIngressAssignments(ctx, request.ActingIdentityID, device.ID, service.ID, "pair", now, "sjc")
	if err != nil || replayed[0].ID != first[0].ID || replayed[1].ID != first[1].ID {
		t.Fatal("normalized preference did not recover exact assignments", replayed, err)
	}
	if _, err := d.CreateVisitorIngressAssignments(ctx, request.ActingIdentityID, device.ID, service.ID, "pair", now, "iad"); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("changing preferred region reused a committed request", err)
	}
	fallback, err := d.CreateVisitorIngressAssignment(ctx, request.ActingIdentityID, device.ID, service.ID, "", "fallback", now, "fly:sjc")
	if err != nil || fallback.Region != "iad" || fallback.IngressID != "a-iad" {
		t.Fatal("full local region did not fall back to the live remote process", fallback, err)
	}
	if err := d.ReleaseVisitorIngressAssignment(ctx, request.ActingIdentityID, first[0].ID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := d.CreateVisitorIngressAssignment(ctx, request.ActingIdentityID, device.ID, service.ID, "", "missing", now, "unknown"); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("unknown location was accepted", err)
	}
	freed, err := d.CreateVisitorIngressAssignment(ctx, request.ActingIdentityID, device.ID, service.ID, "", "freed", now, "sjc")
	if err != nil || freed.Region != "sjc" || freed.IngressID != first[0].IngressID {
		t.Fatal("released preferred capacity was not reused", freed, err)
	}
}

func TestIntegrationPrivateAssignmentReplayValidity(t *testing.T) {
	for _, change := range []string{"device", "service", "count", "exclusion", "revoked-device", "revoked-grant", "disabled-identity", "released", "bound", "expired", "lease-expired", "lease-replaced", "draining", "cleanup", "storage-rotation"} {
		t.Run(change, func(t *testing.T) {
			d, databaseURL, now := newControlStateIntegrationDatabaseWithURL(t, "assignment_replay")
			ctx := t.Context()
			r := oidcRouteRequest(t, d, now)
			service, err := d.CreateServiceAt(ctx, r.TeamID, r.ActingIdentityID, "db", "db", ServicePlacement{}, now, ServiceMetadata{Protocol: "tcp"})
			if err != nil {
				t.Fatal(err)
			}
			public, key, _ := ed25519.GenerateKey(rand.Reader)
			device, err := d.EnrollVisitorDevice(ctx, r.ActingIdentityID, public, now)
			if err != nil {
				t.Fatal(err)
			}
			lease, err := d.RegisterIngress(ctx, IngressRegistration{IngressID: "replay", IngressRunID: "replay-run", ProtocolVersion: tunnelv1.Version,
				ConnectionCapacity: 1, ConnectorAddress: "127.0.0.1:9443", ConnectorTLSServerName: "private.example.test"}, now, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			first, err := d.CreateVisitorIngressAssignment(ctx, r.ActingIdentityID, device.ID, service.ID, "", "retry", now)
			if err != nil {
				t.Fatal(err)
			}
			// concurrent retries at capacity one must recover the exact committed result.
			done := make(chan error, 2)
			for range 2 {
				go func() {
					replayed, err := d.CreateVisitorIngressAssignment(ctx, r.ActingIdentityID, device.ID, service.ID, "", "retry", now)
					if err == nil && (replayed.ID != first.ID || replayed.Credential != first.Credential) {
						err = errors.New("replay changed assignment")
					}
					done <- err
				}()
			}
			for range 2 {
				if err := <-done; err != nil {
					t.Fatal(err)
				}
			}
			exclude, at, expected := "", now, ErrServiceAccess
			switch change {
			case "storage-rotation":
				newKey := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32))
				rotating, err := Open(ctx, databaseURL, newKey, testStorageKey)
				if err != nil {
					t.Fatal(err)
				}
				defer rotating.Close()
				if err := rotating.CompleteStorageKeyRotation(ctx); err != nil {
					t.Fatal(err)
				}
				reopened, err := Open(ctx, databaseURL, newKey, "")
				if err != nil {
					t.Fatal(err)
				}
				defer reopened.Close()
				recovered, err := reopened.CreateVisitorIngressAssignment(ctx, r.ActingIdentityID, device.ID, service.ID, "", "retry", now)
				if err != nil || recovered.ID != first.ID || recovered.Credential != first.Credential {
					t.Fatal("assignment replay lost its recoverable secret after key rotation", err)
				}
				return
			case "device":
				public, _, _ = ed25519.GenerateKey(rand.Reader)
				device, err = d.EnrollVisitorDevice(ctx, r.ActingIdentityID, public, now)
				expected = ErrServiceConflict
			case "service":
				service, err = d.CreateServiceAt(ctx, r.TeamID, r.ActingIdentityID, "other", "other", ServicePlacement{}, now, ServiceMetadata{Protocol: "tcp"})
				expected = ErrServiceConflict
			case "count":
				_, err = d.CreateVisitorIngressAssignments(ctx, r.ActingIdentityID, device.ID, service.ID, "retry", now)
				if !errors.Is(err, ErrServiceConflict) {
					t.Fatal("count mismatch was accepted", err)
				}
				return
			case "exclusion":
				exclude, expected = "other", ErrServiceConflict
			case "revoked-device":
				err = d.RevokeVisitorDevice(ctx, r.ActingIdentityID, device.ID, now)
			case "revoked-grant":
				grants, _, e := d.ListServiceGrants(ctx, service.ID, r.ActingIdentityID, "")
				if e != nil {
					t.Fatal(e)
				}
				err = d.RevokeServiceGrant(ctx, service.ID, r.ActingIdentityID, grants[0].ID, now)
			case "disabled-identity":
				_, err = d.pool.Exec(ctx, `UPDATE control.identities SET disabled_at=$2 WHERE id=$1`, r.ActingIdentityID, now)
			case "released":
				err = d.ReleaseVisitorIngressAssignment(ctx, r.ActingIdentityID, first.ID, now)
			case "bound":
				hello := tunnelv1.ConnectorSessionHello{ProtocolVersion: tunnelv1.Version, Kind: "connector_session", ServiceID: service.ID,
					SessionID: first.ID, Credential: first.Credential, Subject: tunnelv1.VisitorSubject{Kind: tunnelv1.VisitorHumanDevice, DeviceID: device.ID, IdentityID: r.ActingIdentityID}, Nonce: make([]byte, 32)}
				digest, _ := hello.Claim().Digest()
				hello.Signature = ed25519.Sign(key, digest)
				_, err = d.AuthenticateVisitorConnector(ctx, lease.IngressLeaseIdentity, hello.Claim(), netip.MustParseAddr("192.0.2.10"), now)
			case "expired":
				at = first.ExpiresAt
			case "lease-expired":
				_, err = d.pool.Exec(ctx, `UPDATE control.ingress_leases SET lease_expires_at=$2 WHERE ingress_id=$1`, lease.IngressID, now.Add(time.Second))
				at = now.Add(time.Second)
			case "lease-replaced":
				_, err = d.pool.Exec(ctx, `UPDATE control.ingress_leases SET lease_expires_at=$2 WHERE ingress_id=$1`, lease.IngressID, now.Add(time.Second))
				if err != nil {
					t.Fatal(err)
				}
				at = now.Add(2 * time.Second)
				_, err = d.RegisterIngress(ctx, IngressRegistration{IngressID: lease.IngressID, IngressRunID: "replacement-run", ProtocolVersion: tunnelv1.Version, ConnectionCapacity: 1,
					ConnectorAddress: "127.0.0.1:9443", ConnectorTLSServerName: "private.example.test"}, at, time.Hour)
			case "draining":
				_, err = d.BeginIngressDrain(ctx, lease.IngressLeaseIdentity, now, now.Add(time.Minute))
			case "cleanup":
				_, err = d.pool.Exec(ctx, `INSERT INTO control.connector_ingress_assignment_requests SELECT identity_id,'cleanup-'||n,request_digest,result_ciphertext,storage_key_id,expires_at FROM control.connector_ingress_assignment_requests CROSS JOIN generate_series(1,1001) n`)
				if err != nil {
					t.Fatal(err)
				}
				for _, want := range []int{2, 0} {
					if _, err := d.ExpireServiceRuns(context.Background(), now.Add(26*time.Hour)); err != nil {
						t.Fatal(err)
					}
					var count int
					if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM control.connector_ingress_assignment_requests`).Scan(&count); err != nil || count != want {
						t.Fatalf("bounded retry cleanup: count=%d want=%d err=%v", count, want, err)
					}
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := d.CreateVisitorIngressAssignment(ctx, r.ActingIdentityID, device.ID, service.ID, exclude, "retry", at); !errors.Is(err, expected) {
				t.Fatal("invalid replay did not fail closed", err)
			}
			var count int
			if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM control.connector_sessions`).Scan(&count); err != nil || count != 1 {
				t.Fatal("rejected replay created another reservation", err)
			}
		})
	}
}

func TestIntegrationPrivateVisitorSingleAssignmentRenewalAtCapacity(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "single_assignment")
	ctx := t.Context()
	r := oidcRouteRequest(t, d, now)
	service, err := d.CreateServiceAt(ctx, r.TeamID, r.ActingIdentityID, "db", "db", ServicePlacement{}, now, ServiceMetadata{Protocol: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	device, err := d.EnrollVisitorDevice(ctx, r.ActingIdentityID, public, now)
	if err != nil {
		t.Fatal(err)
	}
	leases := map[string]IngressLease{}
	for index := range 2 {
		lease, e := d.RegisterIngress(ctx, IngressRegistration{IngressID: fmt.Sprintf("single-%d", index), IngressRunID: fmt.Sprintf("single-run-%d", index), ProtocolVersion: tunnelv1.Version, ConnectionCapacity: 1, ConnectorAddress: fmt.Sprintf("127.0.0.1:%d", 9400+index), ConnectorTLSServerName: "private.example.test"}, now, time.Hour)
		if e != nil {
			t.Fatal(e)
		}
		leases[lease.IngressID] = lease
	}
	sessions, err := d.CreateVisitorIngressAssignments(ctx, r.ActingIdentityID, device.ID, service.ID, "startup", now)
	if err != nil || len(sessions) != 2 || sessions[0].IngressID == sessions[1].IngressID {
		t.Fatal("startup pair failed", sessions, err)
	}
	a, b := sessions[0], sessions[1]
	hello := tunnelv1.ConnectorSessionHello{ProtocolVersion: tunnelv1.Version, Kind: "connector_session", ServiceID: service.ID, SessionID: a.ID, Credential: a.Credential, Subject: tunnelv1.VisitorSubject{Kind: tunnelv1.VisitorHumanDevice, DeviceID: device.ID, IdentityID: r.ActingIdentityID}, Nonce: make([]byte, 32), Signature: make([]byte, 64)}
	digest, err := hello.Claim().Digest()
	if err != nil {
		t.Fatal(err)
	}
	hello.Signature = ed25519.Sign(key, digest)
	if _, err = d.AuthenticateVisitorConnector(ctx, leases[a.IngressID].IngressLeaseIdentity, hello.Claim(), netip.MustParseAddr("192.0.2.10"), now); err != nil {
		t.Fatal(err)
	}
	if _, err = d.RenewIngress(ctx, IngressRenewal{IngressLeaseIdentity: leases[a.IngressID].IngressLeaseIdentity, ReportedConnections: 1}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	// B's failed/trust-rejected setup must be released before renewal. the
	// healthy A session still consumes its process's only advertised capacity.
	if err = d.ReleaseVisitorIngressAssignment(ctx, r.ActingIdentityID, b.ID, now); err != nil {
		t.Fatal(err)
	}
	if _, err = d.CreateVisitorIngressAssignments(ctx, r.ActingIdentityID, device.ID, service.ID, "overbook-pair", now); !errors.Is(err, ErrInsufficientPrivateIngresses) {
		t.Fatal("pair renewal overbooked healthy A", err)
	}
	renewed, err := d.CreateVisitorIngressAssignment(ctx, r.ActingIdentityID, device.ID, service.ID, a.IngressID, "renewal", now)
	if err != nil || renewed.IngressID != b.IngressID || renewed.ID == b.ID {
		t.Fatal("single-slot renewal required allocating A", renewed, err)
	}
	if _, err = d.CreateVisitorIngressAssignment(ctx, r.ActingIdentityID, device.ID, service.ID, a.IngressID, "overbook-single", now); !errors.Is(err, ErrPrivateIngressUnavailable) {
		t.Fatal("pending renewal overbooked B", err)
	}
	var healthy bool
	if err = d.pool.QueryRow(ctx, `SELECT bound_at IS NOT NULL AND revoked_at IS NULL FROM control.connector_sessions WHERE id=$1`, a.ID).Scan(&healthy); err != nil || !healthy {
		t.Fatal("renewal invalidated bound sibling", err)
	}
	if err = d.ReleaseVisitorIngressAssignment(ctx, r.ActingIdentityID, renewed.ID, now); err != nil {
		t.Fatal(err)
	}
	if _, err = d.BeginIngressDrain(ctx, leases[a.IngressID].IngressLeaseIdentity, now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	renewed, err = d.CreateVisitorIngressAssignment(ctx, r.ActingIdentityID, device.ID, service.ID, "", "draining", now)
	if err != nil || renewed.IngressID != b.IngressID {
		t.Fatal("draining A forced pair allocation", renewed, err)
	}
	if err = d.ReleaseVisitorIngressAssignment(ctx, r.ActingIdentityID, renewed.ID, now); err != nil {
		t.Fatal(err)
	}
	if _, err = d.CreateVisitorIngressAssignment(ctx, r.ActingIdentityID, device.ID, service.ID, "", "expired", leases[b.IngressID].LeaseExpiresAt); !errors.Is(err, ErrPrivateIngressUnavailable) {
		t.Fatal("expired B or draining A received renewal", err)
	}
}

func TestIntegrationPrivateVisitorAssignmentRequiresCurrentDeviceAndGrant(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "assignment_access")
	ctx := t.Context()
	r := oidcRouteRequest(t, d, now)
	service, err := d.CreateServiceAt(ctx, r.TeamID, r.ActingIdentityID, "db", "db", ServicePlacement{}, now, ServiceMetadata{Protocol: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	device, err := d.EnrollVisitorDevice(ctx, r.ActingIdentityID, public, now)
	if err != nil {
		t.Fatal(err)
	}
	other := finalVisitorIdentity(t, d, now, "not-granted@example.test")
	otherDevice, err := d.EnrollVisitorDevice(ctx, other, public, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, attempt := range []func() error{
		func() error {
			_, e := d.CreateVisitorIngressAssignment(ctx, other, device.ID, service.ID, "arbitrary-exclusion", "other-device", now)
			return e
		},
		func() error {
			_, e := d.CreateVisitorIngressAssignment(ctx, other, otherDevice.ID, service.ID, "arbitrary-exclusion", "other-service", now)
			return e
		},
		func() error {
			_, e := d.CreateVisitorIngressAssignments(ctx, other, otherDevice.ID, service.ID, "other-pair", now)
			return e
		},
	} {
		if err := attempt(); !errors.Is(err, ErrServiceAccess) {
			t.Fatal("device/exclusion hint bypassed service access", err)
		}
	}
	if err = d.RevokeVisitorDevice(ctx, r.ActingIdentityID, device.ID, now); err != nil {
		t.Fatal(err)
	}
	if _, err = d.CreateVisitorIngressAssignment(ctx, r.ActingIdentityID, device.ID, service.ID, "", "revoked-device", now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("revoked device reserved capacity", err)
	}
	public, _, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	device, err = d.EnrollVisitorDevice(ctx, r.ActingIdentityID, public, now)
	if err != nil {
		t.Fatal(err)
	}
	grants, _, err := d.ListServiceGrants(ctx, service.ID, r.ActingIdentityID, "")
	if err != nil {
		t.Fatal(err)
	}
	if err = d.RevokeServiceGrant(ctx, service.ID, r.ActingIdentityID, grants[0].ID, now); err != nil {
		t.Fatal(err)
	}
	if _, err = d.CreateVisitorIngressAssignment(ctx, r.ActingIdentityID, device.ID, service.ID, "", "revoked-grant", now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("revoked grant reserved capacity", err)
	}
}
