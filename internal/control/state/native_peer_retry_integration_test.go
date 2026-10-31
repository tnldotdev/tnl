package state

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func TestIntegrationPrivateAssignmentReplayValidity(t *testing.T) {
	for _, change := range []string{"device", "service", "revoked-device", "revoked-grant", "disabled-identity", "expired", "lease-expired", "lease-replaced", "draining"} {
		t.Run(change, func(t *testing.T) {
			f := newNativePairFixture(t)
			first := f.create(t)
			request, at := f.request, f.now
			var err error
			switch change {
			case "device":
				request.Subject.DeviceID = "vdev_aaaaaaaaaaaaaaaaaaaaaa"
			case "service":
				request.ServiceID = "svc_aaaaaaaaaaaaaaaaaaaaaa"
			case "revoked-device":
				err = f.d.RevokeVisitorDevice(f.visitor, request.Subject.IdentityID, request.Subject.DeviceID, at)
			case "revoked-grant":
				_, err = f.d.pool.Exec(f.visitor, `UPDATE control.visitor_grants SET revoked_at=$2 WHERE service_id=$1`, first.ServiceID, at)
			case "disabled-identity":
				_, err = f.d.pool.Exec(f.visitor, `UPDATE control.identities SET disabled_at=$2 WHERE id=$1`, request.Subject.IdentityID, at)
			case "expired":
				at = first.ExpiresAt
			case "lease-expired":
				_, err = f.d.pool.Exec(f.visitor, `UPDATE control.relay_leases SET lease_expires_at=$2 WHERE relay_id=$1`, first.Relays[0].RelayLease.RelayID, at.Add(time.Second))
				at = at.Add(time.Second)
			case "lease-replaced":
				_, err = f.d.pool.Exec(f.visitor, `UPDATE control.relay_leases SET relay_run_id='replacement',relay_lease_revision=relay_lease_revision+1 WHERE relay_id=$1`, first.Relays[0].RelayLease.RelayID)
			case "draining":
				_, err = f.d.BeginRelayDrain(f.visitor, first.Relays[0].RelayLease, at, at.Add(time.Minute))
			}
			if err != nil {
				t.Fatal(err)
			}
			f.sign(t, &request)
			before := nativePairSavedAuthority(t, f.d, first.ID)
			if _, err := f.d.PrepareNativePeerPair(f.visitor, request, at); err == nil {
				t.Fatal("invalid replay recovered authority")
			}
			if !bytes.Equal(before, nativePairSavedAuthority(t, f.d, first.ID)) {
				t.Fatal("denied replay changed durable authority")
			}
			var count int
			if err := f.d.pool.QueryRow(f.visitor, `SELECT count(*) FROM control.native_peer_pairs`).Scan(&count); err != nil || count != 1 {
				t.Fatal("denied replay allocated another owner", count, err)
			}
		})
	}
	// concurrent retries, recovery after storage-key retirement, exact source,
	// replacement and bounded replay-fence collection use the real native owner.
	t.Run("native exact authority", TestIntegrationNativePeerPairExactAuthority)
}

func TestIntegrationPrivateVisitorSingleAssignmentRenewalAtCapacity(t *testing.T) {
	f := newNativePairFixture(t)
	first := f.create(t)
	assertNativePairOwnerIsolation(t, f.d, f.visitor, f.request, first, f.key, f.now)
}

func TestIntegrationPrivateVisitorAssignmentRequiresCurrentDeviceAndGrant(t *testing.T) {
	f := newNativePairFixture(t)
	other := finalVisitorIdentity(t, f.d, f.now, "not-granted@example.test")
	request := f.request
	request.Subject.IdentityID = other
	f.sign(t, &request)
	if _, err := f.d.PrepareNativePeerPair(f.visitor, request, f.now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("foreign device owner bypassed current access", err)
	}
	if err := f.d.RevokeVisitorDevice(f.visitor, f.request.Subject.IdentityID, f.request.Subject.DeviceID, f.now); err != nil {
		t.Fatal(err)
	}
	if _, err := f.d.PrepareNativePeerPair(f.visitor, f.request, f.now); err == nil {
		t.Fatal("revoked device allocated native authority")
	}
}
