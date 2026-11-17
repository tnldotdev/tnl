package state

import (
	"context"
	"crypto/sha256"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
)

func TestIntegrationGuestAccessRestoredTrialExpiryOverridesOverlongStoredBearer(t *testing.T) {
	f, guest := guestAuthorityFixture(t, false, GuestLifetime-10*time.Second)
	ctx, cancel := context.WithTimeout(f.ctx, 10*time.Second)
	defer cancel()
	d, q := f.database, controlstatedb.New(f.database.pool)
	source := netip.PrefixFrom(guest.SourceIP, guest.SourceIP.BitLen()).String()
	trial, err := q.GetGuestTrialByID(ctx, guest.ID)
	if err != nil || trial.UsedReadyNs != 0 || trial.ActiveReadyAt.Valid || trial.ReadyDeadline.Valid ||
		trial.EndedAt.Valid || !guest.ExpiresAt.After(f.now) || !guest.ExpiresAt.Before(f.now.Add(PublisherAccessLifetime)) {
		t.Fatal("guest fixture does not isolate absolute expiry with unspent ready allowance", err)
	}
	assertion, err := publisherproof.Sign(f.publisher.ID, f.publisher.KeyID, f.publisher.GrantID,
		publisherTestAudience, f.private, f.now)
	if err != nil {
		t.Fatal(err)
	}
	access, err := d.ExchangePublisherAssertion(ctx, f.publisher.ID, f.publisher.GrantID,
		publisherTestAudience, assertion, source, f.now)
	if err != nil {
		t.Fatal("exchange the actual enrolled guest publisher", err)
	}
	if access.ID != f.publisher.ID || access.GrantID != f.publisher.GrantID ||
		access.ExpiresAt == nil || !access.ExpiresAt.Equal(guest.ExpiresAt) || !access.Until.Equal(guest.ExpiresAt) {
		t.Fatal("natural guest bearer did not retain its actual grant and trial clamp")
	}
	digest := sha256.Sum256([]byte(access.Token))
	issued, err := q.GetPublisherAccess(ctx, digest[:])
	if err != nil || issued.PublisherIdentityID != f.publisher.ID || issued.GrantID != f.publisher.GrantID ||
		issued.KeyID != f.publisher.KeyID || !issued.ExpiresAt.Time.Equal(guest.ExpiresAt) {
		t.Fatal("issued bearer was not stored with its exact publisher and natural clamp", err)
	}
	authority := func() string {
		t.Helper()
		var snapshot string
		err := d.pool.QueryRow(ctx, `SELECT jsonb_build_object(
			'trial',to_jsonb(trial),'service',to_jsonb(service),
			'publisher',to_jsonb(publisher),'grant',to_jsonb(grant_record))::text
			FROM control.guest_trials trial
			JOIN control.services service ON service.id=$2 AND service.guest_id=trial.id
			JOIN control.publisher_identities publisher ON publisher.id=$3 AND publisher.guest_id=trial.id
			JOIN control.publisher_grants grant_record ON grant_record.id=$4
				AND grant_record.publisher_identity_id=publisher.id AND grant_record.service_id=service.id
			WHERE trial.id=$1`, guest.ID, f.service.ID, f.publisher.ID, f.publisher.GrantID).Scan(&snapshot)
		if err != nil {
			t.Fatal(err)
		}
		return snapshot
	}
	before := authority()
	overlong := guest.ExpiresAt.Add(time.Minute)
	// only the expiry of an actually issued bearer is corrupted. the real
	// publisher grant, service and trial keep their original authority.
	changed, err := d.pool.Exec(ctx, `UPDATE control.publisher_access_tokens SET expires_at=$2
		WHERE access_token_digest=$1 AND publisher_identity_id=$3 AND grant_id=$4`,
		digest[:], overlong, f.publisher.ID, f.publisher.GrantID)
	if err != nil || changed.RowsAffected() != 1 {
		t.Fatal("overlong stored-bearer fixture did not change exactly one issued row", err)
	}
	stored, err := q.GetPublisherAccess(ctx, digest[:])
	if err != nil || !stored.ExpiresAt.Time.Equal(overlong) {
		t.Fatal("stored bearer did not retain the explicit overlong expiry", err)
	}
	stored.ExpiresAt = issued.ExpiresAt
	if !reflect.DeepEqual(stored, issued) || authority() != before {
		t.Fatal("overlong fixture changed fields other than the issued bearer's expiry")
	}
	beforeExpiry := f.now
	authenticated, err := d.AuthenticatePublisherAccess(ctx, access.Token, source, beforeExpiry)
	if err != nil || authenticated.ID != f.publisher.ID || authenticated.GrantID != f.publisher.GrantID ||
		authenticated.ExpiresAt == nil || !authenticated.ExpiresAt.Equal(guest.ExpiresAt) {
		t.Fatal("actual guest bearer was not usable before the independent trial deadline", err)
	}
	for _, at := range []time.Time{guest.ExpiresAt, guest.ExpiresAt.Add(time.Second)} {
		if !overlong.After(at) {
			t.Fatal("bearer expiry masked the trial authority contrast")
		}
		if _, err := d.AuthenticatePublisherAccess(ctx, access.Token, source, at); !failure.Only(err, ErrPublisherIdentity) {
			t.Fatal("expired guest authority did not return only the known publisher denial", err)
		}
	}
	after, err := q.GetPublisherAccess(ctx, digest[:])
	if err != nil || !after.ExpiresAt.Time.Equal(overlong) {
		t.Fatal("authentication changed the overlong stored bearer", err)
	}
	after.ExpiresAt = issued.ExpiresAt
	if !reflect.DeepEqual(after, issued) || authority() != before {
		t.Fatal("authentication changed the actual grant, trial, service or bearer identity")
	}
}
