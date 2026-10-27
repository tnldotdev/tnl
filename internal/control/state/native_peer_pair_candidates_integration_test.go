package state

import (
	"crypto/rand"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

func assertNativePairCandidatePages(t *testing.T, d *Database, pair NativePeerPair, run ServiceRunState, now time.Time) {
	t.Helper()
	ctx := t.Context()
	for _, token := range []string{"", "not-the-run-token"} {
		if _, err := d.ListNativePeerPairs(ctx, pair.ServiceID, run.RunID, "", token, now); !errors.Is(err, ErrServiceAccess) {
			t.Fatal("unrelated token discovered pairs", err)
		}
	}
	if _, err := d.ListNativePeerPairs(ctx, pair.ServiceID, run.RunID, "invalid", run.Token, now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("invalid cursor was accepted", err)
	}
	expected := map[string]int64{pair.ID: pair.DeliveryGeneration}
	var inserted []string
	defer func() {
		if _, err := d.pool.Exec(ctx, `DELETE FROM control.native_peer_pairs WHERE id=ANY($1::text[])`, inserted); err != nil {
			t.Error("remove discovery fixtures", err)
		}
	}()
	for i := range 66 {
		id, err := opaqueid.New("npp_")
		if err != nil {
			t.Fatal(err)
		}
		delivery := make([]byte, 16)
		if _, err := rand.Read(delivery); err != nil {
			t.Fatal(err)
		}
		var generation int64
		err = d.pool.QueryRow(ctx, `INSERT INTO control.native_peer_pairs
			(id,service_id,service_run_id,run_number,publisher_identity_id,subject_kind,subject_id,parent_control_session_id,
			idempotency_key,request_digest,key_digest,key_ciphertext,delivery_id,storage_key_id,slots,
			delivery_generation,created_at,last_authorized_at,last_request_at,replay_fence_until,expires_at)
			SELECT $2,service_id,service_run_id,run_number,publisher_identity_id,subject_kind,$2,parent_control_session_id,
			idempotency_key,request_digest,key_digest,key_ciphertext,$3,storage_key_id,slots,
			nextval('control.native_peer_delivery_generation'),created_at,last_authorized_at,last_request_at,replay_fence_until,expires_at
			FROM control.native_peer_pairs WHERE id=$1 RETURNING delivery_generation`, pair.ID, id, delivery).Scan(&generation)
		if err != nil {
			t.Fatal(err)
		}
		inserted = append(inserted, id)
		if i == 0 {
			if _, err := d.pool.Exec(ctx, `UPDATE control.native_peer_pairs SET created_at=$2,last_authorized_at=$2,expires_at=$3 WHERE id=$1`,
				id, now.Add(-time.Minute), now.Add(-time.Microsecond)); err != nil {
				t.Fatal(err)
			}
		} else {
			expected[id] = generation
		}
	}
	var ordered []string
	for id := range expected {
		ordered = append(ordered, id)
	}
	sort.Strings(ordered)
	after, seen := "", 0
	for pages := 0; ; pages++ {
		if pages > 2 {
			t.Fatal("discovery cursor did not terminate")
		}
		page, err := d.ListNativePeerPairs(ctx, pair.ServiceID, run.RunID, after, run.Token, now)
		if err != nil || len(page.Items) > 64 || pages == 0 && len(page.Items) != 64 {
			t.Fatal("discovery page was not bounded", len(page.Items), err)
		}
		for _, item := range page.Items {
			if seen >= len(ordered) || item.PairID != ordered[seen] || item.DeliveryGeneration != expected[item.PairID] {
				t.Fatal("discovery lost ordering, generation, or expiry filtering")
			}
			seen++
		}
		if page.NextAfter == "" {
			break
		}
		if page.NextAfter <= after || page.NextAfter != page.Items[len(page.Items)-1].PairID {
			t.Fatal("cursor did not advance to the last returned pair")
		}
		after = page.NextAfter
	}
	if seen != len(expected) {
		t.Fatal("discovery omitted candidates", seen, len(expected))
	}
}
