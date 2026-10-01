package controlstate

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
)

func TestIntegrationRoutingSnapshotSelectsLatestBeforeFiltering(t *testing.T) {
	type event struct {
		kind    IngressRoutingTableEventKind
		version uint64
		ttl     time.Duration
	}
	for _, tc := range []struct {
		name    string
		events  []event
		through int
		want    []int // one-based positions in events, independent of SQL row order.
	}{
		{
			name:    "route tombstone suppresses live history",
			events:  []event{{IngressPublicURLUpsert, 1, time.Hour}, {IngressPublicURLTombstone, 1, time.Hour}},
			through: 2,
		},
		{
			name:    "expiration boundary suppresses live history",
			events:  []event{{IngressPublicURLUpsert, 1, time.Hour}, {IngressPublicURLUpsert, 1, 0}},
			through: 2,
		},
		{
			name:    "expired entry suppresses live history",
			events:  []event{{IngressPublicURLUpsert, 1, time.Hour}, {IngressPublicURLUpsert, 1, -time.Second}},
			through: 2,
		},
		{
			name:    "route and challenge share hostname independently",
			events:  []event{{IngressPublicURLUpsert, 1, time.Hour}, {IngressChallengeUpsert, 1, time.Hour}},
			through: 2, want: []int{1, 2},
		},
		{
			name:    "challenge tombstone preserves route",
			events:  []event{{IngressPublicURLUpsert, 1, time.Hour}, {IngressChallengeUpsert, 1, time.Hour}, {IngressChallengeTombstone, 1, time.Hour}},
			through: 3, want: []int{1},
		},
		{
			name:    "route tombstone preserves challenge",
			events:  []event{{IngressPublicURLUpsert, 1, time.Hour}, {IngressChallengeUpsert, 1, time.Hour}, {IngressPublicURLTombstone, 1, time.Hour}},
			through: 3, want: []int{2},
		},
		{
			name:    "new publish run number supersedes old version",
			events:  []event{{IngressPublicURLUpsert, 1, time.Hour}, {IngressPublicURLUpsert, 2, time.Hour}},
			through: 2, want: []int{2},
		},
		{
			name:    "future version and challenge excluded",
			events:  []event{{IngressPublicURLUpsert, 1, time.Hour}, {IngressPublicURLUpsert, 2, time.Hour}, {IngressChallengeUpsert, 2, time.Hour}},
			through: 1, want: []int{1},
		},
		{
			name:    "future tombstone excluded",
			events:  []event{{IngressPublicURLUpsert, 1, time.Hour}, {IngressPublicURLTombstone, 1, time.Hour}},
			through: 1, want: []int{1},
		},
		{
			name:    "empty published history",
			events:  []event{{IngressPublicURLUpsert, 1, time.Hour}},
			through: 0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newPublishRunFixture(t)
			ingress := registerTestIngress(t, f.database, f.now)
			queries := controlstatedb.New(f.database.pool)
			var stored []IngressRoutingTableEvent
			for index, item := range tc.events {
				expires := f.now.Add(item.ttl)
				projection := IngressRoutingTableProjection{
					PublicURLID: f.setup.PublicURLID, PublishRunID: f.setup.PublishRunID,
					CanonicalHostname: f.request.CertificateIdentifiers[0], PublishRunNumber: item.version,
					PolicyRevision: uint64(index + 1), PublicUrlExpiresAt: expires,
				}
				payload, err := json.Marshal(projection)
				if err != nil {
					t.Fatal(err)
				}
				revision, err := queries.InsertIngressRoutingTableEvent(t.Context(), controlstatedb.InsertIngressRoutingTableEventParams{
					EventKind: string(item.kind), PublicURLID: projection.PublicURLID, PublishRunNumber: int64(item.version),
					CanonicalHostname: projection.CanonicalHostname, EntryRevision: int64(index + 1),
					Projection: payload, PublicUrlExpiresAt: timestamptz(expires), CreatedAt: timestamptz(f.now),
				})
				if err != nil {
					t.Fatal(err)
				}
				stored = append(stored, IngressRoutingTableEvent{
					RoutingTableRevision: uint64(revision), Kind: item.kind, PublicURLID: projection.PublicURLID,
					PublishRunNumber: item.version, CanonicalHostname: projection.CanonicalHostname,
					EntryRevision: uint64(index + 1), Projection: projection, PublicUrlExpiresAt: &expires, CreatedAt: f.now,
				})
			}
			// select a high-water revision explicitly, including older boundaries,
			// to exercise snapshot selection independently of event publication.
			var through uint64
			if tc.through != 0 {
				through = stored[tc.through-1].RoutingTableRevision
			}
			if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.ingress_routing_table_clock SET current_revision = $1`, through); err != nil {
				t.Fatal(err)
			}
			snapshot, err := f.database.ReadIngressRoutingTableSnapshot(t.Context(), ingress.IngressLeaseIdentity, f.now)
			if err != nil || snapshot.RoutingTableRevision != through || len(snapshot.Entries) != len(tc.want) {
				t.Fatalf("snapshot revision=%d routes=%d, want revision=%d routes=%d: %v", snapshot.RoutingTableRevision, len(snapshot.Entries), through, len(tc.want), err)
			}
			expected := make(map[uint64]IngressRoutingTableEvent, len(tc.want))
			for _, index := range tc.want {
				item := stored[index-1]
				expected[item.RoutingTableRevision] = item
			}
			for _, got := range snapshot.Entries {
				want, ok := expected[got.RoutingTableRevision]
				if !ok || got.Kind != want.Kind || got.PublicURLID != want.PublicURLID || got.PublishRunNumber != want.PublishRunNumber ||
					got.CanonicalHostname != want.CanonicalHostname || got.EntryRevision != want.EntryRevision ||
					!reflect.DeepEqual(got.Projection, want.Projection) || !got.CreatedAt.Equal(want.CreatedAt) ||
					got.PublicUrlExpiresAt == nil || !got.PublicUrlExpiresAt.Equal(*want.PublicUrlExpiresAt) {
					t.Fatalf("unexpected snapshot event revision=%d kind=%s version=%d", got.RoutingTableRevision, got.Kind, got.PublishRunNumber)
				}
				delete(expected, got.RoutingTableRevision)
			}
		})
	}
}
