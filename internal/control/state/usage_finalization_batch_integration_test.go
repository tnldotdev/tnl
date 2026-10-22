package controlstate

import (
	"testing"
	"time"
)

func TestIntegrationUsageFinalizationBoundsEachTransaction(t *testing.T) {
	fixture := newPublishRunFixture(t)
	start := fixture.now.Add(-257 * time.Minute)
	if _, err := fixture.database.pool.Exec(t.Context(), `
INSERT INTO control.public_url_usage_buckets (
    public_url_id, publish_run_number, team_id, acting_identity_id,
    bucket_start, bucket_end, observed_through, histogram_data, updated_at
)
SELECT $1, $2, $3, $4,
       $5::timestamptz + bucket * INTERVAL '1 minute',
       $5::timestamptz + (bucket + 1) * INTERVAL '1 minute',
       $5::timestamptz + (bucket + 1) * INTERVAL '1 minute',
       decode('', 'hex'), $6
FROM generate_series(0, 256) AS bucket`, fixture.setup.PublicURLID, int64(fixture.setup.PublishRunNumber),
		fixture.request.TeamID, fixture.request.ActingIdentityID, start, fixture.now); err != nil {
		t.Fatal(err)
	}
	for iteration, want := range []int{256, 1, 0} {
		count, err := fixture.database.FinalizePublicURLUsageBuckets(t.Context(), fixture.now, fixture.now)
		if err != nil || count != want {
			t.Fatalf("finalization batch %d = %d, %v; want %d", iteration, count, err, want)
		}
	}
}
