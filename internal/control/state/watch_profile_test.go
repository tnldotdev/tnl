package state

import (
	"testing"
	"time"
)

func TestProfilePublisherWatch(t *testing.T) {
	f := newControlLoadFixture(t)
	sessions := readySteadyLoadSessions(t, f)
	seen := make([]ConnectorPeerWatchVersion, len(sessions))
	for i, session := range sessions {
		seen[i] = ConnectorPeerWatchVersion{RunID: session.run.RunID, Revision: -1}
	}
	for start := 0; start < len(seen); start += MaxConnectorPeerWatchBatch {
		batch := seen[start:min(start+MaxConnectorPeerWatchBatch, len(seen))]
		initial, err := f.database.CompareConnectorPeerWatchVersions(t.Context(), batch)
		if err != nil || len(initial) != len(batch) {
			t.Fatal("missing initial watches", err)
		}
		copy(batch, initial)
	}
	const polls = 40
	started := time.Now()
	for range polls {
		for start := 0; start < len(seen); start += MaxConnectorPeerWatchBatch {
			changes, err := f.database.CompareConnectorPeerWatchVersions(t.Context(), seen[start:min(start+MaxConnectorPeerWatchBatch, len(seen))])
			if err != nil || len(changes) != 0 {
				t.Fatal("unchanged watch reported changes", err)
			}
		}
	}
	t.Logf("steady_watches=%d polls=%d mean_poll=%s", len(seen), polls, time.Since(started)/polls)
}
