package peer

import (
	"sync/atomic"
	"time"

	"github.com/pion/ice/v4"
)

const connectivityConsentTimeout = 3 * time.Second

// pion's connection-state timeout also observes application packets. consent
// must instead expire from authenticated STUN responses on the nominated pair,
// even when encrypted packets and endpoint probes continue to arrive.
type connectivityConsent struct {
	lost          atomic.Bool
	until         atomic.Pointer[time.Time]
	local, remote string
	responses     uint64
}

func (c *connectivityConsent) valid() bool {
	if c == nil {
		return false
	}
	until := c.until.Load()
	if c.lost.Load() || until == nil {
		return false
	}
	if !time.Now().Before(*until) {
		// a late response cannot revive a retired attempt or inherit its probes.
		c.lost.Store(true)
		return false
	}
	return true
}

func (c *connectivityConsent) refresh(agent *ice.Agent) bool {
	if c.lost.Load() || c.until.Load() != nil && !c.valid() {
		return false
	}
	selected, ok := agent.GetSelectedCandidatePairStats()
	if !ok {
		return false
	}
	if c.local != "" && (selected.LocalCandidateID != c.local || selected.RemoteCandidateID != c.remote) {
		c.lost.Store(true)
		return false
	}
	c.local, c.remote = selected.LocalCandidateID, selected.RemoteCandidateID
	if selected.ResponsesReceived > c.responses {
		// the pinned selected-pair stats omit the response timestamp. consult the
		// full bounded checklist only when its authenticated response count moves.
		for _, pair := range agent.GetCandidatePairsStats() {
			if pair.LocalCandidateID == c.local && pair.RemoteCandidateID == c.remote && !pair.LastResponseTimestamp.IsZero() {
				until := pair.LastResponseTimestamp.Add(connectivityConsentTimeout)
				c.until.Store(&until)
				c.responses = pair.ResponsesReceived
				break
			}
		}
	}
	return c.valid()
}
