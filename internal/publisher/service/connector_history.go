package service

import (
	"container/heap"
	"time"
)

// rememberOpeningLocked retains a verified opening until the signed permission
// can no longer be replayed. a live admission (including terminal cleanup)
// continues to own its visitor ID independently of the opening's expiry.
func (p *PeerSession) rememberOpeningLocked(id string, now, expires time.Time) bool {
	p.pruneOpeningHistoryLocked(now)
	if !expires.After(p.seenAt) || !p.seen[id].IsZero() {
		return false
	}
	for a := range p.streams {
		if a.terminalKey.VisitorConnectionID == id {
			return false
		}
	}
	p.extendOpeningLocked(id, expires)
	return true
}

func (p *PeerSession) pruneOpeningHistoryLocked(now time.Time) {
	if now.After(p.seenAt) {
		p.seenAt = now
	}
	for len(p.seenExpirations) != 0 && !p.seenExpirations[0].until.After(p.seenAt) {
		entry := heap.Pop(&p.seenExpirations).(connectorOpeningExpiration)
		if p.seen[entry.id].Equal(entry.until) {
			delete(p.seen, entry.id)
		}
	}
}

// a verified renewal also signs the visitor ID and may outlive its first proof.
func (p *PeerSession) extendOpeningLocked(id string, expires time.Time) {
	if expires.After(p.seenAt) && expires.After(p.seen[id]) {
		p.seen[id] = expires
		heap.Push(&p.seenExpirations, connectorOpeningExpiration{id, expires})
	}
}

type connectorOpeningExpiration struct {
	id    string
	until time.Time
}

type connectorOpeningExpirations []connectorOpeningExpiration

func (h connectorOpeningExpirations) Len() int           { return len(h) }
func (h connectorOpeningExpirations) Less(i, j int) bool { return h[i].until.Before(h[j].until) }
func (h connectorOpeningExpirations) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *connectorOpeningExpirations) Push(value any) {
	*h = append(*h, value.(connectorOpeningExpiration))
}
func (h *connectorOpeningExpirations) Pop() any {
	last := len(*h) - 1
	value := (*h)[last]
	(*h)[last] = connectorOpeningExpiration{}
	*h = (*h)[:last]
	return value
}
