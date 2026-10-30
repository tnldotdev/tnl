package publisher

import (
	"container/heap"
	"errors"
	"time"

	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

var errVisitorSourceReplay = errors.New("visitor source proof was already consumed or superseded")

// a fixed window permits reordered setup without remembering every visitor.
// release never clears evidence or evicts an already-authorized visitor.
type visitorSourceHistory struct {
	highest uint64
	seen    [4]uint64
}

func (h *visitorSourceHistory) consume(sequence uint64) error {
	if sequence == 0 {
		return errVisitorSourceReplay
	}
	if sequence > h.highest {
		shift := sequence - h.highest
		if shift >= 256 {
			h.seen = [4]uint64{}
		} else {
			words, bits := int(shift/64), shift%64
			for index := len(h.seen) - 1; index >= 0; index-- {
				value := uint64(0)
				if index >= words {
					value = h.seen[index-words] << bits
					if bits != 0 && index > words {
						value |= h.seen[index-words-1] >> (64 - bits)
					}
				}
				h.seen[index] = value
			}
		}
		h.highest = sequence
	}
	back := h.highest - sequence
	if back >= 256 {
		return errVisitorSourceReplay
	}
	word, mask := back/64, uint64(1)<<(back%64)
	if h.seen[word]&mask != 0 {
		return errVisitorSourceReplay
	}
	h.seen[word] |= mask
	return nil
}

type visitorSourceExpiration struct {
	key   [32]byte
	until int64
}

type visitorSourceExpirations []visitorSourceExpiration

func (h visitorSourceExpirations) Len() int           { return len(h) }
func (h visitorSourceExpirations) Less(i, j int) bool { return h[i].until < h[j].until }
func (h visitorSourceExpirations) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *visitorSourceExpirations) Push(value any)    { *h = append(*h, value.(visitorSourceExpiration)) }
func (h *visitorSourceExpirations) Pop() any {
	last := len(*h) - 1
	value := (*h)[last]
	*h = (*h)[:last]
	return value
}

func (r *PublicURLServer) consumeVisitorSource(proof tunnelv1.VisitorSourceProof, now time.Time) error {
	if len(proof.Authority.MAC) != 32 {
		return visitortoken.ErrVisitorSource
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	// policy refreshes can reduce the projected authority time. acceptance and
	// retirement share one run-owned floor so retired evidence stays expired.
	r.sourceTime = max(r.sourceTime, now.Unix())
	if proof.Authority.ValidUntil <= r.sourceTime {
		return visitortoken.ErrVisitorSource
	}
	for len(r.sourceExpirations) > 0 && r.sourceExpirations[0].until <= r.sourceTime {
		expired := heap.Pop(&r.sourceExpirations).(visitorSourceExpiration)
		delete(r.sourceHistory, expired.key)
	}
	key := [32]byte(proof.Authority.MAC)
	if r.sourceHistory == nil {
		r.sourceHistory = make(map[[32]byte]*visitorSourceHistory)
	}
	history := r.sourceHistory[key]
	if history == nil {
		history = new(visitorSourceHistory)
		r.sourceHistory[key] = history
		heap.Push(&r.sourceExpirations, visitorSourceExpiration{key: key, until: proof.Authority.ValidUntil})
	}
	return history.consume(proof.Sequence)
}

// consume after metadata arrives: ingress may choose another relay before its
// first byte, but cannot replay or rewrite a committed connection.
func (r *PublicURLServer) authenticateVisitorSource(stream tunnelv1.VisitorStreamHeader, header proxyproto.Header) error {
	if r.policy == nil || r.run.PublicURLID == "" || r.run.PublishRunID == "" || r.run.Number == 0 ||
		stream.PublicURLID != r.run.PublicURLID || stream.PublishRunID != r.run.PublishRunID || stream.PublishRunNumber != r.run.Number {
		return visitortoken.ErrVisitorSource
	}
	view, enabled, _ := r.policy.Current()
	if !enabled || view.Scope.ID != r.run.PublicURLID {
		return visitortoken.ErrVisitorSource
	}
	proof, err := tunnelv1.ReadVisitorSourceProof([]byte(header.VisitorSourceProof))
	if err != nil {
		return err
	}
	now := view.AuthorityTime(time.Now())
	if err := visitortoken.VerifyVisitorSource(r.visitorSourceKey, proof, tunnelv1.VisitorSourceBinding{
		PublicURLID: r.run.PublicURLID, PublishRunID: r.run.PublishRunID, PublishRunNumber: r.run.Number,
		VisitorID: stream.VisitorConnectionID, Source: header.Source, Destination: header.Destination,
	}, view.VisitorPolicyRevision, now); err != nil {
		return err
	}
	return r.consumeVisitorSource(proof, now)
}
