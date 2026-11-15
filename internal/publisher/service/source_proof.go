package service

import (
	"container/heap"
	"errors"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

var errSourceProofReplay = errors.New("visitor source proof was already used or is too old")

// a window remembers the last 256 sequence numbers in 32 bytes. bits use the
// sequence's position modulo 256; advancing clears only positions being reused.
type sourceProofWindow struct {
	highest uint64
	seen    [4]uint64
}

func (w *sourceProofWindow) remember(sequence uint64) error {
	if sequence == 0 || sequence <= w.highest && w.highest-sequence >= 256 {
		return errSourceProofReplay
	}
	if sequence > w.highest {
		distance := sequence - w.highest
		if distance >= 256 {
			w.seen = [4]uint64{}
		} else {
			for offset := range distance {
				reused := w.highest + offset + 1
				w.seen[(reused%256)/64] &^= uint64(1) << (reused % 64)
			}
		}
		w.highest = sequence
	}
	word, bit := (sequence%256)/64, uint64(1)<<(sequence%64)
	if w.seen[word]&bit != 0 {
		return errSourceProofReplay
	}
	w.seen[word] |= bit
	return nil
}

// a service run shares this history across both publisher connections. a
// visitor's release never clears its source evidence. callers verify the source
// signature first and remember it only after the first visitor byte arrives.
type sourceProofHistory struct {
	mu          sync.Mutex
	latestTime  int64
	windows     map[[32]byte]*sourceProofWindow
	expirations sourceProofExpirations
}

func (h *sourceProofHistory) remember(proof tunnelv1.VisitorSourceProof, now time.Time) error {
	if len(proof.Authority.MAC) != 32 {
		return visitortoken.ErrVisitorSource
	}
	if proof.Sequence == 0 {
		return errSourceProofReplay
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.latestTime = max(h.latestTime, now.Unix())
	if proof.Authority.ValidUntil <= h.latestTime {
		return visitortoken.ErrVisitorSource
	}
	for len(h.expirations) > 0 && h.expirations[0].until <= h.latestTime {
		expired := heap.Pop(&h.expirations).(sourceProofExpiration)
		delete(h.windows, expired.key)
	}
	key := [32]byte(proof.Authority.MAC)
	if h.windows == nil {
		h.windows = make(map[[32]byte]*sourceProofWindow)
	}
	window := h.windows[key]
	if window == nil {
		window = new(sourceProofWindow)
		h.windows[key] = window
		heap.Push(&h.expirations, sourceProofExpiration{key: key, until: proof.Authority.ValidUntil})
	}
	return window.remember(proof.Sequence)
}

type sourceProofExpiration struct {
	key   [32]byte
	until int64
}

type sourceProofExpirations []sourceProofExpiration

func (h sourceProofExpirations) Len() int           { return len(h) }
func (h sourceProofExpirations) Less(i, j int) bool { return h[i].until < h[j].until }
func (h sourceProofExpirations) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *sourceProofExpirations) Push(value any)    { *h = append(*h, value.(sourceProofExpiration)) }
func (h *sourceProofExpirations) Pop() any {
	last := len(*h) - 1
	value := (*h)[last]
	*h = (*h)[:last]
	return value
}
