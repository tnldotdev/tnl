package service

import (
	"context"
	"sync"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
)

// the real sender's STREAM_DATA_BLOCKED frames provide the saturation barrier:
// every fresh application has spent its full advertised stream window before
// the test submits a control renewal. no application read supplies this signal.
type permissionBackpressureTrace struct {
	window, first uint64
	mu            sync.Mutex
	seen          map[uint64]struct{}
	allBlocked    chan struct{}
}

func newPermissionBackpressureTrace(window uint64, grown bool) *permissionBackpressureTrace {
	first := uint64(4) // client stream 0 is control.
	if grown {
		first = 8
	} // the closed warm-up stream used client stream 4.
	return &permissionBackpressureTrace{window: window, first: first, seen: make(map[uint64]struct{}), allBlocked: make(chan struct{})}
}

func (t *permissionBackpressureTrace) tracer(_ context.Context, client bool, _ quic.ConnectionID) qlogwriter.Trace {
	if !client {
		return nil
	}
	return t
}

func (*permissionBackpressureTrace) SupportsSchemas(string) bool        { return true }
func (t *permissionBackpressureTrace) AddProducer() qlogwriter.Recorder { return t }
func (*permissionBackpressureTrace) Close() error                       { return nil }

func (t *permissionBackpressureTrace) RecordEvent(event qlogwriter.Event) {
	packet, ok := event.(qlog.PacketSent)
	if !ok {
		return
	}
	for _, frame := range packet.Frames {
		blocked, ok := frame.Frame.(*qlog.StreamDataBlockedFrame)
		if !ok || uint64(blocked.MaximumStreamData) != t.window {
			continue
		}
		id := uint64(blocked.StreamID)
		if id < t.first || id >= t.first+4*tunnel.MaxConnectorApplicationStreams || id%4 != 0 {
			continue
		}
		t.mu.Lock()
		if _, seen := t.seen[id]; !seen {
			t.seen[id] = struct{}{}
			if len(t.seen) == tunnel.MaxConnectorApplicationStreams {
				close(t.allBlocked)
			}
		}
		t.mu.Unlock()
	}
}
