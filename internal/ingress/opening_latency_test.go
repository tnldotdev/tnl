package ingress

import (
	"fmt"
	"io"
	"sort"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

// a small real WSS/yamux workload shared by the serial and pipelined opening
// implementations. run with -v through go:test:focused to retain the samples.
func TestPublicOpeningLatency(t *testing.T) {
	f := newAdmissionTransportFixture(t)
	const samples = 32
	worker := ingressWorker(t, f.closePublisher, func() error {
		for range samples + 1 {
			incoming, err := f.publisher.AcceptServiceForwardingStream(ingressContext(t))
			if err != nil {
				return err
			}
			if err := incoming.Accept(); err != nil {
				return err
			}
			var request [6]byte
			if _, err := io.ReadFull(incoming.Stream(), request[:]); err != nil {
				return err
			}
			if string(request[:]) != "proxy!" {
				return fmt.Errorf("changed initial bytes: %q", request)
			}
			if _, err := incoming.Stream().Write([]byte("!")); err != nil {
				return err
			}
			if err := incoming.CloseWrite(ingressContext(t)); err != nil {
				return err
			}
			if _, err := io.Copy(io.Discard, incoming.Stream()); err != nil {
				return err
			}
			_ = incoming.Stream().Close()
		}
		return nil
	})
	durations := make([]time.Duration, 0, samples)
	for i := range samples + 1 {
		start := time.Now()
		header := f.header
		header.VisitorConnectionID, _ = opaqueid.New(opaqueid.VisitorConnectionPrefix)
		stream, err := f.forwarder.OpenService(ingressContext(t), f.relay, header, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(stream, "proxy!"); err != nil {
			t.Fatal(err)
		}
		var response [1]byte
		if _, err := io.ReadFull(stream, response[:]); err != nil || response[0] != '!' {
			t.Fatal("first return byte failed", err)
		}
		elapsed := time.Since(start)
		if err := stream.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(io.Discard, stream); err != nil {
			t.Fatal(err)
		}
		_ = stream.Close()
		ingressAwait(t, f.released)
		if i != 0 {
			durations = append(durations, elapsed)
		}
	}
	if err := ingressAwait(t, worker); err != nil {
		t.Fatal(err)
	}
	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	t.Logf("warm local setup to first publisher byte: n=%d p50=%s p95=%s", samples, durations[samples/2], durations[samples*95/100])
}
