package publisher

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestPublicCapacityOneIsSharedAcrossIndependentIngresses(t *testing.T) {
	for _, first := range []int{0, 1} {
		t.Run([]string{"first", "second"}[first], func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			var targetCalls atomic.Int64
			f := newPublicCapacityFixture(t, 1, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				targetCalls.Add(1)
				if r.URL.Path == "/hold" {
					close(entered)
					select {
					case <-release:
					case <-r.Context().Done():
						return
					}
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			other := f.allocation
			other.Id = "salloc_" + strings.Repeat("B", 22)
			other.IngressId += "-other"
			other.IngressRunId += "-other"
			other.ReservationKey = bytes.Repeat([]byte{0x43}, 32)
			f.update.Allocations[other.Id] = other
			if err := f.policy.Apply(f.policy.Begin(), f.update); err != nil {
				t.Fatal(err)
			}
			// a valid allocation ID and process binding cannot borrow another
			// ingress's proof key. rejection must not spend the valid claim.
			for index := range 2 {
				forged := f.allocation
				forged.ReservationKey = other.ReservationKey
				if index == 1 {
					forged = other
					forged.ReservationKey = f.allocation.ReservationKey
				}
				stream, err := f.openAllocation(forged, index, 0, 1)
				if err != nil {
					t.Fatal(err)
				}
				_, err = stream.Read(make([]byte, 1))
				_ = stream.Close()
				var rejected *tunnel.ProtocolError
				if !errors.As(err, &rejected) || rejected.Code != tunnelv1.Unauthenticated || targetCalls.Load() != 0 {
					t.Fatal("another ingress's proof key authorized public setup", err, targetCalls.Load())
				}
			}
			firstAllocation, secondAllocation := f.allocation, other
			if first == 1 {
				firstAllocation, secondAllocation = other, f.allocation
			}
			stream, err := f.openAllocation(firstAllocation, first, 0, 1)
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				response, err := f.request(stream, "/hold")
				if err == nil {
					_, err = io.Copy(io.Discard, response.Body)
					_ = response.Body.Close()
				}
				done <- err
			}()
			select {
			case <-entered:
			case <-f.ctx.Done():
				t.Fatal("first ingress did not reach the target")
			}
			extra, err := f.openAllocation(secondAllocation, 1-first, 0, 2)
			if err != nil {
				t.Fatal("second ingress could not complete bounded setup", err)
			}
			response, err := f.request(extra, "/overflow")
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			if response.StatusCode != http.StatusServiceUnavailable || targetCalls.Load() != 1 {
				t.Fatal("independent ingress setup spent additional authorized capacity", response.StatusCode, targetCalls.Load())
			}
			close(release)
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			f.wait(0, 0)
			next, err := f.openAllocation(secondAllocation, 1-first, 0, 3)
			if err != nil {
				t.Fatal(err)
			}
			response, err = f.request(next, "/after")
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			if response.StatusCode != http.StatusNoContent || targetCalls.Load() != 2 {
				t.Fatal("physical retirement did not release the one shared slot", response.StatusCode, targetCalls.Load())
			}
		})
	}
}
