package tunnel

import (
	"context"
	"net"
	"testing"
	"testing/synctest"
	"time"
)

func TestConnectorRejectionWaitsForPeerWithinOriginalBudget(t *testing.T) {
	for _, boundary := range []string{"peer close", "unresponsive peer", "short exchange"} {
		t.Run(boundary, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				left, right := net.Pipe()
				defer left.Close()
				defer right.Close()
				budget := time.Second
				if boundary == "short exchange" {
					budget = 20 * time.Millisecond
				}
				ctx, cancel := context.WithTimeout(t.Context(), budget)
				defer cancel()
				stream := &memoryStream{Conn: left, deadline: time.Now().Add(time.Hour)}
				done := make(chan struct{})
				go func() { defer close(done); drainConnectorRejection(ctx, stream) }()
				synctest.Wait()
				select {
				case <-done:
					t.Fatal("rejection retired before the peer could consume it")
				default:
				}
				if boundary == "peer close" {
					_ = right.Close()
				} else {
					time.Sleep(budget)
				}
				synctest.Wait()
				select {
				case <-done:
				default:
					t.Fatal("rejected peer outlived its bounded drain")
				}
			})
		})
	}
}
