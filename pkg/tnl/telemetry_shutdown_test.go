package tnl

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"
)

func TestSDKTelemetryShutdownUsesOriginalRemainingBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		start := time.Now()
		until := start.Add(10 * time.Second)
		cancel()
		time.Sleep(7 * time.Second)
		joined := false
		err := closeSDKTelemetry(ctx, until, func(finish context.Context) {
			if got, ok := finish.Deadline(); !ok || !got.Equal(until) || finish.Err() != nil {
				t.Fatal("collector did not receive the original remaining deadline", got, finish.Err())
			}
			<-finish.Done()
			joined = true
		})
		if !joined || !errors.Is(err, context.DeadlineExceeded) || !time.Now().Equal(until) {
			t.Fatal("collector received a fresh phase budget or did not join", joined, err, time.Since(start))
		}
		// a later cleanup attempt cannot reopen the exhausted budget.
		err = closeSDKTelemetry(ctx, until, func(finish context.Context) {
			if !errors.Is(finish.Err(), context.DeadlineExceeded) {
				t.Fatal("expired collector cleanup received a new budget")
			}
		})
		if !errors.Is(err, context.DeadlineExceeded) || !time.Now().Equal(until) {
			t.Fatal("expired collector cleanup hid its timeout", err, time.Since(start))
		}
	})
}
