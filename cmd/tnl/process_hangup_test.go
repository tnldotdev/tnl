package main

import (
	"context"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestProcessSignalProxyHangupRequestsJoinedShutdown(t *testing.T) {
	received := make(chan os.Signal, 1)
	var unregistered atomic.Bool
	ctx, stop := processSignalContext(t.Context(), received, func() { unregistered.Store(true) })
	defer stop()
	received <- syscall.SIGHUP
	select {
	case <-ctx.Done():
		if context.Cause(ctx) != context.Canceled || !unregistered.Load() {
			t.Fatal("proxy hangup did not restore default handling before requesting cleanup", context.Cause(ctx))
		}
	case <-time.After(time.Second):
		t.Fatal("proxy hangup did not request joined shutdown")
	}
}
