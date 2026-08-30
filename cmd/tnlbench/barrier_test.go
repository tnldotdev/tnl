package main

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDriverBarrierReleasesEveryDriverPerPhase(t *testing.T) {
	server := httptest.NewServer(newDriverBarrier(2, "secret"))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	for _, phase := range []string{"activated", "ready", "loaded"} {
		firstDone := make(chan error, 1)
		go func() {
			firstDone <- waitDriverBarrier(ctx, cli{
				DriverCount: 2, DriverIndex: 0, BarrierURL: server.URL, BarrierToken: "secret",
			}, phase)
		}()
		select {
		case err := <-firstDone:
			t.Fatalf("first driver passed %s barrier early: %v", phase, err)
		case <-time.After(50 * time.Millisecond):
		}
		if err := waitDriverBarrier(ctx, cli{
			DriverCount: 2, DriverIndex: 1, BarrierURL: server.URL, BarrierToken: "secret",
		}, phase); err != nil {
			t.Fatalf("second driver %s barrier: %v", phase, err)
		}
		if err := <-firstDone; err != nil {
			t.Fatalf("first driver %s barrier: %v", phase, err)
		}
	}
}

func TestDriverBarrierRejectsWrongToken(t *testing.T) {
	server := httptest.NewServer(newDriverBarrier(2, "secret"))
	defer server.Close()
	err := waitDriverBarrier(context.Background(), cli{
		DriverCount: 2, DriverIndex: 0, BarrierURL: server.URL, BarrierToken: "wrong",
	}, "ready")
	if err == nil {
		t.Fatal("wrong barrier token succeeded")
	}
}
