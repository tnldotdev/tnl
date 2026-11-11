package tnl

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestShutdownHTTPClosesActiveRequestsAndJoinsServe(t *testing.T) {
	entered, exited := make(chan struct{}), make(chan struct{})
	server := &http.Server{Handler: http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(entered)
		<-r.Context().Done()
		close(exited)
	})}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	served := make(chan error, 1)
	serveFailure := errors.New("serve failed")
	go func() { _ = server.Serve(listener); served <- serveFailure }()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	requestDone := make(chan struct{})
	go func() {
		defer close(requestDone)
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+listener.Addr().String(), nil)
		response, err := (&http.Client{Transport: &http.Transport{DisableKeepAlives: true, Proxy: nil}}).Do(request)
		if err == nil {
			_ = response.Body.Close()
		}
	}()
	t.Cleanup(func() { cancel(); _ = server.Close(); <-requestDone })
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("request did not enter handler")
	}
	deadline, stop := context.WithDeadline(ctx, time.Now().Add(-time.Second))
	defer stop()
	err = shutdownHTTP(deadline, server, served)
	if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, serveFailure) {
		t.Fatalf("shutdown = %v", err)
	}
	select {
	case <-exited:
	case <-ctx.Done():
		t.Fatal("active request survived shutdown")
	}
	select {
	case <-requestDone:
	case <-ctx.Done():
		t.Fatal("visitor survived shutdown")
	}
}
