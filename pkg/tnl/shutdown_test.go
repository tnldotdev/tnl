package tnl

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
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

func TestShutdownHTTPJoinsActiveHandlerOnNormalDrain(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	entered, exited, releaseHandler := make(chan struct{}), make(chan struct{}), make(chan struct{})
	release := sync.OnceFunc(func() { close(releaseHandler) })
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		defer close(exited)
		close(entered)
		<-releaseHandler
		_, _ = io.WriteString(w, "final local response")
	})}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	servingExited := make(chan struct{})
	served := make(chan error, 1)
	go func() {
		err := server.Serve(listener)
		close(servingExited)
		if err == http.ErrServerClosed {
			err = nil
		}
		served <- err
	}()
	replied := make(chan error, 1)
	go func() {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+listener.Addr().String(), nil)
		if err != nil {
			replied <- err
			return
		}
		transport := &http.Transport{DisableKeepAlives: true, Proxy: nil}
		defer transport.CloseIdleConnections()
		response, err := transport.RoundTrip(request)
		if err != nil {
			replied <- err
			return
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err == nil && string(body) != "final local response" {
			err = errors.New("local response was truncated")
		}
		replied <- err
	}()
	defer func() { release(); cancel(); _ = server.Close() }()
	awaitSDK(t, ctx, entered)
	shutdown := make(chan error, 1)
	go func() { shutdown <- shutdownHTTP(ctx, server, served) }()
	awaitSDK(t, ctx, servingExited)
	select {
	case err := <-shutdown:
		t.Fatal("loopback server shutdown returned before its handler", err)
	default:
	}
	release()
	if err := awaitSDK(t, ctx, replied); err != nil {
		t.Fatal(err)
	}
	if err := awaitSDK(t, ctx, shutdown); err != nil {
		t.Fatal(err)
	}
	select {
	case <-exited:
	default:
		t.Fatal("loopback server shutdown left an active handler")
	}
}
