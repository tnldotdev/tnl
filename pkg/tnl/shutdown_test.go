package tnl

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"testing/synctest"
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
		w.Header().Set("Trailer", "X-Final")
		_, _ = io.WriteString(w, "final local response")
		w.Header().Set("X-Final", "accepted")
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
		if err == nil && response.Trailer.Get("X-Final") != "accepted" {
			err = errors.New("local response lost its final trailer")
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

type shutdownPipeListener struct {
	connections chan net.Conn
	closed      chan struct{}
	closeOnce   sync.Once
}

func (l *shutdownPipeListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.connections:
		return conn, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *shutdownPipeListener) Close() error {
	l.closeOnce.Do(func() { close(l.closed) })
	return nil
}

func (*shutdownPipeListener) Addr() net.Addr { return &net.TCPAddr{Port: 1} }

func TestHTTPPublicationShutdownSharesOneBudgetAndDoesNotJoinArbitraryHandlers(t *testing.T) {
	for _, force := range []bool{false, true} {
		t.Run(map[bool]string{false: "graceful", true: "forced"}[force], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				listener := &shutdownPipeListener{connections: make(chan net.Conn, 1), closed: make(chan struct{})}
				client, accepted := net.Pipe()
				listener.connections <- accepted
				entered, released, exited := make(chan struct{}), make(chan struct{}), make(chan struct{})
				release := sync.OnceFunc(func() { close(released) })
				defer release()
				server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					defer close(exited)
					close(entered)
					<-released // the application deliberately ignores cancellation
					w.Header().Set("Trailer", "X-Final")
					_, _ = io.WriteString(w, "accepted final bytes")
					w.Header().Set("X-Final", "complete")
				})}
				defer server.Close()
				served := make(chan error, 1)
				go func() {
					err := server.Serve(listener)
					if err == http.ErrServerClosed {
						err = nil
					}
					served <- err
				}()
				replied := make(chan error, 1)
				go func() {
					transport := &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) { return client, nil }}
					defer transport.CloseIdleConnections()
					response, err := (&http.Client{Transport: transport}).Get("http://owned.test/")
					if err == nil {
						defer response.Body.Close()
						var body []byte
						body, err = io.ReadAll(response.Body)
						if err == nil && (string(body) != "accepted final bytes" || response.Trailer.Get("X-Final") != "complete") {
							err = errors.New("graceful shutdown lost accepted bytes or trailers")
						}
					}
					replied <- err
				}()
				<-entered
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				captured := make(chan time.Time, 1)
				joined := make(chan error, 1)
				cleanupFailure := errors.New("remote cleanup unconfirmed")
				go func() {
					joined <- runHTTPPublication(ctx, server, served, func(deadline func() time.Time) error {
						<-ctx.Done()
						captured <- deadline()
						time.Sleep(6 * time.Second) // publication cleanup spends the first phase
						if force {
							return errors.Join(ctx.Err(), cleanupFailure)
						}
						return nil
					})
				}()
				start := time.Now()
				cancel()
				if until := <-captured; !until.Equal(start.Add(10 * time.Second)) {
					t.Fatal("shutdown did not retain its original deadline", until, start)
				}
				time.Sleep(7 * time.Second)
				synctest.Wait()
				select {
				case err := <-joined:
					t.Fatal("shutdown returned before graceful drain or its deadline", err)
				default:
				}
				if force {
					time.Sleep(3 * time.Second)
					if err := <-joined; !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, cleanupFailure) {
						t.Fatal("force close lost the deadline or independent cleanup failure", err)
					}
					if !time.Now().Equal(start.Add(10 * time.Second)) {
						t.Fatal("HTTP drain received a new phase budget", time.Since(start))
					}
					select {
					case <-exited:
						t.Fatal("fixture did not retain its arbitrary application handler")
					default:
					}
					if err := <-replied; err == nil {
						t.Fatal("deadline did not force-close the owned request connection")
					}
					release()
					<-exited
				} else {
					release()
					if err := <-replied; err != nil {
						t.Fatal(err)
					}
					if err := <-joined; err != nil {
						t.Fatal(err)
					}
					if !time.Now().Before(start.Add(10 * time.Second)) {
						t.Fatal("graceful shutdown unnecessarily exhausted its budget")
					}
				}
			})
		})
	}
}
